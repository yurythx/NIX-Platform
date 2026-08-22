package app

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	diarioWorker "github.com/yurythx/nix-platform/internal/modules/diario_oficial/worker"
	secopsWorker "github.com/yurythx/nix-platform/internal/modules/secops/worker"

	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
	"github.com/yurythx/nix-platform/internal/platform/ratelimit"
)

// Worker runs every long-lived background processor (RabbitMQ consumers,
// the outbox publisher) with a shared lifecycle: Run blocks until ctx is
// cancelled, then waits for every processor goroutine to finish its
// current unit of work before returning, giving cmd/worker's graceful
// shutdown something meaningful to wait on.
type Worker struct {
	deps       *Dependencies
	processors []processor
}

// processor is one background loop (e.g. a queue consumer or the outbox
// publisher). Each is started in its own goroutine and must return when ctx
// is cancelled.
type processor func(ctx context.Context) error

// NewWorker builds the worker runner: the outbox publisher plus every
// module's RabbitMQ queue + DLQ consumers. Each is wrapped by supervised so
// one processor's transient failure (a connection blip mid-consume, for
// instance) restarts just that processor instead of taking the whole
// worker process down.
func NewWorker(deps *Dependencies) (*Worker, error) {
	outboxPublisher := outbox.NewPublisher(deps.DB, deps.Publisher, deps.Logger)

	newConsumer := func(queue string) *messaging.Consumer {
		return messaging.NewConsumer(deps.Messaging, queue, deps.Config.RabbitMQ.PrefetchCount, deps.Config.RabbitMQ.MaxRetries, deps.Logger)
	}

	diarioConsumer := newConsumer(messaging.QueueDiarioOficialWorker.Name)
	diarioDLQConsumer := newConsumer(messaging.QueueDiarioOficialWorker.DLQName)
	secopsConsumer := newConsumer(messaging.QueueIntegrationWorker.Name)
	secopsDLQConsumer := newConsumer(messaging.QueueIntegrationWorker.DLQName)

	return &Worker{
		deps: deps,
		processors: []processor{
			supervised("outbox_publisher", deps.Logger, outboxPublisher.Run),
			supervised("rate_limit_cleanup", deps.Logger, ratelimit.Cleanup(deps.DB)),
			supervised("diario_oficial.worker", deps.Logger, func(ctx context.Context) error {
				return diarioConsumer.Consume(ctx, diarioWorker.JobCreatedHandler(deps.Modules.DiarioOficial.Service))
			}),
			supervised("diario_oficial.dlq", deps.Logger, func(ctx context.Context) error {
				return diarioDLQConsumer.Consume(ctx, diarioWorker.DeadLetterHandler(deps.Modules.DiarioOficial.Service, deps.Logger))
			}),
			supervised("integration.worker", deps.Logger, func(ctx context.Context) error {
				return secopsConsumer.Consume(ctx, secopsWorker.JobCreatedHandler(deps.Modules.SecOps.Service))
			}),
			supervised("integration.dlq", deps.Logger, func(ctx context.Context) error {
				return secopsDLQConsumer.Consume(ctx, secopsWorker.DeadLetterHandler(deps.Modules.SecOps.Service, deps.Logger))
			}),
		},
	}, nil
}

// supervised wraps a processor so that if it returns before ctx is
// cancelled (an unexpected error, or — for a queue consumer — simply
// losing its channel when the underlying connection reconnects), it is
// restarted with backoff instead of taking the rest of the worker down.
func supervised(name string, logger *slog.Logger, fn processor) processor {
	return func(ctx context.Context) error {
		backoff := time.Second
		const maxBackoff = 30 * time.Second

		for {
			err := fn(ctx)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				logger.Error("processor exited unexpectedly, restarting", slog.String("processor", name), slog.Any("error", err), slog.Duration("retry_in", backoff))
			} else {
				logger.Warn("processor returned without error before shutdown, restarting", slog.String("processor", name))
			}

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}

// Run starts every registered processor and blocks until ctx is cancelled
// and all of them have returned.
func (w *Worker) Run(ctx context.Context) error {
	if len(w.processors) == 0 {
		// No processors registered yet (early bootstrap phase) — still
		// honor graceful shutdown semantics by blocking on ctx.
		<-ctx.Done()
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(w.processors))

	for _, p := range w.processors {
		wg.Add(1)
		go func(p processor) {
			defer wg.Done()
			if err := p(ctx); err != nil {
				errCh <- err
			}
		}(p)
	}

	<-ctx.Done()
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// RunMetricsServer starts the worker's minimal /health + /metrics HTTP
// listener (no business routes) and blocks until ctx is cancelled, then
// shuts it down gracefully. It never serves business traffic — only
// Docker healthchecks and Prometheus scraping.
func (w *Worker) RunMetricsServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/health", httpserver.HealthHandler())
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              w.deps.Config.Worker.MetricsAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		w.deps.Logger.Info("worker metrics listener starting", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
