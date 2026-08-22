package app

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
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

// NewWorker builds the worker runner. As later phases add RabbitMQ queue
// consumers for each module, they are registered here alongside the
// outbox publisher.
func NewWorker(deps *Dependencies) (*Worker, error) {
	outboxPublisher := outbox.NewPublisher(deps.DB, deps.Publisher, deps.Logger)

	return &Worker{
		deps: deps,
		processors: []processor{
			outboxPublisher.Run,
		},
	}, nil
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
