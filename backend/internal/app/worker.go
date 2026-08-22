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

// Worker roda todo processador de segundo plano de vida longa (consumers
// do RabbitMQ, o publisher do outbox) com um ciclo de vida compartilhado:
// Run bloqueia até ctx ser cancelado, e então espera cada goroutine de
// processador terminar sua unidade de trabalho atual antes de retornar,
// dando ao graceful shutdown do cmd/worker algo concreto para esperar.
type Worker struct {
	deps       *Dependencies
	processors []processor
}

// processor é um loop de segundo plano (ex.: um consumer de fila ou o
// publisher do outbox). Cada um é iniciado em sua própria goroutine e
// precisa retornar quando ctx é cancelado.
type processor func(ctx context.Context) error

// NewWorker constrói o runner do worker: o publisher do outbox mais os
// consumers de fila + DLQ de cada módulo, e a limpeza periódica dos
// buckets de rate limit. Cada um é envolvido por supervised, para que a
// falha transitória de um processador (uma soluço de conexão no meio de
// um consume, por exemplo) reinicie só aquele processador em vez de
// derrubar o processo worker inteiro.
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

// supervised envolve um processador para que, se ele retornar antes de
// ctx ser cancelado (um erro inesperado, ou — no caso de um consumer de
// fila — simplesmente perder seu canal quando a conexão subjacente
// reconecta), ele seja reiniciado com backoff em vez de derrubar o
// restante do worker.
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

// Run inicia todo processador registrado e bloqueia até ctx ser cancelado
// e todos eles terem retornado.
func (w *Worker) Run(ctx context.Context) error {
	if len(w.processors) == 0 {
		// Nenhum processador registrado ainda (fase inicial de bootstrap)
		// — ainda assim respeita a semântica de graceful shutdown
		// bloqueando em ctx.
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

// RunMetricsServer inicia o listener HTTP mínimo /health + /metrics do
// worker (sem rotas de negócio) e bloqueia até ctx ser cancelado, então o
// encerra graciosamente. Nunca serve tráfego de negócio — só healthcheck
// do Docker e scrape do Prometheus.
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
