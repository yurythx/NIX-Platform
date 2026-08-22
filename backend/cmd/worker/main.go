// Command worker roda os processadores assíncronos do NIX Platform:
// consumers das filas do RabbitMQ (diario_oficial, integrations,
// notifications), o publisher do outbox e a execução dos jobs. Compartilha
// as dependências de plataforma com o cmd/api, mas nunca serve tráfego
// HTTP de negócio — só um listener mínimo para /health e /metrics
// (ver RunMetricsServer em internal/app/worker.go).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/yurythx/nix-platform/internal/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "worker: fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, err := app.NewDependencies(ctx, "worker")
	if err != nil {
		return fmt.Errorf("bootstrap dependencies: %w", err)
	}
	defer deps.Close()

	runner, err := app.NewWorker(deps)
	if err != nil {
		return fmt.Errorf("bootstrap worker: %w", err)
	}

	deps.Logger.Info("worker starting")

	// Roda os consumers/outbox publisher e o listener de métricas em
	// goroutines separadas; o processo só é considerado "rodando de
	// verdade" quando ambos estão de pé (ambos escrevem em errCh quando
	// terminam, seja por erro ou pelo cancelamento de ctx).
	errCh := make(chan error, 2)
	go func() { errCh <- runner.Run(ctx) }()
	go func() { errCh <- runner.RunMetricsServer(ctx) }()

	// Espera as duas goroutines terminarem antes de retornar — reporta o
	// primeiro erro encontrado, mas não sai antes de ambas pararem (senão
	// o defer deps.Close() em run() derrubaria as conexões debaixo de uma
	// goroutine que ainda está usando o pool/canal AMQP).
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return fmt.Errorf("worker run: %w", firstErr)
	}

	deps.Logger.Info("worker stopped", slog.String("reason", "graceful shutdown complete"))
	return nil
}
