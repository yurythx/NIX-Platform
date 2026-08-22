// Command worker runs the NIX Platform asynchronous processors: RabbitMQ
// queue consumers (diario_oficial, integrations, notifications), the
// outbox publisher, and job execution. It shares platform dependencies
// with cmd/api but never serves HTTP traffic.
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

	deps, err := app.NewDependencies(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap dependencies: %w", err)
	}
	defer deps.Close()

	runner, err := app.NewWorker(deps)
	if err != nil {
		return fmt.Errorf("bootstrap worker: %w", err)
	}

	deps.Logger.Info("worker starting")

	errCh := make(chan error, 2)
	go func() { errCh <- runner.Run(ctx) }()
	go func() { errCh <- runner.RunMetricsServer(ctx) }()

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
