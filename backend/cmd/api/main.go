// Command api runs the NIX Platform HTTP API: REST endpoints, WebSocket
// notifications, health/readiness/metrics. Asynchronous job processing
// lives in cmd/worker instead.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yurythx/nix-platform/internal/app"
)

// shutdownTimeout bounds how long the API waits for in-flight requests to
// finish during graceful shutdown before forcing an exit.
const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		// The dependencies bootstrap failure path may run before a logger
		// exists, so this is the one place allowed to use the stdlib
		// logger directly.
		fmt.Fprintln(os.Stderr, "api: fatal:", err)
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

	// The WebSocket Hub and its feeding RabbitMQ consumer live in the API
	// process (§37) — cmd/worker never touches them. Both run for the
	// process lifetime and are joined during graceful shutdown below.
	var background sync.WaitGroup
	background.Add(2)
	go func() {
		defer background.Done()
		if err := deps.Hub.Run(ctx); err != nil {
			deps.Logger.Error("websocket hub stopped with error", slog.Any("error", err))
		}
	}()
	go func() {
		defer background.Done()
		notificationConsumer := app.NewNotificationConsumer(deps)
		if err := notificationConsumer.Consume(ctx, app.NotificationHandler(deps.Hub, deps.Logger)); err != nil {
			deps.Logger.Error("notification consumer stopped with error", slog.Any("error", err))
		}
	}()

	router := app.NewRouter(deps)

	server := &http.Server{
		Addr:              deps.Config.HTTP.Addr(),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErrCh := make(chan error, 1)
	go func() {
		deps.Logger.Info("api starting", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
	}()

	select {
	case <-ctx.Done():
		deps.Logger.Info("shutdown signal received, draining in-flight requests")
	case err := <-serveErrCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		deps.Logger.Error("graceful shutdown failed, forcing close", slog.Any("error", err))
		_ = server.Close()
	}

	background.Wait()
	deps.Logger.Info("api stopped")
	return nil
}
