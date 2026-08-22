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

	deps.Logger.Info("api stopped")
	return nil
}
