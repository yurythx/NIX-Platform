// Package app wires together every platform and module dependency
// (database, messaging, auth, WebSocket hub, module services) and exposes
// the assembled HTTP router used by cmd/api and the assembled worker
// runner used by cmd/worker. It is the only place allowed to know about
// every module at once.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/platform/config"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/logging"
)

// Dependencies holds every shared platform resource. Module-specific
// dependencies (repositories, use cases) are added to this struct as each
// module is wired in; nothing here should hold business logic.
type Dependencies struct {
	Config *config.Config
	Logger *slog.Logger
	DB     *pgxpool.Pool
}

// NewDependencies builds and validates every platform dependency. It
// returns an error immediately if any required dependency (database,
// later: RabbitMQ) cannot be reached, so the process fails fast instead of
// serving traffic in a half-initialized state.
func NewDependencies(ctx context.Context) (*Dependencies, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("app: load config: %w", err)
	}

	logger := logging.New(logging.Options{
		Level:       cfg.App.LogLevel,
		Format:      cfg.App.LogFormat,
		Service:     cfg.App.Name,
		Environment: cfg.App.Env,
	})

	pool, err := database.New(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("app: connect database: %w", err)
	}

	return &Dependencies{
		Config: cfg,
		Logger: logger,
		DB:     pool,
	}, nil
}

// Close releases every resource opened by NewDependencies. Safe to call
// once during graceful shutdown.
func (d *Dependencies) Close() {
	if d.DB != nil {
		d.DB.Close()
	}
}
