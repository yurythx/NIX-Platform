// Package database configures the shared PostgreSQL connection pool
// (pgx/v5 + pgxpool). Modules receive a *pgxpool.Pool (or a narrower
// interface over it) through dependency injection — nothing in this
// package knows about business schemas.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// pgxTx is a local alias so callers of WithTx don't need to import pgx
// directly just to spell the transaction type.
type pgxTx = pgx.Tx

// New builds and validates a pgxpool.Pool from the given database config.
// It applies pool sizing/lifetime/idle settings and performs an initial
// ping so misconfiguration fails fast at startup rather than on first use.
func New(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("database: parse pool config: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: initial ping failed: %w", err)
	}

	return pool, nil
}

// Ping is a readiness Check function suitable for httpserver.Check.
func Ping(pool *pgxpool.Pool) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		return pool.Ping(ctx)
	}
}

// WithTx runs fn inside a PostgreSQL transaction, committing on success and
// rolling back on error or panic. Used by application use cases that must
// write business data and an outbox event atomically (§16).
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(ctx context.Context, tx pgxTx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(ctx, tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("database: rollback failed: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit transaction: %w", err)
	}
	return nil
}

// DefaultTimeout is the default per-query timeout applied by callers that
// don't derive a more specific deadline from the incoming request context.
const DefaultTimeout = 5 * time.Second
