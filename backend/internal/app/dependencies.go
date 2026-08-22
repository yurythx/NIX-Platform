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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/config"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
	"github.com/yurythx/nix-platform/internal/platform/ratelimit"
	"github.com/yurythx/nix-platform/internal/platform/telemetry"
	"github.com/yurythx/nix-platform/internal/platform/ws"
)

// RateLimiters holds every distributed (Postgres-backed — §rate limiting
// distribuído) rate limiter the API uses. Built once per process and
// shared by every request, so every API replica reads/writes the same
// rate_limit_buckets rows instead of each keeping its own independent
// (and therefore N×-too-generous) in-memory count.
type RateLimiters struct {
	TestJob  httpserver.Limiter // POST .../diario-oficial/test, .../virustotal/test
	WSTicket httpserver.Limiter // POST /api/v1/ws/ticket
}

// OutboxSource identifies this backend as the Source stamped on every
// event envelope written to the outbox, regardless of which module wrote
// it — module-level provenance lives in aggregate_type/aggregate_id.
const OutboxSource = "nix.platform"

// Dependencies holds every shared platform resource. Module-specific
// dependencies (repositories, use cases) are added to this struct as each
// module is wired in; nothing here should hold business logic.
type Dependencies struct {
	Config       *config.Config
	Logger       *slog.Logger
	DB           *pgxpool.Pool
	Verifier     *auth.Verifier
	Messaging    *messaging.Connection
	Publisher    events.EventPublisher
	Outbox       *outbox.Writer
	Hub          *ws.Hub
	Tickets      *ws.TicketStore
	Modules      *Modules
	RateLimiters *RateLimiters

	telemetryShutdown telemetry.Shutdown
}

// NewDependencies builds and validates every platform dependency for one
// process. component distinguishes "api" from "worker" in logs and traces
// (both share this same bootstrap). It returns an error immediately if any
// required dependency (database, RabbitMQ, OIDC discovery) cannot be
// reached, so the process fails fast instead of serving traffic in a
// half-initialized state.
func NewDependencies(ctx context.Context, component string) (*Dependencies, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("app: load config: %w", err)
	}

	serviceName := cfg.App.Name + "-" + component
	logger := logging.New(logging.Options{
		Level:       cfg.App.LogLevel,
		Format:      cfg.App.LogFormat,
		Service:     serviceName,
		Environment: cfg.App.Env,
	})

	telemetryShutdown, err := telemetry.Setup(ctx, serviceName, cfg.App.Env, cfg.OTELExporterOTLPURL, logger)
	if err != nil {
		return nil, fmt.Errorf("app: setup telemetry: %w", err)
	}

	pool, err := database.New(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("app: connect database: %w", err)
	}
	metrics.RegisterPostgresPoolMetrics(pool)

	verifier, err := auth.NewVerifier(ctx, cfg.Keycloak)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("app: initialize OIDC verifier: %w", err)
	}

	mqConn, err := messaging.Connect(ctx, cfg.RabbitMQ.URL, logger)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("app: connect to rabbitmq: %w", err)
	}

	topologyCh, err := mqConn.Channel()
	if err != nil {
		pool.Close()
		_ = mqConn.Close()
		return nil, fmt.Errorf("app: open channel to declare topology: %w", err)
	}
	if err := messaging.DeclareTopology(topologyCh, messaging.AllQueues()); err != nil {
		pool.Close()
		_ = mqConn.Close()
		return nil, fmt.Errorf("app: declare rabbitmq topology: %w", err)
	}
	_ = topologyCh.Close()

	publisher := messaging.NewPublisher(mqConn)

	deps := &Dependencies{
		Config:    cfg,
		Logger:    logger,
		DB:        pool,
		Verifier:  verifier,
		Messaging: mqConn,
		Publisher: publisher,
		Outbox:    outbox.NewWriter(OutboxSource),
		Hub:       ws.NewHub(logger),
		Tickets:   ws.NewTicketStore(ws.TicketTTL),
		RateLimiters: &RateLimiters{
			// Equivalente aproximado aos parâmetros anteriores em memória
			// (0.5 req/s, burst 3): até 3 requisições a cada 10s.
			TestJob: ratelimit.NewPostgresLimiter(pool, 10, 3),
			// Equivalente a 1 req/s, burst 5: até 5 requisições a cada 5s.
			WSTicket: ratelimit.NewPostgresLimiter(pool, 5, 5),
		},

		telemetryShutdown: telemetryShutdown,
	}
	deps.Modules = buildModules(deps)

	return deps, nil
}

// Close releases every resource opened by NewDependencies. Safe to call
// once during graceful shutdown.
func (d *Dependencies) Close() {
	if d.Tickets != nil {
		d.Tickets.Close()
	}
	if d.Messaging != nil {
		_ = d.Messaging.Close()
	}
	if d.DB != nil {
		d.DB.Close()
	}
	if d.telemetryShutdown != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.telemetryShutdown(shutdownCtx)
	}
}
