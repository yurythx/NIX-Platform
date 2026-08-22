// Package app conecta entre si toda dependência de plataforma e de módulo
// (banco de dados, mensageria, autenticação, hub de WebSocket, serviços de
// módulo) e expõe o router HTTP já montado usado pelo cmd/api e o runner
// de worker já montado usado pelo cmd/worker. É o único lugar autorizado a
// conhecer todo módulo de uma vez — nenhum módulo importa outro
// diretamente, só internal/app os conecta.
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
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/idempotency"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
	"github.com/yurythx/nix-platform/internal/platform/ratelimit"
	"github.com/yurythx/nix-platform/internal/platform/telemetry"
	"github.com/yurythx/nix-platform/internal/platform/ws"
)

// RateLimiters guarda todo rate limiter distribuído (baseado em Postgres —
// rate limiting distribuído) que a API usa. Construído uma única vez por
// processo e compartilhado por toda requisição, para que cada réplica da
// API leia/escreva as mesmas linhas de rate_limit_buckets em vez de cada
// uma manter sua própria contagem independente em memória (e portanto
// N×-generosa demais).
type RateLimiters struct {
	TestJob  httpserver.Limiter // POST .../diario-oficial/test, .../virustotal/test
	WSTicket httpserver.Limiter // POST /api/v1/ws/ticket
}

// OutboxSource identifica este backend como o Source carimbado em todo
// envelope de evento gravado no outbox, independente de qual módulo o
// escreveu — a proveniência no nível de módulo vive em
// aggregate_type/aggregate_id.
const OutboxSource = "nix.platform"

// Dependencies guarda todo recurso de plataforma compartilhado.
// Dependências específicas de módulo (repositórios, casos de uso) são
// adicionadas a esta struct conforme cada módulo é conectado; nada aqui
// deve carregar regra de negócio.
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
	Idempotency  idempotency.Store
	Flags        configflags.Store

	telemetryShutdown telemetry.Shutdown
}

// NewDependencies constrói e valida toda dependência de plataforma para um
// processo. component distingue "api" de "worker" em logs e traces (os
// dois compartilham este mesmo bootstrap). Retorna um erro imediatamente
// se qualquer dependência obrigatória (banco de dados, RabbitMQ, discovery
// OIDC) não puder ser alcançada, para que o processo falhe rápido em vez
// de servir tráfego num estado parcialmente inicializado.
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

	// Declara a topologia (exchange, filas, DLQs, bindings) aqui no
	// bootstrap — tanto o cmd/api quanto o cmd/worker chamam
	// NewDependencies, então a topologia existe garantidamente antes de
	// qualquer um dos dois tentar publicar ou consumir, não importa qual
	// suba primeiro.
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
		Idempotency: idempotency.NewPostgresStore(pool),
		Flags:       configflags.NewPostgresStore(pool),

		telemetryShutdown: telemetryShutdown,
	}
	deps.Modules = buildModules(deps)

	return deps, nil
}

// Close libera todo recurso aberto por NewDependencies. Seguro de chamar
// uma vez durante o graceful shutdown.
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
