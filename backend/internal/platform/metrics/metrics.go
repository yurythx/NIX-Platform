// Package metrics centraliza toda métrica Prometheus que a plataforma
// expõe em /metrics (§53). Defini-las todas aqui — em vez de espalhar
// chamadas a promauto por todo pacote — permite enxergar a superfície
// completa de métricas da plataforma num único arquivo e evita erros de
// registro duplicado; cada var é registrada no registry padrão exatamente
// uma vez, na inicialização do pacote.
//
// Os textos de "Help" de cada métrica ficam em inglês deliberadamente —
// são o contrato consumido por Prometheus/Grafana/alertas, não texto de
// UI, e seguem a convenção do ecossistema (o mesmo padrão usado pelas
// métricas nativas do próprio Prometheus e de toda métrica de terceiros
// que este projeto pode vir a agregar num dashboard).
package metrics

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// --- HTTP ---
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_http_requests_total",
		Help: "Total HTTP requests handled, by method, route and status code.",
	}, []string{"method", "route", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nix_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds, by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	// --- RabbitMQ ---
	RabbitMQPublishedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_rabbitmq_published_total",
		Help: "Messages successfully published (broker-confirmed), by routing key.",
	}, []string{"routing_key"})

	RabbitMQConsumedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_rabbitmq_consumed_total",
		Help: "Messages successfully consumed (acked), by queue.",
	}, []string{"queue"})

	RabbitMQFailedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_rabbitmq_failed_total",
		Help: "Message handler failures, by queue.",
	}, []string{"queue"})

	RabbitMQRetryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_rabbitmq_retry_total",
		Help: "Message redelivery attempts scheduled, by queue.",
	}, []string{"queue"})

	RabbitMQDLQTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_rabbitmq_dlq_total",
		Help: "Messages routed to a dead-letter queue after exhausting retries, by queue.",
	}, []string{"queue"})

	// --- Jobs ---
	JobsProcessedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_jobs_processed_total",
		Help: "Jobs that reached a terminal state, by type and outcome (completed/failed/dead_letter).",
	}, []string{"type", "status"})

	JobsDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nix_jobs_duration_seconds",
		Help:    "Time from job creation to reaching a terminal state, by type.",
		Buckets: prometheus.ExponentialBuckets(0.1, 2, 12), // 100ms .. ~200s
	}, []string{"type"})

	// --- WebSocket ---
	WebSocketConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nix_websocket_connections",
		Help: "Currently connected WebSocket clients.",
	})

	WebSocketErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nix_websocket_errors_total",
		Help: "WebSocket upgrade failures and dropped (slow/stuck) clients.",
	})

	// --- Integrations ---
	IntegrationRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_integration_requests_total",
		Help: "Outbound requests to an external integration, by provider.",
	}, []string{"provider"})

	IntegrationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nix_integration_request_duration_seconds",
		Help:    "Outbound integration request duration in seconds, by provider.",
		Buckets: prometheus.DefBuckets,
	}, []string{"provider"})

	IntegrationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nix_integration_failures_total",
		Help: "Failed outbound integration requests, by provider.",
	}, []string{"provider"})
)

// RegisterPostgresPoolMetrics registra os gauges
// nix_postgres_connections{state=...} baseados nas estatísticas ao vivo do
// pool (acquired/idle/max — §53). Valores de GaugeFunc são calculados de
// forma preguiçosa no momento do scrape, então isso não adiciona nenhuma
// goroutine em segundo plano própria. Chamar exatamente uma vez por pool.
func RegisterPostgresPoolMetrics(pool *pgxpool.Pool) {
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "nix_postgres_connections",
		Help:        "PostgreSQL pool connections, by state (acquired/idle/max).",
		ConstLabels: prometheus.Labels{"state": "acquired"},
	}, func() float64 { return float64(pool.Stat().AcquiredConns()) })

	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "nix_postgres_connections",
		Help:        "PostgreSQL pool connections, by state (acquired/idle/max).",
		ConstLabels: prometheus.Labels{"state": "idle"},
	}, func() float64 { return float64(pool.Stat().IdleConns()) })

	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "nix_postgres_connections",
		Help:        "PostgreSQL pool connections, by state (acquired/idle/max).",
		ConstLabels: prometheus.Labels{"state": "max"},
	}, func() float64 { return float64(pool.Stat().MaxConns()) })
}
