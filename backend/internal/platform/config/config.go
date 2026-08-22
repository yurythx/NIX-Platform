// Package config loads and validates the NIX Platform configuration from
// environment variables. Missing required configuration makes Load return
// an error immediately (fail fast) instead of letting the application start
// in a partially configured state.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig holds general application identity settings.
type AppConfig struct {
	Env       string // development | staging | production
	Name      string
	LogLevel  string
	LogFormat string // json | text
}

// HTTPConfig holds the HTTP server bind settings.
type HTTPConfig struct {
	Host string
	Port int
}

func (c HTTPConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// DatabaseConfig holds the PostgreSQL connection and pool settings.
type DatabaseConfig struct {
	Host            string
	Port            int
	Name            string
	User            string
	Password        string
	SSLMode         string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	ConnectTimeout  time.Duration
}

// DSN returns a libpq-style connection string suitable for pgxpool.
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=%d",
		c.Host, c.Port, c.Name, c.User, c.Password, c.SSLMode, int(c.ConnectTimeout.Seconds()),
	)
}

// RabbitMQConfig holds RabbitMQ connection and retry/prefetch settings.
type RabbitMQConfig struct {
	URL           string
	MaxRetries    int
	PrefetchCount int
}

// KeycloakConfig holds the OIDC settings for the externally managed Keycloak.
type KeycloakConfig struct {
	IssuerURL    string
	Realm        string
	ClientID     string
	ClientSecret string
	Audience     string
}

// JobsConfig holds asynchronous job processing settings.
type JobsConfig struct {
	Timeout time.Duration
}

// WorkerConfig holds settings for cmd/worker's own minimal HTTP listener,
// used only for /health and /metrics (Docker healthcheck + Prometheus
// scrape) — never for business traffic.
type WorkerConfig struct {
	MetricsHost string
	MetricsPort int
}

func (c WorkerConfig) MetricsAddr() string {
	return fmt.Sprintf("%s:%d", c.MetricsHost, c.MetricsPort)
}

// DiarioOficialConfig holds settings for the Diário Oficial integration.
// BaseURL is intentionally allowed to be empty — an unconfigured
// environment should report the integration as unavailable, not crash.
type DiarioOficialConfig struct {
	BaseURL string
	Timeout time.Duration
}

// VirusTotalConfig holds settings for the VirusTotal SecOps integration.
type VirusTotalConfig struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

// Config is the fully validated application configuration.
type Config struct {
	App      AppConfig
	HTTP     HTTPConfig
	Database DatabaseConfig
	RabbitMQ RabbitMQConfig
	Keycloak KeycloakConfig
	Jobs     JobsConfig
	Worker   WorkerConfig

	DiarioOficial DiarioOficialConfig
	VirusTotal    VirusTotalConfig

	FrontendURL         string
	APIPublicURL        string
	WebSocketPublicURL  string
	OTELExporterOTLPURL string
	MaxPageSize         int
}

// loader accumulates lookup errors so Load reports every missing variable at
// once instead of forcing the operator through a fix-one-restart-repeat loop.
type loader struct {
	errs []string
}

func (l *loader) str(key string, required bool, def string) string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		if required {
			l.errs = append(l.errs, key)
		}
		return def
	}
	return v
}

func (l *loader) intVal(key string, required bool, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		if required {
			l.errs = append(l.errs, key)
		}
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s (invalid integer %q)", key, v))
		return def
	}
	return n
}

func (l *loader) durationVal(key string, required bool, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		if required {
			l.errs = append(l.errs, key)
		}
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s (invalid duration %q)", key, v))
		return def
	}
	return d
}

// Load reads configuration from the process environment. It returns an
// error naming every missing/invalid required variable if validation fails.
func Load() (*Config, error) {
	l := &loader{}

	cfg := &Config{
		App: AppConfig{
			Env:       l.str("APP_ENV", true, ""),
			Name:      l.str("APP_NAME", false, "nix-platform"),
			LogLevel:  l.str("APP_LOG_LEVEL", false, "info"),
			LogFormat: l.str("LOG_FORMAT", false, "json"),
		},
		HTTP: HTTPConfig{
			Host: l.str("HTTP_HOST", false, "0.0.0.0"),
			Port: l.intVal("HTTP_PORT", false, 8000),
		},
		Database: DatabaseConfig{
			Host:            l.str("DB_HOST", true, ""),
			Port:            l.intVal("DB_PORT", true, 0),
			Name:            l.str("DB_NAME", true, ""),
			User:            l.str("DB_USER", true, ""),
			Password:        l.str("DB_PASSWORD", true, ""),
			SSLMode:         l.str("DB_SSLMODE", false, "disable"),
			MaxConns:        int32(l.intVal("DB_MAX_CONNS", false, 20)),
			MinConns:        int32(l.intVal("DB_MIN_CONNS", false, 2)),
			MaxConnLifetime: l.durationVal("DB_MAX_CONN_LIFETIME", false, time.Hour),
			MaxConnIdleTime: l.durationVal("DB_MAX_CONN_IDLE_TIME", false, 15*time.Minute),
			ConnectTimeout:  l.durationVal("DB_CONNECT_TIMEOUT", false, 5*time.Second),
		},
		RabbitMQ: RabbitMQConfig{
			URL:           l.str("RABBITMQ_URL", true, ""),
			MaxRetries:    l.intVal("RABBITMQ_MAX_RETRIES", false, 3),
			PrefetchCount: l.intVal("RABBITMQ_PREFETCH_COUNT", false, 10),
		},
		Keycloak: KeycloakConfig{
			IssuerURL:    l.str("KEYCLOAK_ISSUER_URL", true, ""),
			Realm:        l.str("KEYCLOAK_REALM", true, ""),
			ClientID:     l.str("KEYCLOAK_CLIENT_ID", true, ""),
			ClientSecret: l.str("KEYCLOAK_CLIENT_SECRET", false, ""),
			Audience:     l.str("KEYCLOAK_AUDIENCE", true, ""),
		},
		Jobs: JobsConfig{
			Timeout: l.durationVal("JOB_TIMEOUT", false, 5*time.Minute),
		},
		Worker: WorkerConfig{
			MetricsHost: l.str("WORKER_METRICS_HOST", false, "0.0.0.0"),
			MetricsPort: l.intVal("WORKER_METRICS_PORT", false, 9100),
		},
		DiarioOficial: DiarioOficialConfig{
			BaseURL: l.str("DIARIO_OFICIAL_BASE_URL", false, ""),
			Timeout: l.durationVal("DIARIO_OFICIAL_TIMEOUT", false, 10*time.Second),
		},
		VirusTotal: VirusTotalConfig{
			APIKey:  l.str("VIRUSTOTAL_API_KEY", false, ""),
			BaseURL: l.str("VIRUSTOTAL_BASE_URL", false, "https://www.virustotal.com/api/v3"),
			Timeout: l.durationVal("VIRUSTOTAL_TIMEOUT", false, 10*time.Second),
		},
		FrontendURL:         l.str("FRONTEND_URL", false, "http://localhost:3000"),
		APIPublicURL:        l.str("API_PUBLIC_URL", false, "http://localhost:8000"),
		WebSocketPublicURL:  l.str("WEBSOCKET_PUBLIC_URL", false, "ws://localhost:8000/ws"),
		OTELExporterOTLPURL: l.str("OTEL_EXPORTER_OTLP_ENDPOINT", false, ""),
		MaxPageSize:         l.intVal("MAX_PAGE_SIZE", false, 100),
	}

	if len(l.errs) > 0 {
		return nil, fmt.Errorf("config: missing or invalid required environment variables: %s", strings.Join(l.errs, ", "))
	}

	if cfg.App.Env != "development" && cfg.App.Env != "staging" && cfg.App.Env != "production" && cfg.App.Env != "test" {
		return nil, fmt.Errorf("config: APP_ENV must be one of development|staging|production|test, got %q", cfg.App.Env)
	}

	return cfg, nil
}

// IsProduction reports whether the application is running in production.
func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}
