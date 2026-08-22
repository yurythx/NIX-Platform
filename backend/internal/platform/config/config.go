// Package config carrega e valida a configuração do NIX Platform a partir
// de variáveis de ambiente. Configuração obrigatória ausente faz Load
// retornar um erro imediatamente (fail fast) em vez de deixar a aplicação
// subir num estado parcialmente configurado — é preferível o processo nem
// iniciar a iniciar e falhar de forma imprevisível no primeiro request que
// tocar a configuração faltante.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig guarda as configurações gerais de identidade da aplicação.
type AppConfig struct {
	Env       string // development | staging | production
	Name      string
	LogLevel  string
	LogFormat string // json | text
}

// HTTPConfig guarda as configurações de bind do servidor HTTP.
type HTTPConfig struct {
	Host string
	Port int
}

func (c HTTPConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// DatabaseConfig guarda as configurações de conexão e pool do PostgreSQL.
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

// DSN retorna uma connection string no estilo libpq, pronta para o pgxpool.
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=%d",
		c.Host, c.Port, c.Name, c.User, c.Password, c.SSLMode, int(c.ConnectTimeout.Seconds()),
	)
}

// RabbitMQConfig guarda as configurações de conexão e de retry/prefetch do
// RabbitMQ.
type RabbitMQConfig struct {
	URL           string
	MaxRetries    int
	PrefetchCount int
}

// KeycloakConfig guarda as configurações OIDC do Keycloak gerenciado
// externamente — este projeto nunca cria/administra o Keycloak em si,
// apenas consome um realm/client já existentes (§29).
type KeycloakConfig struct {
	IssuerURL    string
	Realm        string
	ClientID     string
	ClientSecret string
	Audience     string
}

// JobsConfig guarda as configurações de processamento assíncrono de jobs.
type JobsConfig struct {
	Timeout time.Duration
}

// WorkerConfig guarda as configurações do listener HTTP mínimo próprio do
// cmd/worker, usado só para /health e /metrics (healthcheck do Docker +
// scrape do Prometheus) — nunca para tráfego de negócio.
type WorkerConfig struct {
	MetricsHost string
	MetricsPort int
}

func (c WorkerConfig) MetricsAddr() string {
	return fmt.Sprintf("%s:%d", c.MetricsHost, c.MetricsPort)
}

// DiarioOficialConfig guarda as configurações da integração com o Diário
// Oficial. BaseURL é deliberadamente permitido vazio — um ambiente sem
// essa integração configurada deve reportá-la como indisponível, não
// derrubar o processo.
type DiarioOficialConfig struct {
	BaseURL string
	Timeout time.Duration
}

// VirusTotalConfig guarda as configurações da integração SecOps com o
// VirusTotal.
type VirusTotalConfig struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

// Config é a configuração da aplicação já totalmente validada.
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

// loader acumula os erros de leitura para que Load reporte de uma vez toda
// variável faltante, em vez de forçar quem está operando a passar por um
// ciclo de "corrige uma, reinicia, corrige a próxima".
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

// secret funciona como str, mas primeiro verifica se existe uma variável
// "<KEY>_FILE" apontando para um arquivo — se sim, o CONTEÚDO do arquivo
// (sem espaços/quebras de linha nas pontas) é usado como valor, e a
// variável "<KEY>" direta é ignorada.
//
// Isto é o padrão universal para rotação/gestão de segredos sem precisar
// de código específico para cada backend: Docker Swarm secrets monta cada
// segredo como um arquivo em /run/secrets/<nome>; Kubernetes Secrets
// montados como volume funcionam do mesmo jeito; o Vault Agent Sidecar
// Injector escreve o segredo lido do Vault num arquivo local; AWS
// Secrets Manager com o CSI driver também. Nenhum desses precisa que a
// aplicação fale a API específica do provedor — só que ela saiba ler
// "<KEY>_FILE" em vez de "<KEY>" quando o arquivo existir. Usado para
// todo valor que é de fato um segredo (senha, client secret, chave de
// API) — nunca para configuração não sensível (host, nome de banco,
// etc.), que continua vindo direto de env var via str().
func (l *loader) secret(key string, required bool, def string) string {
	filePath, hasFileVar := os.LookupEnv(key + "_FILE")
	if hasFileVar && filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			l.errs = append(l.errs, fmt.Sprintf("%s_FILE (failed to read %q: %v)", key, filePath, err))
			return def
		}
		return strings.TrimSpace(string(content))
	}
	return l.str(key, required, def)
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

// Load lê a configuração a partir do ambiente do processo. Retorna um erro
// nomeando toda variável obrigatória ausente/inválida, caso a validação
// falhe.
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
			Password:        l.secret("DB_PASSWORD", true, ""),
			SSLMode:         l.str("DB_SSLMODE", false, "disable"),
			MaxConns:        int32(l.intVal("DB_MAX_CONNS", false, 20)),
			MinConns:        int32(l.intVal("DB_MIN_CONNS", false, 2)),
			MaxConnLifetime: l.durationVal("DB_MAX_CONN_LIFETIME", false, time.Hour),
			MaxConnIdleTime: l.durationVal("DB_MAX_CONN_IDLE_TIME", false, 15*time.Minute),
			ConnectTimeout:  l.durationVal("DB_CONNECT_TIMEOUT", false, 5*time.Second),
		},
		RabbitMQ: RabbitMQConfig{
			URL:           l.secret("RABBITMQ_URL", true, ""),
			MaxRetries:    l.intVal("RABBITMQ_MAX_RETRIES", false, 3),
			PrefetchCount: l.intVal("RABBITMQ_PREFETCH_COUNT", false, 10),
		},
		Keycloak: KeycloakConfig{
			IssuerURL:    l.str("KEYCLOAK_ISSUER_URL", true, ""),
			Realm:        l.str("KEYCLOAK_REALM", true, ""),
			ClientID:     l.str("KEYCLOAK_CLIENT_ID", true, ""),
			ClientSecret: l.secret("KEYCLOAK_CLIENT_SECRET", false, ""),
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
			APIKey:  l.secret("VIRUSTOTAL_API_KEY", false, ""),
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

// IsProduction reporta se a aplicação está rodando em produção.
func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}
