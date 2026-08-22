// Package resilience implementa o padrão Circuit Breaker (§ Circuit
// Breaker & Resiliência HTTP) sobre github.com/sony/gobreaker/v2: quando
// um provedor externo (Diário Oficial, VirusTotal) começa a falhar
// repetidamente, o circuito abre e toda chamada subsequente falha
// IMEDIATAMENTE com um erro de fallback amigável, em vez de continuar
// tentando (e esperando o timeout HTTP configurado) contra um provedor
// que já se mostrou indisponível — protege tanto o provedor externo
// (menos carga contra um serviço já sobrecarregado) quanto o próprio NIX
// Platform (workers não ficam presos em timeouts longos e repetidos,
// consumindo goroutines/conexões).
package resilience

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sony/gobreaker/v2"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// Valores padrão de configuração, usados por New quando Options não os
// especifica — ver o comentário de cada campo em Options para o
// raciocínio por trás de cada escolha.
const (
	DefaultMaxRequests         = 3
	DefaultInterval            = 60 * time.Second
	DefaultTimeout             = 30 * time.Second
	DefaultConsecutiveFailures = 5
)

// Options configura um Breaker.
type Options struct {
	// Name identifica o breaker nos logs, métricas e mensagens de erro —
	// tipicamente o nome do provedor externo protegido, ex.: "virustotal".
	Name string

	// MaxRequests é quantas requisições de teste são permitidas passar
	// enquanto o circuito está half-open (testando se o provedor já
	// voltou). Zero usa DefaultMaxRequests.
	MaxRequests uint32

	// Interval é de quanto em quanto tempo os contadores de
	// sucesso/falha são zerados enquanto o circuito está fechado. Zero
	// usa DefaultInterval.
	Interval time.Duration

	// Timeout é por quanto tempo o circuito fica aberto antes de passar
	// para half-open e tentar de novo. Zero usa DefaultTimeout.
	Timeout time.Duration

	// ConsecutiveFailures é quantas falhas seguidas (dentro do mesmo
	// Interval) abrem o circuito. Zero usa DefaultConsecutiveFailures.
	ConsecutiveFailures uint32

	// Logger recebe uma linha em toda transição de estado. Se nil,
	// nenhum log é emitido (as métricas ainda são registradas).
	Logger *slog.Logger
}

// Breaker envolve gobreaker.CircuitBreaker[T], traduzindo os erros
// internos do gobreaker (estado aberto / limite de requisições de teste
// no half-open) para o erro de domínio padrão da plataforma
// (apperrors.DependencyUnavailable com o código CIRCUIT_OPEN), e
// conectando toda transição de estado às métricas Prometheus
// nix_circuit_breaker_* (§53).
type Breaker[T any] struct {
	cb   *gobreaker.CircuitBreaker[T]
	name string
}

// New constrói um Breaker[T] com os Options informados, aplicando os
// padrões documentados acima para todo campo zerado.
func New[T any](opts Options) *Breaker[T] {
	maxRequests := opts.MaxRequests
	if maxRequests == 0 {
		maxRequests = DefaultMaxRequests
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	consecutiveFailures := opts.ConsecutiveFailures
	if consecutiveFailures == 0 {
		consecutiveFailures = DefaultConsecutiveFailures
	}

	name := opts.Name
	metrics.CircuitBreakerState.WithLabelValues(name).Set(float64(gobreaker.StateClosed))

	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: maxRequests,
		Interval:    interval,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= consecutiveFailures
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			metrics.CircuitBreakerState.WithLabelValues(name).Set(float64(to))
			metrics.CircuitBreakerTransitionsTotal.WithLabelValues(name, from.String(), to.String()).Inc()
			if opts.Logger != nil {
				opts.Logger.Warn("circuit breaker state changed",
					slog.String("breaker", name), slog.String("from", from.String()), slog.String("to", to.String()))
			}
		},
	}

	return &Breaker[T]{cb: gobreaker.NewCircuitBreaker[T](settings), name: name}
}

// Execute roda fn através do circuit breaker. Enquanto o circuito está
// fechado ou half-open (dentro do limite de MaxRequests de teste), fn é
// chamada normalmente e seu resultado conta para as estatísticas de
// sucesso/falha. Enquanto está aberto, fn NUNCA é chamada — Execute
// retorna imediatamente um apperrors.DependencyUnavailable com o código
// CIRCUIT_OPEN, o "erro de fallback amigável" pedido: o chamador (o
// handler HTTP, através da cadeia de erros) reporta ao cliente que a
// integração está temporariamente indisponível, sem esperar o timeout
// HTTP nem sobrecarregar ainda mais um provedor que já está com problema.
func (b *Breaker[T]) Execute(fn func() (T, error)) (T, error) {
	result, err := b.cb.Execute(fn)
	if err != nil && (errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests)) {
		return result, apperrors.DependencyUnavailable(
			fmt.Sprintf("%s: temporarily unavailable (circuit breaker open)", b.name),
		).WithCode("CIRCUIT_OPEN")
	}
	return result, err
}

// State reporta o estado atual do circuito — exposto para diagnósticos
// (ex.: um futuro endpoint de status detalhado) sem precisar depender só
// das métricas Prometheus.
func (b *Breaker[T]) State() gobreaker.State {
	return b.cb.State()
}
