package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

const RequestIDHeader = "X-Request-ID"

// RequestID respeita um header X-Request-ID de entrada ou gera um novo,
// devolve o mesmo valor na resposta, e o guarda no contexto da requisição
// para que toda linha de log e chamada subsequente (banco, outbox,
// RabbitMQ) possa carregá-lo — é a base da correlação de logs entre
// serviços descrita em §50.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := logging.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog loga uma linha estruturada por requisição, com método, path,
// status, duração e o request id.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)

			logging.FromContext(r.Context(), logger).Info("http_request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.status),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

// statusRecorder envolve um http.ResponseWriter só para capturar qual
// status code foi de fato escrito — o ResponseWriter padrão não expõe
// isso, e tanto AccessLog quanto Metrics precisam saber o status final
// depois que o handler já rodou.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Metrics registra nix_http_requests_total e
// nix_http_request_duration_seconds (§53). Rotula pelo *padrão* de rota
// que o chi casou (ex.: "/api/v1/users/{id}"), lido do contexto de
// roteamento depois que ServeHTTP retorna — nunca o path bruto, que
// explodiria a cardinalidade das métricas com uma série por id de usuário.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)

		route := "unmatched"
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if pattern := rctx.RoutePattern(); pattern != "" {
				route = pattern
			}
		}

		metrics.HTTPRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(ww.status)).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// Recoverer converte um panic em qualquer handler downstream numa resposta
// 500 estruturada, em vez de derrubar o processo inteiro ou vazar um stack
// trace para o cliente.
func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logging.FromContext(r.Context(), logger).Error("panic recovered",
						slog.Any("panic", rec),
						slog.String("path", r.URL.Path),
					)
					httputil.WriteError(w, r, logger, apperrors.Internal(fmt.Errorf("panic: %v", rec)))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders define os headers de segurança de base em toda resposta.
// O CSP com nonce (política mais forte, por requisição) é gerado à parte
// no proxy.ts do frontend — estes aqui são os headers estáticos que fazem
// sentido em qualquer resposta da API, independente de rota.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// Limiter decide se uma requisição identificada por key é permitida agora.
// RateLimit é deliberadamente desacoplado de qualquer implementação
// específica: o InMemoryLimiter abaixo funciona para um único processo,
// enquanto internal/platform/ratelimit.PostgresLimiter compartilha o
// estado entre todas as réplicas da API — trocar um pelo outro não exige
// tocar neste middleware.
type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// InMemoryLimiter é um limitador de token bucket por chave, com remoção
// preguiçosa de entradas obsoletas. É deliberadamente single-instance: com
// mais de uma réplica da API, cada uma tem seu próprio balde independente,
// então o limite *efetivo* vira N × o configurado. Serve bem para
// desenvolvimento local ou um deployment de réplica única; produção deve
// usar internal/platform/ratelimit.PostgresLimiter, que é compartilhado
// por todas as réplicas (rate limiting distribuído — a plataforma não usa
// Redis por design, §7, então o compartilhamento é feito via Postgres).
type InMemoryLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateEntry
	rps      rate.Limit
	burst    int
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewInMemoryLimiter(rps float64, burst int) *InMemoryLimiter {
	cl := &InMemoryLimiter{
		limiters: make(map[string]*rateEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go cl.evictLoop()
	return cl
}

// evictLoop remove periodicamente os buckets de chaves que não aparecem
// há mais de 10 minutos — sem isso, o mapa cresceria indefinidamente com
// uma entrada por IP/usuário já visto, mesmo que nunca mais volte.
func (cl *InMemoryLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cl.mu.Lock()
		for key, entry := range cl.limiters {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(cl.limiters, key)
			}
		}
		cl.mu.Unlock()
	}
}

func (cl *InMemoryLimiter) Allow(_ context.Context, key string) (bool, error) {
	cl.mu.Lock()
	entry, ok := cl.limiters[key]
	if !ok {
		entry = &rateEntry{limiter: rate.NewLimiter(cl.rps, cl.burst)}
		cl.limiters[key] = entry
	}
	entry.lastSeen = time.Now()
	limiter := entry.limiter
	cl.mu.Unlock()

	return limiter.Allow(), nil
}

// RateLimit retorna um middleware que limita cada cliente (identificado
// por keyFunc, tipicamente o id do usuário autenticado ou o IP remoto) de
// acordo com limiter. Um erro do Limiter (ex.: o banco por trás de um
// PostgresLimiter fica brevemente inalcançável) falha ABERTO — a
// requisição é deixada passar e o erro é apenas logado — em vez de deixar
// uma instabilidade do rate limiter virar uma indisponibilidade completa
// do endpoint que ele protege.
func RateLimit(logger *slog.Logger, limiter Limiter, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			allowed, err := limiter.Allow(r.Context(), key)
			if err != nil {
				logging.FromContext(r.Context(), logger).Error("rate limiter check failed, allowing request", slog.Any("error", err))
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				httputil.WriteError(w, r, logger, apperrors.RateLimited("too many requests, please try again later"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIPKey é um keyFunc padrão para RateLimit, usando o RemoteAddr da
// requisição.
func ClientIPKey(r *http.Request) string {
	return r.RemoteAddr
}

// contextTimeout é um pequeno helper usado pelas verificações de readiness.
func contextTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
