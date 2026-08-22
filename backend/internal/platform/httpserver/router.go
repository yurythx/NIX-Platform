// Package httpserver fornece o router chi base, os middlewares
// compartilhados (request id, recovery, CORS, security headers, limite de
// tamanho, rate limiting) e os endpoints /health, /ready, /metrics. As
// rotas de negócio são montadas sobre o router retornado por New pelo
// internal/app/router.go — este pacote não carrega nenhuma regra de
// negócio, só a infraestrutura HTTP comum a toda a aplicação.
package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options configura o router base.
type Options struct {
	Logger         *slog.Logger
	AllowedOrigins []string
	RequestTimeout time.Duration
}

// New constrói um chi.Router com a pilha padrão de middlewares da
// plataforma já montada, mais /health e /metrics. Não inclui nenhuma rota
// de autenticação ou de negócio — essas são adicionadas por cima
// (internal/app/router.go), incluindo o /ready, que depende dos Checks de
// dependência específicos daquele processo (API ou worker).
func New(opts Options) chi.Router {
	r := chi.NewRouter()

	// A ordem dos middlewares importa: RequestID precisa vir primeiro para
	// que AccessLog e Recoverer já consigam incluir o request id nos logs
	// que emitem; Recoverer precisa vir antes de qualquer coisa que possa
	// dar panic, para transformar isso em 500 em vez de derrubar o
	// processo; SecurityHeaders/CORS valem tanto para respostas normais
	// quanto para as de erro capturadas pelo Recoverer.
	r.Use(RequestID)
	r.Use(AccessLog(opts.Logger))
	r.Use(Recoverer(opts.Logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   opts.AllowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(SecurityHeaders)
	r.Use(chimiddleware.Timeout(opts.RequestTimeout))
	r.Use(Metrics)

	r.Get("/health", HealthHandler())
	r.Handle("/metrics", promhttp.Handler())

	return r
}
