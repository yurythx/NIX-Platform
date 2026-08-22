// Package httpserver provides the base chi router, shared middleware
// (request id, recovery, CORS, security headers, size limits, rate
// limiting) and the /health, /ready, /metrics endpoints. Business routes
// are mounted onto the router returned by New by internal/app/router.go —
// this package carries no business logic.
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

// Options configures the base router.
type Options struct {
	Logger            *slog.Logger
	AllowedOrigins    []string
	RequestTimeout    time.Duration
	MetricsMiddleware func(http.Handler) http.Handler // records HTTP metrics; optional
}

// New builds a chi.Router with the platform's standard middleware stack
// mounted, plus /health, /ready and /metrics. It does not include any
// authentication or business routes.
func New(opts Options) chi.Router {
	r := chi.NewRouter()

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
	if opts.MetricsMiddleware != nil {
		r.Use(opts.MetricsMiddleware)
	}

	r.Get("/health", HealthHandler())
	r.Handle("/metrics", promhttp.Handler())

	return r
}
