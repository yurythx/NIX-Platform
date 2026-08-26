package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// RegisterRoutes mounts the diario_oficial module's routes onto an
// already auth.RequireAuthentication-protected router. limiter is built
// once in internal/app (backed by Postgres, shared across every API
// replica — §rate limiting distribuído) and passed in rather than
// constructed here, so every module doesn't stand up its own store.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger, limiter httpserver.Limiter) {
	r.With(
		auth.RequirePermission(logger, auth.PermIntegrationsTest),
		httpserver.RateLimit(logger, limiter, RateLimitKey),
	).Post("/integrations/diario-oficial/test", h.TestDiarioOficial)

	// MVP de monitoramento real do Diário Oficial via DJEN —
	// cadastrar/listar/remover termo (manage) e ler publicações casadas
	// (read), mesma separação leitura/gestão que scanning:read/manage
	// já usa.
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialManage),
	).Post("/diario-oficial/monitored-terms", h.CreateMonitoredTerm)
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialRead),
	).Get("/diario-oficial/monitored-terms", h.ListMonitoredTerms)
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialManage),
	).Delete("/diario-oficial/monitored-terms/{termID}", h.DeleteMonitoredTerm)
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialRead),
	).Get("/diario-oficial/monitored-terms/{termID}/publications", h.ListPublicationsForTerm)
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialRead),
	).Get("/diario-oficial/publications", h.ListRecentPublications)
	r.With(
		auth.RequirePermission(logger, auth.PermDiarioOficialRead),
	).Get("/diario-oficial/health", h.Health)
}
