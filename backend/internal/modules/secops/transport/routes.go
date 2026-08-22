package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// RegisterRoutes mounts the secops module's routes onto an already
// auth.RequireAuthentication-protected router. limiter is built once in
// internal/app (backed by Postgres, shared across every API replica —
// §rate limiting distribuído) and passed in rather than constructed
// here, so every module doesn't stand up its own store.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger, limiter httpserver.Limiter) {
	r.With(
		auth.RequirePermission(logger, auth.PermIntegrationsTest),
		httpserver.RateLimit(logger, limiter, RateLimitKey),
	).Post("/integrations/secops/virustotal/test", h.TestVirusTotal)
}
