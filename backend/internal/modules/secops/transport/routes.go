package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// RegisterRoutes mounts the secops module's routes onto an already
// auth.RequireAuthentication-protected router.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger) {
	r.With(
		auth.RequirePermission(logger, auth.PermIntegrationsTest),
		httpserver.RateLimit(logger, 0.5, 3, RateLimitKey),
	).Post("/integrations/secops/virustotal/test", h.TestVirusTotal)
}
