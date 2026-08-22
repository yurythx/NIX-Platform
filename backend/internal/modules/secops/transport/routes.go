package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// RegisterRoutes monta as rotas do módulo secops num router já protegido
// por auth.RequireAuthentication. limiter é construído uma única vez em
// internal/app (baseado em Postgres, compartilhado por toda réplica da
// API — rate limiting distribuído) e passado por parâmetro em vez de
// construído aqui, para que cada módulo não crie seu próprio
// armazenamento de rate limit.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger, limiter httpserver.Limiter) {
	r.With(
		auth.RequirePermission(logger, auth.PermIntegrationsTest),
		httpserver.RateLimit(logger, limiter, RateLimitKey),
	).Post("/integrations/secops/virustotal/test", h.TestVirusTotal)
}
