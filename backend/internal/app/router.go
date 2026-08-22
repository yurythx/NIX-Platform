package app

import (
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// NewRouter assembles the full HTTP router: the platform base (health,
// metrics, request id, recovery, CORS, security headers), /ready wired to
// every essential dependency, and — as later phases add them — the
// versioned /api/v1 business routes and /ws.
func NewRouter(deps *Dependencies) chi.Router {
	r := httpserver.New(httpserver.Options{
		Logger:         deps.Logger,
		AllowedOrigins: []string{deps.Config.FrontendURL},
		RequestTimeout: 30 * time.Second,
	})

	checks := []httpserver.Check{
		{Name: "postgres", Fn: database.Ping(deps.DB)},
		{Name: "rabbitmq", Fn: deps.Messaging.Ping},
	}
	r.Get("/ready", httpserver.ReadyHandler(checks, 3*time.Second))

	// /api/v1/* business routes and /ws are mounted here in later phases,
	// once the users/integrations/diario_oficial/secops modules and the
	// WebSocket hub exist.

	return r
}
