package app

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	diarioTransport "github.com/yurythx/nix-platform/internal/modules/diario_oficial/transport"
	integrationsTransport "github.com/yurythx/nix-platform/internal/modules/integrations/transport"
	secopsTransport "github.com/yurythx/nix-platform/internal/modules/secops/transport"
	usersTransport "github.com/yurythx/nix-platform/internal/modules/users/transport"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/ws"
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

	// /ws itself is ticket-authenticated (browsers can't set an
	// Authorization header on the handshake — §38), so it deliberately
	// does NOT sit behind auth.RequireAuthentication.
	r.Get("/ws", ws.UpgradeHandler(deps.Hub, deps.Tickets, deps.Config.FrontendURL, deps.Logger))

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(auth.RequireAuthentication(deps.Verifier, deps.Logger))

		api.With(httpserver.RateLimit(deps.Logger, 1, 5, wsTicketRateLimitKey)).
			Post("/ws/ticket", ws.TicketHandler(deps.Tickets, deps.Logger))

		usersTransport.RegisterRoutes(api, deps.Modules.Users.Handlers, deps.Logger)
		integrationsTransport.RegisterRoutes(api, deps.Modules.Integrations.Handlers)
		diarioTransport.RegisterRoutes(api, deps.Modules.DiarioOficial.Handlers, deps.Logger)
		secopsTransport.RegisterRoutes(api, deps.Modules.SecOps.Handlers, deps.Logger)
	})

	return r
}

// wsTicketRateLimitKey rate-limits ticket issuance per authenticated user
// rather than per IP, since the endpoint always runs behind
// auth.RequireAuthentication.
func wsTicketRateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
