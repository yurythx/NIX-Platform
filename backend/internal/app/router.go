package app

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	diarioTransport "github.com/yurythx/nix-platform/internal/modules/diario_oficial/transport"
	integrationsTransport "github.com/yurythx/nix-platform/internal/modules/integrations/transport"
	usersTransport "github.com/yurythx/nix-platform/internal/modules/users/transport"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/idempotency"
	"github.com/yurythx/nix-platform/internal/platform/localauth"
	"github.com/yurythx/nix-platform/internal/platform/ws"
)

// NewRouter monta o router HTTP completo: a base da plataforma (health,
// metrics, request id, recovery, CORS, security headers), o /ready
// conectado a toda dependência essencial, e as rotas de negócio
// versionadas em /api/v1 e /ws.
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

	// O próprio /ws é autenticado por ticket (navegadores não conseguem
	// definir um header Authorization no handshake — §38), então
	// deliberadamente NÃO fica atrás de auth.RequireAuthentication.
	r.Get("/ws", ws.UpgradeHandler(deps.Hub, deps.Tickets, deps.Config.FrontendURL, deps.Logger))

	// Registrado no router de fora, ANTES do grupo /api/v1 autenticado
	// abaixo — quem está fazendo login, por definição, ainda não tem um
	// token para apresentar (§ Sistema de Login Local). Deliberadamente
	// um no-op (404) quando LOCAL_AUTH_ENABLED=false, ver
	// localauth.Handlers.Login.
	localauth.RegisterRoutes(r, deps.Modules.LocalAuth.Handlers, deps.Logger, deps.RateLimiters.LocalLogin)

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(auth.RequireAuthentication(deps.Verifier, deps.Logger))
		// Precisa vir depois de RequireAuthentication — chaves de
		// idempotência são escopadas por usuário autenticado (ver
		// internal/platform/idempotency.Middleware). Montado uma única
		// vez para todo /api/v1: só tem efeito em requisições que
		// realmente enviam o header Idempotency-Key, então não afeta
		// nenhuma rota que não o use.
		api.Use(idempotency.Middleware(deps.Idempotency, deps.Logger))

		api.With(httpserver.RateLimit(deps.Logger, deps.RateLimiters.WSTicket, wsTicketRateLimitKey)).
			Post("/ws/ticket", ws.TicketHandler(deps.Tickets, deps.Logger))

		usersTransport.RegisterRoutes(api, deps.Modules.Users.Handlers, deps.Logger)
		integrationsTransport.RegisterRoutes(api, deps.Modules.Integrations.Handlers)
		diarioTransport.RegisterRoutes(api, deps.Modules.DiarioOficial.Handlers, deps.Logger, deps.RateLimiters.TestJob)
		configflags.RegisterRoutes(api, deps.Modules.ConfigFlags.Handlers, deps.Logger)
	})

	return r
}

// wsTicketRateLimitKey limita a emissão de tickets por usuário autenticado
// em vez de por IP, já que o endpoint sempre roda atrás de
// auth.RequireAuthentication.
func wsTicketRateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
