package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
)

// RegisterRoutes monta as rotas do módulo users num router já protegido
// por auth.RequireAuthentication (quem chama — internal/app — conecta
// esse middleware uma vez para todo /api/v1). /users e /users/{id} exigem
// adicionalmente a permissão users:read — listar/ver outros usuários é
// mais sensível que ver a si mesmo via /me.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger) {
	r.Get("/me", h.GetCurrentUser)

	r.Group(func(protected chi.Router) {
		protected.Use(auth.RequirePermission(logger, auth.PermUsersRead))
		protected.Get("/users", h.ListUsers)
		protected.Get("/users/{id}", h.GetUser)
	})
}
