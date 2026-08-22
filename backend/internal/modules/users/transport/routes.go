package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
)

// RegisterRoutes mounts the users module's routes onto an already
// auth.RequireAuthentication-protected router (the caller — internal/app —
// wires that middleware once for all of /api/v1).
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger) {
	r.Get("/me", h.GetCurrentUser)

	r.Group(func(protected chi.Router) {
		protected.Use(auth.RequirePermission(logger, auth.PermUsersRead))
		protected.Get("/users", h.ListUsers)
		protected.Get("/users/{id}", h.GetUser)
	})
}
