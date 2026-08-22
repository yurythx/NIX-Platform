package transport

import "github.com/go-chi/chi/v5"

// RegisterRoutes mounts the integrations module's routes onto an already
// auth.RequireAuthentication-protected router.
func RegisterRoutes(r chi.Router, h *Handlers) {
	r.Get("/integrations", h.ListIntegrations)
	r.Get("/integrations/{id}/status", h.GetIntegrationStatus)
}
