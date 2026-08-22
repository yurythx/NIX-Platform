package transport

import "github.com/go-chi/chi/v5"

// RegisterRoutes monta as rotas do módulo integrations num router já
// protegido por auth.RequireAuthentication.
func RegisterRoutes(r chi.Router, h *Handlers) {
	r.Get("/integrations", h.ListIntegrations)
	r.Get("/integrations/{id}/status", h.GetIntegrationStatus)
}
