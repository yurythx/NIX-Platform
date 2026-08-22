package transport

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/integrations/application"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

type Handlers struct {
	service *application.Service
	logger  *slog.Logger
}

func NewHandlers(service *application.Service, logger *slog.Logger) *Handlers {
	return &Handlers{service: service, logger: logger}
}

// ListIntegrations handles GET /api/v1/integrations.
func (h *Handlers) ListIntegrations(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.ListIntegrations(r.Context())
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	httputil.WriteOK(w, toIntegrationResponses(list))
}

// GetIntegrationStatus handles GET /api/v1/integrations/{id}/status.
func (h *Handlers) GetIntegrationStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("invalid integration id"))
		return
	}

	integration, err := h.service.GetIntegrationStatus(r.Context(), id)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toIntegrationResponse(integration))
}
