package transport

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/users/application"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

type Handlers struct {
	service     *application.Service
	logger      *slog.Logger
	maxPageSize int
}

func NewHandlers(service *application.Service, logger *slog.Logger, maxPageSize int) *Handlers {
	return &Handlers{service: service, logger: logger, maxPageSize: maxPageSize}
}

// GetCurrentUser handles GET /api/v1/me.
func (h *Handlers) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, r, h.logger, apperrors.Unauthorized("authentication required"))
		return
	}

	user, err := h.service.GetCurrentUser(r.Context(), application.SyncIdentityInput{
		Subject:  identity.Subject,
		Username: identity.Username,
		Email:    identity.Email,
	})
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toUserResponse(user))
}

// ListUsers handles GET /api/v1/users.
func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	params := pagination.New(page, pageSize, h.maxPageSize)

	users, meta, err := h.service.ListUsers(r.Context(), params)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOKWithMeta(w, toUserResponses(users), meta)
}

// GetUser handles GET /api/v1/users/{id}.
func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("invalid user id"))
		return
	}

	user, err := h.service.GetUser(r.Context(), id)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toUserResponse(user))
}
