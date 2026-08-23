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

// GetCurrentUser trata GET /api/v1/me.
//
// Para identidades do Keycloak, sincroniza a linha local do usuário a
// partir do token a cada chamada (ver application.Service.GetCurrentUser)
// — é assim que o frontend descobre quem é o usuário logado e, no
// primeiro acesso, dispara a criação da conta local.
//
// Para identidades locais (§ Sistema de Login Local), NÃO há upsert: a
// conta já existe por definição (foi ela quem acabou de provar a senha em
// POST /api/v1/auth/login) e identity.Subject já É o id interno da linha
// em "users" — usar o fluxo de upsert-por-keycloak_subject aqui tentaria
// inserir uma segunda linha com o mesmo username/email e falharia com uma
// violação de unicidade, então os dois casos são tratados
// deliberadamente de formas diferentes.
func (h *Handlers) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, r, h.logger, apperrors.Unauthorized("authentication required"))
		return
	}

	if identity.Source == auth.SourceLocal {
		id, err := uuid.Parse(identity.Subject)
		if err != nil {
			httputil.WriteError(w, r, h.logger, apperrors.Unauthorized("invalid subject in local token"))
			return
		}
		user, err := h.service.GetUser(r.Context(), id)
		if err != nil {
			httputil.WriteError(w, r, h.logger, err)
			return
		}
		httputil.WriteOK(w, toUserResponse(user))
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

// ListUsers trata GET /api/v1/users — protegido por permissão
// users:read (ver routes.go); page/page_size vêm da query string e são
// limitados por h.maxPageSize (§46).
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

// GetUser trata GET /api/v1/users/{id}.
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
