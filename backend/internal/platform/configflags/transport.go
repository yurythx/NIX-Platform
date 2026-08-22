package configflags

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// ActionFeatureFlagChanged é a ação registrada em audit_logs (§49) toda
// vez que uma flag é alterada via Set.
const ActionFeatureFlagChanged = "feature_flag.changed"

// Handlers expõe a API administrativa de feature flags — GET para
// listar, PATCH para alternar. Registrado atrás de
// auth.RequirePermission(auth.PermFeatureFlagsManage), ou seja, restrito
// ao papel nix-admin (§ Feature Flags & Configuração Dinâmica).
type Handlers struct {
	store  Store
	audit  *audit.Writer
	logger *slog.Logger
}

func NewHandlers(store Store, auditWriter *audit.Writer, logger *slog.Logger) *Handlers {
	return &Handlers{store: store, audit: auditWriter, logger: logger}
}

// flagResponse é o formato público de uma flag retornada pela API.
type flagResponse struct {
	Key         string `json:"key"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updated_at"`
	UpdatedBy   string `json:"updated_by,omitempty"`
}

func toFlagResponse(f Flag) flagResponse {
	return flagResponse{
		Key:         f.Key,
		Enabled:     f.Enabled,
		Description: f.Description,
		UpdatedAt:   f.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedBy:   f.UpdatedBy,
	}
}

// List trata GET /api/v1/admin/feature-flags.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	flags, err := h.store.List(r.Context())
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	out := make([]flagResponse, 0, len(flags))
	for _, f := range flags {
		out = append(out, toFlagResponse(f))
	}
	httputil.WriteOK(w, out)
}

type setFlagRequest struct {
	Enabled *bool `json:"enabled" validate:"required"`
}

// Set trata PATCH /api/v1/admin/feature-flags/{key}. O corpo
// {"enabled": bool} decide o novo estado; a flag é criada na primeira
// alteração se ainda não existir (upsert — ver PostgresStore.Set), então
// este mesmo endpoint também serve para registrar uma flag nova em tempo
// de execução, sem precisar de uma migration.
func (h *Handlers) Set(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("missing flag key"))
		return
	}

	var req setFlagRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	if err := httputil.Validate(req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	var updatedBy string
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		updatedBy = identity.Subject
	}

	flag, err := h.store.Set(r.Context(), key, *req.Enabled, updatedBy)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	if h.audit != nil {
		// audit.Entry.UserID espera um uuid.UUID (o id da linha local do
		// usuário), enquanto updatedBy aqui é o subject do Keycloak (nem
		// sempre um UUID) — guardamos em Metadata em vez de forçar a
		// conversão, para não perder a informação de quem alterou.
		_ = h.audit.Record(r.Context(), audit.Entry{
			Action:       ActionFeatureFlagChanged,
			ResourceType: "feature_flag",
			ResourceID:   key,
			Metadata: map[string]any{
				"enabled":    flag.Enabled,
				"updated_by": updatedBy,
			},
		})
	}

	httputil.WriteOK(w, toFlagResponse(flag))
}

// RegisterRoutes monta as rotas administrativas de feature flags. r já
// deve estar atrás de auth.RequireAuthentication; este método adiciona
// por cima a exigência de auth.PermFeatureFlagsManage (nix-admin) para
// ambas as rotas — mesmo a leitura, já que a lista de flags revela
// detalhes operacionais internos (quais integrações existem, se estão
// habilitadas) que não são para qualquer usuário autenticado ver.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger) {
	r.Route("/admin/feature-flags", func(admin chi.Router) {
		admin.Use(auth.RequirePermission(logger, auth.PermFeatureFlagsManage))
		admin.Get("/", h.List)
		admin.Patch("/{key}", h.Set)
	})
}
