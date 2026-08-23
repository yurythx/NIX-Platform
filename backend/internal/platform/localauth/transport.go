package localauth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/config"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// ActionLoginFailed é registrado em audit_logs (§49) a cada tentativa de
// login local rejeitada — username inexistente, sem senha local
// configurada, ou senha errada. Pensado para detecção de força bruta;
// ActionLogin (já existente, usado também pelo fluxo Keycloak-side no
// futuro) cobre o caso de sucesso.
const ActionLoginFailed = "login.failed"

// Handlers expõe o endpoint de login local.
type Handlers struct {
	store  Store
	cfg    config.LocalAuthConfig
	audit  *audit.Writer
	logger *slog.Logger
}

func NewHandlers(store Store, cfg config.LocalAuthConfig, auditWriter *audit.Writer, logger *slog.Logger) *Handlers {
	return &Handlers{store: store, cfg: cfg, audit: auditWriter, logger: logger}
}

type loginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type loginResponse struct {
	AccessToken string            `json:"access_token"`
	TokenType   string            `json:"token_type"`
	ExpiresAt   string            `json:"expires_at"`
	User        loginResponseUser `json:"user"`
}

// loginResponseUser poupa o chamador (o NextAuth CredentialsProvider do
// frontend, hoje) de precisar decodificar o JWT só para saber quem acabou
// de logar — nunca inclui PasswordHash nem Roles brutas, só o suficiente
// para exibir "logado como X".
type loginResponseUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// Login trata POST /api/v1/auth/login. Rota pública — não passa por
// auth.RequireAuthentication, pelo motivo óbvio de que quem chama ainda
// não está autenticado. Retorna sempre a mesma mensagem genérica de erro
// para "username não existe", "username existe mas é conta só-Keycloak"
// e "senha errada" — não dar ao chamador uma forma de descobrir, por
// tentativa e erro, quais usernames têm conta local configurada.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Enabled {
		httputil.WriteError(w, r, h.logger, apperrors.NotFound("local login is not enabled"))
		return
	}

	var req loginRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	if err := httputil.Validate(req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	account, err := h.store.GetByUsername(r.Context(), req.Username)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteError(w, r, h.logger, err)
			return
		}
		h.recordFailure(r, req.Username, "unknown username or no local password set")
		h.rejectInvalidCredentials(w, r)
		return
	}

	if !account.Active {
		h.recordFailure(r, req.Username, "account is inactive")
		h.rejectInvalidCredentials(w, r)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.Password)); err != nil {
		h.recordFailure(r, req.Username, "wrong password")
		h.rejectInvalidCredentials(w, r)
		return
	}

	token, expiresAt, err := auth.IssueLocalToken(h.cfg, auth.LocalAccount{
		ID:       account.ID.String(),
		Username: account.Username,
		Email:    account.Email,
		Roles:    account.Roles,
	})
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.Internal(err))
		return
	}

	if err := h.store.TouchLastSeen(r.Context(), account.ID); err != nil {
		// Não bloqueia o login por isto — é só um carimbo de atividade,
		// não uma condição de segurança.
		h.logger.Warn("localauth: failed to touch last_seen_at", slog.Any("error", err))
	}

	if h.audit != nil {
		uid := account.ID
		_ = h.audit.Record(r.Context(), audit.Entry{
			UserID:       &uid,
			Action:       audit.ActionLogin,
			ResourceType: "user",
			ResourceID:   account.ID.String(),
			Metadata:     map[string]any{"method": "local"},
			IPAddress:    httpserver.ClientIPKey(r),
		})
	}

	httputil.WriteOK(w, loginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt.Format("2006-01-02T15:04:05Z07:00"),
		User: loginResponseUser{
			ID:       account.ID.String(),
			Username: account.Username,
			Email:    account.Email,
		},
	})
}

func (h *Handlers) recordFailure(r *http.Request, username, reason string) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Record(r.Context(), audit.Entry{
		Action:       ActionLoginFailed,
		ResourceType: "user",
		ResourceID:   username,
		Metadata:     map[string]any{"method": "local", "reason": reason},
		IPAddress:    httpserver.ClientIPKey(r),
	})
}

func (h *Handlers) rejectInvalidCredentials(w http.ResponseWriter, r *http.Request) {
	httputil.WriteError(w, r, h.logger, apperrors.Unauthorized("invalid username or password"))
}

// RateLimitKey limita tentativas de login por IP — não há identidade
// autenticada ainda para usar como chave (ao contrário de
// diario_oficial/secops RateLimitKey, que usam o subject do chamador).
func RateLimitKey(r *http.Request) string {
	return httpserver.ClientIPKey(r)
}

// RegisterRoutes monta a rota pública de login local. r deve ser um
// router SEM auth.RequireAuthentication — ao contrário dos outros
// RegisterRoutes da plataforma, este precisa ficar fora do grupo
// autenticado de /api/v1.
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger, limiter httpserver.Limiter) {
	r.With(httpserver.RateLimit(logger, limiter, RateLimitKey)).
		Post("/api/v1/auth/login", h.Login)
}
