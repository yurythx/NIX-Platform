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
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// ActionLoginFailed é registrado em audit_logs (§49) a cada tentativa de
// login local rejeitada — username inexistente, sem senha local
// configurada, conta bloqueada, ou senha errada. Pensado para detecção de
// força bruta; ActionLogin (já existente, usado também pelo fluxo
// Keycloak-side no futuro) cobre o caso de sucesso.
const ActionLoginFailed = "login.failed"

// dummyHash é um hash bcrypt válido de uma senha que não é a de nenhuma
// conta real — usado para rodar bcrypt.CompareHashAndPassword em todo
// caminho de rejeição que, de outra forma, retornaria mais rápido que o
// caminho de "senha errada" (username inexistente, conta bloqueada). Sem
// isso, a diferença de latência entre "essa conta existe mas está
// bloqueada" e "senha errada" seria um oráculo de temporização que revela
// informação a um atacante — mesmo as duas respostas HTTP sendo
// idênticas. O mesmo custo (10) usado no hash do usuário admin semeado
// pela migration 000011, para que o tempo de comparação seja equivalente.
const dummyHash = "$2a$10$f6v8uuTKRmZPxpA5UVCC5.hpi9Dhh5i6V8k2bxRd9ejDCzAfpNbB2"

// Handlers expõe o endpoint de login local.
type Handlers struct {
	store  Store
	signer *auth.LocalSigner
	audit  *audit.Writer
	logger *slog.Logger
}

// NewHandlers monta os handlers do login local. signer pode ser nil — Login
// responde 404 nesse caso (a mesma checagem que antes olhava para um campo
// booleano "Enabled" separado; um LocalSigner nil já significa "desligado",
// ver auth.NewLocalSigner).
func NewHandlers(store Store, signer *auth.LocalSigner, auditWriter *audit.Writer, logger *slog.Logger) *Handlers {
	return &Handlers{store: store, signer: signer, audit: auditWriter, logger: logger}
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
// para "username não existe", "username existe mas é conta só-Keycloak",
// "conta bloqueada" e "senha errada" — não dar ao chamador uma forma de
// descobrir, por tentativa e erro ou por temporização (ver dummyHash),
// qual delas ocorreu.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if h.signer == nil {
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
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(req.Password))
		h.recordFailure(r, req.Username, "unknown username or no local password set")
		h.rejectInvalidCredentials(w, r)
		return
	}

	if !account.Active {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(req.Password))
		h.recordFailure(r, req.Username, "account is inactive")
		h.rejectInvalidCredentials(w, r)
		return
	}

	if account.Locked() {
		// Ainda roda a comparação (contra o dummyHash, não a senha real)
		// para que o tempo de resposta de uma conta bloqueada seja
		// indistinguível do de uma senha errada comum — ver o comentário
		// de dummyHash.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(req.Password))
		h.recordFailure(r, req.Username, "account_locked")
		h.rejectInvalidCredentials(w, r)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.Password)); err != nil {
		if regErr := h.store.RegisterFailedAttempt(r.Context(), account.ID); regErr != nil {
			h.logger.Warn("localauth: failed to register failed login attempt", slog.Any("error", regErr))
		}
		h.recordFailure(r, req.Username, "wrong password")
		h.rejectInvalidCredentials(w, r)
		return
	}

	token, expiresAt, err := h.signer.IssueToken(auth.LocalAccount{
		ID:       account.ID.String(),
		Username: account.Username,
		Email:    account.Email,
		Roles:    account.Roles,
	})
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.Internal(err))
		return
	}

	if err := h.store.ResetFailedAttempts(r.Context(), account.ID); err != nil {
		h.logger.Warn("localauth: failed to reset failed login attempts", slog.Any("error", err))
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

	// O corpo carrega um bearer token — nunca deve ficar em cache de
	// disco do navegador nem em nenhum proxy/CDN intermediário.
	w.Header().Set("Cache-Control", "no-store")
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
	w.Header().Set("Cache-Control", "no-store")
	httputil.WriteError(w, r, h.logger, apperrors.Unauthorized("invalid username or password"))
}

// RateLimitKey limita tentativas de login por IP — não há identidade
// autenticada ainda para usar como chave (ao contrário de
// diario_oficial/secops RateLimitKey, que usam o subject do chamador).
// Defesa em profundidade além disso: o bloqueio por conta em
// Store.RegisterFailedAttempt cobre o caso de um atacante distribuído
// (múltiplos IPs), que este rate limit por IP sozinho não pegaria.
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
