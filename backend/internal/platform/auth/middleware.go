package auth

import (
	"log/slog"
	"net/http"
	"strings"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// RequireAuthentication extrai e verifica o bearer token do header
// Authorization, guardando a Identity resultante no contexto da
// requisição. Precisa rodar antes de RequirePermission, que lê a
// identidade do contexto que este middleware preenche.
func RequireAuthentication(verifier *Verifier, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken, err := bearerToken(r)
			if err != nil {
				httputil.WriteError(w, r, logger, err)
				return
			}

			identity, err := verifier.Verify(r.Context(), rawToken)
			if err != nil {
				httputil.WriteError(w, r, logger, apperrors.Unauthorized("invalid or expired access token"))
				return
			}

			ctx := WithIdentity(r.Context(), identity)
			ctx = logging.WithUserID(ctx, identity.Subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", apperrors.Unauthorized("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", apperrors.Unauthorized("Authorization header must use the Bearer scheme")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", apperrors.Unauthorized("empty bearer token")
	}
	return token, nil
}

// RequirePermission autoriza a requisição somente se os roles da
// identidade autenticada concederem permission. Precisa rodar depois de
// RequireAuthentication.
func RequirePermission(logger *slog.Logger, permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := IdentityFromContext(r.Context())
			if !ok {
				httputil.WriteError(w, r, logger, apperrors.Unauthorized("authentication required"))
				return
			}
			if !HasPermission(identity, permission) {
				httputil.WriteError(w, r, logger, apperrors.Forbidden("insufficient permission"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
