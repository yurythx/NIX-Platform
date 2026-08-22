package auth

import (
	"log/slog"
	"net/http"
	"strings"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// RequireAuthentication extracts and verifies the bearer token from the
// Authorization header, storing the resulting Identity in the request
// context. It must run before RequireRole/RequirePermission.
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

// RequireRole authorizes the request only if the authenticated identity
// has at least one of roles. Must run after RequireAuthentication.
func RequireRole(logger *slog.Logger, roles ...RoleName) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := IdentityFromContext(r.Context())
			if !ok {
				httputil.WriteError(w, r, logger, apperrors.Unauthorized("authentication required"))
				return
			}
			if !identity.HasAnyRole(roles...) {
				httputil.WriteError(w, r, logger, apperrors.Forbidden("insufficient role"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission authorizes the request only if the authenticated
// identity's roles grant permission. Must run after RequireAuthentication.
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
