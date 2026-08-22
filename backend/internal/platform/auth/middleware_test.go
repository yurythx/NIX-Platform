package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwk "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// testOIDCProvider sobe um endpoint HTTP real e autocontido de discovery
// OIDC + JWKS (sem rede além de localhost), para que o Verifier possa ser
// exercitado de ponta a ponta: discovery, cache de JWKS, validação de
// assinatura/issuer/audience/expiração — o mesmo caminho de código usado
// contra um Keycloak real.
type testOIDCProvider struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	p := &testOIDCProvider{privateKey: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 p.issuer,
			"jwks_uri":               p.issuer + "/jwks",
			"authorization_endpoint": p.issuer + "/auth",
			"token_endpoint":         p.issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := josejwk.JSONWebKeySet{
			Keys: []josejwk.JSONWebKey{
				{
					Key:       &key.PublicKey,
					KeyID:     p.kid,
					Algorithm: "RS256",
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	p.server = httptest.NewServer(mux)
	p.issuer = p.server.URL
	t.Cleanup(p.server.Close)
	return p
}

type tokenOpts struct {
	subject           string
	preferredUsername string
	email             string
	audience          string
	realmRoles        []string
	clientRoles       map[string][]string
	expiresAt         time.Time
	notBefore         time.Time
}

func (p *testOIDCProvider) signToken(t *testing.T, opts tokenOpts) string {
	t.Helper()

	resourceAccess := map[string]any{}
	for client, roles := range opts.clientRoles {
		resourceAccess[client] = map[string]any{"roles": roles}
	}

	claims := jwt.MapClaims{
		"iss":                p.issuer,
		"sub":                opts.subject,
		"aud":                opts.audience,
		"preferred_username": opts.preferredUsername,
		"email":              opts.email,
		"realm_access":       map[string]any{"roles": opts.realmRoles},
		"resource_access":    resourceAccess,
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                opts.expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid

	signed, err := token.SignedString(p.privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newTestVerifier(t *testing.T, p *testOIDCProvider, clientID, audience string) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), config.KeycloakConfig{
		IssuerURL: p.issuer,
		ClientID:  clientID,
		Audience:  audience,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func testHandlerEchoIdentity() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s|%s|%s", id.Subject, id.Username, id.Email)
	})
}

func TestRequireAuthentication_ValidToken(t *testing.T) {
	provider := newTestOIDCProvider(t)
	verifier := newTestVerifier(t, provider, "nix-platform-api", "nix-platform-api")
	logger := slog.Default()

	token := provider.signToken(t, tokenOpts{
		subject:           "sub-1",
		preferredUsername: "jdoe",
		email:             "jdoe@example.com",
		audience:          "nix-platform-api",
		realmRoles:        []string{RoleUser},
		expiresAt:         time.Now().Add(time.Hour),
	})

	handler := RequireAuthentication(verifier, logger)(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "sub-1|jdoe|jdoe@example.com" {
		t.Errorf("body = %q", got)
	}
}

func TestRequireAuthentication_MissingHeader(t *testing.T) {
	provider := newTestOIDCProvider(t)
	verifier := newTestVerifier(t, provider, "nix-platform-api", "nix-platform-api")
	handler := RequireAuthentication(verifier, slog.Default())(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthentication_ExpiredToken(t *testing.T) {
	provider := newTestOIDCProvider(t)
	verifier := newTestVerifier(t, provider, "nix-platform-api", "nix-platform-api")
	handler := RequireAuthentication(verifier, slog.Default())(testHandlerEchoIdentity())

	token := provider.signToken(t, tokenOpts{
		subject:   "sub-1",
		audience:  "nix-platform-api",
		expiresAt: time.Now().Add(-time.Hour), // already expired
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for expired token", rec.Code)
	}
}

func TestRequireAuthentication_WrongAudience(t *testing.T) {
	provider := newTestOIDCProvider(t)
	verifier := newTestVerifier(t, provider, "nix-platform-api", "nix-platform-api")
	handler := RequireAuthentication(verifier, slog.Default())(testHandlerEchoIdentity())

	token := provider.signToken(t, tokenOpts{
		subject:   "sub-1",
		audience:  "some-other-audience",
		expiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong audience", rec.Code)
	}
}

func TestRequireAuthentication_MalformedScheme(t *testing.T) {
	provider := newTestOIDCProvider(t)
	verifier := newTestVerifier(t, provider, "nix-platform-api", "nix-platform-api")
	handler := RequireAuthentication(verifier, slog.Default())(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for non-Bearer scheme", rec.Code)
	}
}

func TestRequireRole_ForbidsMissingRole(t *testing.T) {
	handler := RequireRole(slog.Default(), RoleAdmin)(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req = req.WithContext(WithIdentity(req.Context(), Identity{Subject: "sub-1", Roles: []string{RoleUser}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	handler := RequireRole(slog.Default(), RoleAdmin, RoleUser)(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req = req.WithContext(WithIdentity(req.Context(), Identity{Subject: "sub-1", Roles: []string{RoleUser}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequirePermission_ForbidsWithoutPermission(t *testing.T) {
	handler := RequirePermission(slog.Default(), PermUsersManage)(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req = req.WithContext(WithIdentity(req.Context(), Identity{Subject: "sub-1", Roles: []string{RoleUser}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequirePermission_RequiresAuthenticationFirst(t *testing.T) {
	handler := RequirePermission(slog.Default(), PermUsersRead)(testHandlerEchoIdentity())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when no identity in context", rec.Code)
	}
}
