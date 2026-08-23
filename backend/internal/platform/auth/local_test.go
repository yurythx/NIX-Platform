package auth

import (
	"testing"
	"time"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

func TestIssueLocalToken_ThenVerifyLocalToken_RoundTrips(t *testing.T) {
	cfg := config.LocalAuthConfig{JWTSecret: "test-secret-at-least-32-bytes-long", TokenTTL: time.Hour}
	account := LocalAccount{ID: "user-1", Username: "admin", Email: "admin@nix.local", Roles: []string{"nix-admin", "nix-user"}}

	token, expiresAt, err := IssueLocalToken(cfg, account)
	if err != nil {
		t.Fatalf("IssueLocalToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("expiresAt = %v, want in the future", expiresAt)
	}

	identity, err := verifyLocalToken(cfg.JWTSecret, token)
	if err != nil {
		t.Fatalf("verifyLocalToken: %v", err)
	}
	if identity.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", identity.Subject)
	}
	if identity.Username != "admin" {
		t.Errorf("Username = %q, want admin", identity.Username)
	}
	if !identity.HasRole("nix-admin") || !identity.HasRole("nix-user") {
		t.Errorf("Roles = %v, want to include nix-admin and nix-user", identity.Roles)
	}
}

func TestVerifyLocalToken_WrongSecretIsRejected(t *testing.T) {
	cfg := config.LocalAuthConfig{JWTSecret: "correct-secret-at-least-32-bytes", TokenTTL: time.Hour}
	token, _, err := IssueLocalToken(cfg, LocalAccount{ID: "user-1", Username: "admin"})
	if err != nil {
		t.Fatalf("IssueLocalToken: %v", err)
	}

	if _, err := verifyLocalToken("a-completely-different-secret-value", token); err == nil {
		t.Fatal("expected verification to fail with a different secret")
	}
}

func TestVerifyLocalToken_ExpiredTokenIsRejected(t *testing.T) {
	cfg := config.LocalAuthConfig{JWTSecret: "test-secret-at-least-32-bytes-long", TokenTTL: -time.Hour} // já expirado
	token, _, err := IssueLocalToken(cfg, LocalAccount{ID: "user-1", Username: "admin"})
	if err != nil {
		t.Fatalf("IssueLocalToken: %v", err)
	}

	if _, err := verifyLocalToken(cfg.JWTSecret, token); err == nil {
		t.Fatal("expected verification to reject an expired token")
	}
}

func TestIssueLocalToken_RequiresConfiguredSecret(t *testing.T) {
	_, _, err := IssueLocalToken(config.LocalAuthConfig{}, LocalAccount{ID: "user-1"})
	if err == nil {
		t.Fatal("expected an error when LOCAL_AUTH_JWT_SECRET is not configured")
	}
}
