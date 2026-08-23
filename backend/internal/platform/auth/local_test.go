package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// testRSAKeyPEM generates a throwaway RSA private key (PKCS1 PEM) of the
// given bit size for use in a single test — never reused across tests, so
// no test accidentally depends on another's key material.
func testRSAKeyPEM(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block))
}

func testSigner(t *testing.T, ttl time.Duration) *LocalSigner {
	t.Helper()
	cfg := config.LocalAuthConfig{Enabled: true, PrivateKeyPEM: testRSAKeyPEM(t, 2048), TokenTTL: ttl}
	signer, err := NewLocalSigner(cfg)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return signer
}

func TestIssueToken_ThenVerifyToken_RoundTrips(t *testing.T) {
	signer := testSigner(t, time.Hour)
	account := LocalAccount{ID: "user-1", Username: "admin", Email: "admin@nix.local", Roles: []string{"nix-admin", "nix-user"}}

	token, expiresAt, err := signer.IssueToken(account)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("expiresAt = %v, want in the future", expiresAt)
	}

	identity, err := signer.verifyToken(token)
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	if identity.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", identity.Subject)
	}
	if identity.Username != "admin" {
		t.Errorf("Username = %q, want admin", identity.Username)
	}
	if identity.Source != SourceLocal {
		t.Errorf("Source = %q, want %q", identity.Source, SourceLocal)
	}
	if !identity.HasRole("nix-admin") || !identity.HasRole("nix-user") {
		t.Errorf("Roles = %v, want to include nix-admin and nix-user", identity.Roles)
	}
}

func TestVerifyToken_WrongKeyIsRejected(t *testing.T) {
	signerA := testSigner(t, time.Hour)
	signerB := testSigner(t, time.Hour)

	token, _, err := signerA.IssueToken(LocalAccount{ID: "user-1", Username: "admin"})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// signerB tem uma chave RSA completamente diferente — precisa rejeitar
	// um token assinado por signerA, exatamente como rejeitaria um token
	// de verdade do Keycloak (chave RSA de outra origem qualquer).
	if _, err := signerB.verifyToken(token); err == nil {
		t.Fatal("expected verification to fail with a different key pair")
	}
}

func TestVerifyToken_ExpiredTokenIsRejected(t *testing.T) {
	signer := testSigner(t, -time.Hour) // já expirado
	token, _, err := signer.IssueToken(LocalAccount{ID: "user-1", Username: "admin"})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	if _, err := signer.verifyToken(token); err == nil {
		t.Fatal("expected verification to reject an expired token")
	}
}

func TestNewLocalSigner_DisabledReturnsNilWithoutError(t *testing.T) {
	signer, err := NewLocalSigner(config.LocalAuthConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewLocalSigner: unexpected error %v", err)
	}
	if signer != nil {
		t.Fatal("expected a nil signer when local auth is disabled")
	}
}

func TestNewLocalSigner_RejectsKeySmallerThanMinimum(t *testing.T) {
	_, err := NewLocalSigner(config.LocalAuthConfig{Enabled: true, PrivateKeyPEM: testRSAKeyPEM(t, 1024)})
	if err == nil {
		t.Fatal("expected an error for a key smaller than the minimum size")
	}
}

func TestNewLocalSigner_RejectsInvalidPEM(t *testing.T) {
	_, err := NewLocalSigner(config.LocalAuthConfig{Enabled: true, PrivateKeyPEM: "not a pem"})
	if err == nil {
		t.Fatal("expected an error for an invalid PEM value")
	}
}
