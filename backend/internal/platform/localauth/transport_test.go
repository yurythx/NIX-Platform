package localauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/config"
)

// fakeStore é uma implementação de Store inteiramente em memória, para
// testar o handler de login sem depender de um Postgres real. O bloqueio
// por tentativas é reproduzido aqui com a mesma lógica de
// PostgresStore.RegisterFailedAttempt, para que os testes cubram o
// comportamento real do handler.
type fakeStore struct {
	byUsername map[string]*Account
	touched    map[uuid.UUID]bool
}

func newFakeStore(accounts ...*Account) *fakeStore {
	s := &fakeStore{byUsername: map[string]*Account{}, touched: map[uuid.UUID]bool{}}
	for _, a := range accounts {
		s.byUsername[a.Username] = a
	}
	return s
}

func (s *fakeStore) GetByUsername(_ context.Context, username string) (*Account, error) {
	a, ok := s.byUsername[username]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	// Devolve uma cópia — o handler nunca deveria conseguir corromper o
	// estado do fake mutando o ponteiro devolvido fora de
	// RegisterFailedAttempt/ResetFailedAttempts.
	cp := *a
	return &cp, nil
}

func (s *fakeStore) TouchLastSeen(_ context.Context, id uuid.UUID) error {
	s.touched[id] = true
	return nil
}

func (s *fakeStore) RegisterFailedAttempt(_ context.Context, id uuid.UUID) error {
	for _, a := range s.byUsername {
		if a.ID != id {
			continue
		}
		a.FailedLoginAttempts++
		if a.FailedLoginAttempts >= maxFailedAttempts {
			until := time.Now().Add(lockoutDuration)
			a.LockedUntil = &until
		}
		return nil
	}
	return nil
}

func (s *fakeStore) ResetFailedAttempts(_ context.Context, id uuid.UUID) error {
	for _, a := range s.byUsername {
		if a.ID == id {
			a.FailedLoginAttempts = 0
			a.LockedUntil = nil
			return nil
		}
	}
	return nil
}

var _ Store = (*fakeStore)(nil)

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testSigner monta um *auth.LocalSigner de verdade (chave RSA gerada só
// para este teste) — os testes deste pacote exercitam o handler de ponta
// a ponta, então precisam de um signer funcional, não um dublê.
func testSigner(t *testing.T) *auth.LocalSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	cfg := config.LocalAuthConfig{
		Enabled:       true,
		PrivateKeyPEM: string(pem.EncodeToMemory(block)),
		TokenTTL:      time.Hour,
	}
	signer, err := auth.NewLocalSigner(cfg)
	if err != nil {
		t.Fatalf("auth.NewLocalSigner: %v", err)
	}
	return signer
}

func doLogin(h *Handlers, username, password string) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"username":"` + username + `","password":"` + password + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, r)
	return rec
}

func TestLogin_CorrectCredentialsIssuesToken(t *testing.T) {
	id := uuid.New()
	store := newFakeStore(&Account{
		ID: id, Username: "admin", Email: "admin@nix.local",
		PasswordHash: mustHash(t, "Admin123!"), Roles: []string{"nix-admin"}, Active: true,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (response carries a bearer token)", rec.Header().Get("Cache-Control"))
	}
	var resp struct {
		Data loginResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Data.AccessToken == "" {
		t.Error("expected a non-empty access_token")
	}
	if !store.touched[id] {
		t.Error("expected TouchLastSeen to have been called on successful login")
	}
}

func TestLogin_WrongPasswordIsRejected(t *testing.T) {
	store := newFakeStore(&Account{
		ID: uuid.New(), Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "admin", "wrong-password")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_UnknownUsernameIsRejectedWithSameStatusAsWrongPassword(t *testing.T) {
	store := newFakeStore()
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "nobody", "whatever")

	// Mesmo status e formato de erro do caso "senha errada" — não deve
	// dar para um atacante distinguir "usuário não existe" de "senha
	// incorreta" pela resposta.
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_InactiveAccountIsRejected(t *testing.T) {
	store := newFakeStore(&Account{
		ID: uuid.New(), Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: false,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_DisabledFeatureReturns404(t *testing.T) {
	store := newFakeStore(&Account{
		ID: uuid.New(), Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
	})
	h := NewHandlers(store, nil, nil, testLogger()) // signer nil == login local desligado

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when local auth is disabled", rec.Code)
	}
}

func TestLogin_MissingFieldsIsRejected(t *testing.T) {
	h := NewHandlers(newFakeStore(), testSigner(t), nil, testLogger())

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, r)

	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 422 or 400 for a missing required field", rec.Code)
	}
}

func TestLogin_AccountLocksAfterMaxFailedAttempts(t *testing.T) {
	id := uuid.New()
	store := newFakeStore(&Account{
		ID: id, Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	for i := 0; i < maxFailedAttempts; i++ {
		rec := doLogin(h, "admin", "wrong-password")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}

	// A conta agora está bloqueada — mesmo a senha CORRETA precisa ser
	// rejeitada até o bloqueio expirar.
	rec := doLogin(h, "admin", "Admin123!")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a locked account even with the correct password", rec.Code)
	}
}

func TestLogin_LockedAccountRejectsCorrectPassword(t *testing.T) {
	id := uuid.New()
	until := time.Now().Add(lockoutDuration)
	store := newFakeStore(&Account{
		ID: id, Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
		LockedUntil: &until,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an already-locked account", rec.Code)
	}
}

func TestLogin_SuccessResetsFailedAttempts(t *testing.T) {
	id := uuid.New()
	store := newFakeStore(&Account{
		ID: id, Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
		FailedLoginAttempts: maxFailedAttempts - 1,
	})
	h := NewHandlers(store, testSigner(t), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	if got := store.byUsername["admin"].FailedLoginAttempts; got != 0 {
		t.Errorf("FailedLoginAttempts after success = %d, want 0", got)
	}
}
