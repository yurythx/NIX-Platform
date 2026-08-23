package localauth

import (
	"context"
	"encoding/json"
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

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// fakeStore é uma implementação de Store inteiramente em memória, para
// testar o handler de login sem depender de um Postgres real.
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
	return a, nil
}

func (s *fakeStore) TouchLastSeen(_ context.Context, id uuid.UUID) error {
	s.touched[id] = true
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

func testCfg() config.LocalAuthConfig {
	return config.LocalAuthConfig{Enabled: true, JWTSecret: "test-secret-at-least-32-bytes-long", TokenTTL: time.Hour}
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
	h := NewHandlers(store, testCfg(), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
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
	h := NewHandlers(store, testCfg(), nil, testLogger())

	rec := doLogin(h, "admin", "wrong-password")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_UnknownUsernameIsRejectedWithSameStatusAsWrongPassword(t *testing.T) {
	store := newFakeStore()
	h := NewHandlers(store, testCfg(), nil, testLogger())

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
	h := NewHandlers(store, testCfg(), nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_DisabledFeatureReturns404(t *testing.T) {
	store := newFakeStore(&Account{
		ID: uuid.New(), Username: "admin", PasswordHash: mustHash(t, "Admin123!"), Active: true,
	})
	cfg := testCfg()
	cfg.Enabled = false
	h := NewHandlers(store, cfg, nil, testLogger())

	rec := doLogin(h, "admin", "Admin123!")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when local auth is disabled", rec.Code)
	}
}

func TestLogin_MissingFieldsIsRejected(t *testing.T) {
	h := NewHandlers(newFakeStore(), testCfg(), nil, testLogger())

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, r)

	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 422 or 400 for a missing required field", rec.Code)
	}
}
