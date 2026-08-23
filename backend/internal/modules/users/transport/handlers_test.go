package transport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/users/application"
	"github.com/yurythx/nix-platform/internal/modules/users/domain"
	"github.com/yurythx/nix-platform/internal/platform/auth"
)

// fakeRepository é um domain.Repository inteiramente em memória — a
// mesma ideia do fakeRepository já usado em application/service_test.go,
// reconstruído aqui (não exportado do outro pacote) para acionar os
// handlers de ponta a ponta: HTTP -> application.Service real -> este
// fake, sem tocar em Postgres. Nenhum módulo de transporte tinha teste
// próprio antes desta auditoria — só a camada application era testada.
type fakeRepository struct {
	byID map[uuid.UUID]*domain.User
}

func newFakeRepository(users ...*domain.User) *fakeRepository {
	f := &fakeRepository{byID: map[uuid.UUID]*domain.User{}}
	for _, u := range users {
		f.byID[u.ID] = u
	}
	return f
}

func (f *fakeRepository) UpsertByKeycloakSubject(_ context.Context, u *domain.User) (domain.UpsertResult, error) {
	for _, existing := range f.byID {
		if existing.KeycloakSubject != nil && u.KeycloakSubject != nil && *existing.KeycloakSubject == *u.KeycloakSubject {
			existing.Username = u.Username
			existing.Email = u.Email
			return domain.UpsertResult{User: existing, Created: false}, nil
		}
	}
	u.ID = uuid.New()
	f.byID[u.ID] = u
	return domain.UpsertResult{User: u, Created: true}, nil
}

func (f *fakeRepository) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, apperrors.NotFound("user not found")
	}
	return u, nil
}

func (f *fakeRepository) List(_ context.Context, p pagination.Params) ([]*domain.User, int64, error) {
	var out []*domain.User
	for _, u := range f.byID {
		out = append(out, u)
	}
	return out, int64(len(out)), nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func decodeEnvelope[T any](t *testing.T, body []byte) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response envelope: %v, body=%s", err, body)
	}
	return env.Data
}

func TestGetCurrentUser_KeycloakIdentitySyncsViaUpsert(t *testing.T) {
	repo := newFakeRepository()
	h := NewHandlers(application.NewService(repo, nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r = r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{
		Subject: "keycloak-sub-1", Username: "jdoe", Email: "jdoe@example.com", Source: auth.SourceKeycloak,
	}))
	rec := httptest.NewRecorder()

	h.GetCurrentUser(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[UserResponse](t, rec.Body.Bytes())
	if got.Username != "jdoe" {
		t.Errorf("Username = %q, want jdoe", got.Username)
	}
	if len(repo.byID) != 1 {
		t.Errorf("expected the Keycloak identity to have been upserted into the repository, got %d rows", len(repo.byID))
	}
}

func TestGetCurrentUser_LocalIdentityFetchesDirectlyWithoutUpsert(t *testing.T) {
	existing := &domain.User{ID: uuid.New(), Username: "admin", Email: "admin@nix.local", Active: true}
	repo := newFakeRepository(existing)
	h := NewHandlers(application.NewService(repo, nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	// identity.Subject é o próprio id da linha em "users" para uma conta
	// local (ver localauth.Handlers.Login) — nunca um "sub" de Keycloak.
	r = r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{
		Subject: existing.ID.String(), Username: "admin", Source: auth.SourceLocal,
	}))
	rec := httptest.NewRecorder()

	h.GetCurrentUser(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[UserResponse](t, rec.Body.Bytes())
	if got.ID != existing.ID.String() {
		t.Errorf("ID = %q, want %q", got.ID, existing.ID.String())
	}
	// O ponto central deste teste: uma identidade local nunca deve passar
	// pelo caminho de upsert-por-keycloak_subject (criaria uma segunda
	// linha duplicada) — ver o comentário do handler.
	if len(repo.byID) != 1 {
		t.Errorf("expected no new row to have been created for a local identity, got %d rows", len(repo.byID))
	}
}

func TestGetCurrentUser_RequiresAuthentication(t *testing.T) {
	h := NewHandlers(application.NewService(newFakeRepository(), nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/me", nil) // sem identidade no contexto
	rec := httptest.NewRecorder()

	h.GetCurrentUser(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestListUsers_ReturnsPaginatedResults(t *testing.T) {
	repo := newFakeRepository(
		&domain.User{ID: uuid.New(), Username: "alice", Active: true},
		&domain.User{ID: uuid.New(), Username: "bob", Active: true},
	)
	h := NewHandlers(application.NewService(repo, nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/users?page=1&page_size=10", nil)
	rec := httptest.NewRecorder()

	h.ListUsers(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[[]UserResponse](t, rec.Body.Bytes())
	if len(got) != 2 {
		t.Errorf("got %d users, want 2", len(got))
	}
}

func TestGetUser_ReturnsTheRequestedUser(t *testing.T) {
	existing := &domain.User{ID: uuid.New(), Username: "carol", Active: true, CreatedAt: time.Now()}
	repo := newFakeRepository(existing)
	h := NewHandlers(application.NewService(repo, nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/users/"+existing.ID.String(), nil)
	r = withChiURLParam(r, "id", existing.ID.String())
	rec := httptest.NewRecorder()

	h.GetUser(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[UserResponse](t, rec.Body.Bytes())
	if got.Username != "carol" {
		t.Errorf("Username = %q, want carol", got.Username)
	}
}

func TestGetUser_UnknownIDReturns404(t *testing.T) {
	h := NewHandlers(application.NewService(newFakeRepository(), nil), testLogger(), 50)

	missing := uuid.New()
	r := httptest.NewRequest(http.MethodGet, "/users/"+missing.String(), nil)
	r = withChiURLParam(r, "id", missing.String())
	rec := httptest.NewRecorder()

	h.GetUser(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestGetUser_MalformedIDReturns400(t *testing.T) {
	h := NewHandlers(application.NewService(newFakeRepository(), nil), testLogger(), 50)

	r := httptest.NewRequest(http.MethodGet, "/users/not-a-uuid", nil)
	r = withChiURLParam(r, "id", "not-a-uuid")
	rec := httptest.NewRecorder()

	h.GetUser(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// withChiURLParam simula o que o router chi normalmente faz ao casar
// /users/{id} — grava o valor no RouteContext que chi.URLParam lê. O
// idioma padrão de teste do chi para exercitar um handler sem subir o
// router inteiro.
func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
