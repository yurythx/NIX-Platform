package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/integrations/application"
	"github.com/yurythx/nix-platform/internal/modules/integrations/domain"
)

// fakeRepository é um domain.Repository em memória — este módulo nunca
// teve nenhum teste (nem de application, nem de transport) antes desta
// auditoria; UpdateStatusTx não é exercitado por nenhum dos dois handlers
// HTTP testados aqui (só o worker de diario_oficial chama
// RecordCheckResult), então fica deliberadamente sem implementação real.
type fakeRepository struct {
	byID map[uuid.UUID]*domain.Integration
}

func newFakeRepository(items ...*domain.Integration) *fakeRepository {
	f := &fakeRepository{byID: map[uuid.UUID]*domain.Integration{}}
	for _, i := range items {
		f.byID[i.ID] = i
	}
	return f
}

func (f *fakeRepository) List(_ context.Context) ([]*domain.Integration, error) {
	var out []*domain.Integration
	for _, i := range f.byID {
		out = append(out, i)
	}
	return out, nil
}

func (f *fakeRepository) GetByID(_ context.Context, id uuid.UUID) (*domain.Integration, error) {
	i, ok := f.byID[id]
	if !ok {
		return nil, apperrors.NotFound("integration not found")
	}
	return i, nil
}

func (f *fakeRepository) GetByKey(_ context.Context, key string) (*domain.Integration, error) {
	for _, i := range f.byID {
		if i.Key == key {
			return i, nil
		}
	}
	return nil, apperrors.NotFound("integration not found")
}

func (f *fakeRepository) UpdateStatusTx(_ context.Context, _ pgx.Tx, _ string, _ bool, _ *string) (*domain.Integration, bool, error) {
	return nil, false, fmt.Errorf("fakeRepository: UpdateStatusTx not implemented (unused by the handlers under test)")
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

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestListIntegrations_ReturnsAllConfigured(t *testing.T) {
	repo := newFakeRepository(
		&domain.Integration{ID: uuid.New(), Key: "diario-oficial", Name: "Diário Oficial", Status: domain.StatusOnline},
		&domain.Integration{ID: uuid.New(), Key: "example-provider", Name: "Example Provider", Status: domain.StatusOffline},
	)
	h := NewHandlers(application.NewService(repo), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/integrations", nil)
	rec := httptest.NewRecorder()

	h.ListIntegrations(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[[]IntegrationResponse](t, rec.Body.Bytes())
	if len(got) != 2 {
		t.Errorf("got %d integrations, want 2", len(got))
	}
}

func TestGetIntegrationStatus_ReturnsTheRequestedIntegration(t *testing.T) {
	existing := &domain.Integration{ID: uuid.New(), Key: "diario-oficial", Name: "Diário Oficial", Status: domain.StatusDegraded}
	repo := newFakeRepository(existing)
	h := NewHandlers(application.NewService(repo), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/integrations/"+existing.ID.String()+"/status", nil)
	r = withChiURLParam(r, "id", existing.ID.String())
	rec := httptest.NewRecorder()

	h.GetIntegrationStatus(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[IntegrationResponse](t, rec.Body.Bytes())
	if got.Status != string(domain.StatusDegraded) {
		t.Errorf("Status = %q, want %q", got.Status, domain.StatusDegraded)
	}
}

func TestGetIntegrationStatus_UnknownIDReturns404(t *testing.T) {
	h := NewHandlers(application.NewService(newFakeRepository()), testLogger())

	missing := uuid.New()
	r := httptest.NewRequest(http.MethodGet, "/integrations/"+missing.String()+"/status", nil)
	r = withChiURLParam(r, "id", missing.String())
	rec := httptest.NewRecorder()

	h.GetIntegrationStatus(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestGetIntegrationStatus_MalformedIDReturns400(t *testing.T) {
	h := NewHandlers(application.NewService(newFakeRepository()), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/integrations/not-a-uuid/status", nil)
	r = withChiURLParam(r, "id", "not-a-uuid")
	rec := httptest.NewRecorder()

	h.GetIntegrationStatus(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
