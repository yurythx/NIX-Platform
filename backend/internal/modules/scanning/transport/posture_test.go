// Testes dos handlers SecurityPosture/PostureHistory (Fase 14 —
// Maturidade de AppSec, e sua continuação — tendência histórica).
package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

func TestSecurityPosture_Returns200WithEnvelope(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger(), testSonarQubePublicURL)

	r := httptest.NewRequest(http.MethodGet, "/scanning/posture", nil)
	rec := httptest.NewRecorder()

	h.SecurityPosture(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data struct {
			OpenCritical int `json:"open_critical"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
}

func TestPostureHistory_WithoutPostureRepositoryConfigured_Returns500(t *testing.T) {
	pool := testPool(t)
	// newTestService não chama WithPostureRepository — mesmo estado
	// "opcional, não configurado" que o resto do módulo já tolera.
	h := NewHandlers(newTestService(pool), testLogger(), testSonarQubePublicURL)

	r := httptest.NewRequest(http.MethodGet, "/scanning/posture/history", nil)
	rec := httptest.NewRecorder()

	h.PostureHistory(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (postureRepo not configured)", rec.Code)
	}
}

func TestPostureHistory_WithPostureRepositoryConfigured_IncludesTodaysSnapshot(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newTestService(pool).WithPostureRepository(repo)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)

	if err := svc.SnapshotSecurityPosture(context.Background()); err != nil {
		t.Fatalf("SnapshotSecurityPosture: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/scanning/posture/history?days=30", nil)
	rec := httptest.NewRecorder()

	h.PostureHistory(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []struct {
			Date string `json:"date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
	if len(env.Data) == 0 {
		t.Fatal("expected at least one snapshot in the response")
	}
}
