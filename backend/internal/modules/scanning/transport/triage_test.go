// Testes dos handlers TriageFinding/UntriageFinding (Fase 14 —
// Maturidade de AppSec) — nenhum existia até esta revisão, apesar dos
// handlers em si datarem da primeira rodada da Fase 14; a lógica de
// negócio já era coberta em application/triage_test.go, mas a camada
// HTTP (decode do corpo, extração de projectID/fingerprint da URL,
// status code) nunca tinha teste próprio.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

func newTriageTestHandlers(t *testing.T) (*Handlers, string) {
	t.Helper()
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newTestService(pool).WithTriageRepository(repo)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)

	project, err := svc.CreateProjectGit(context.Background(), "test-project-triage-handler", "https://example.com/repo-triage-handler.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}
	return h, project.ID.String()
}

func triageRequest(t *testing.T, projectID, fingerprint string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/scanning/projects/"+projectID+"/findings/"+fingerprint+"/triage", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectID", projectID)
	rctx.URLParams.Add("fingerprint", fingerprint)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestTriageFindingHandler_ValidRequest_Returns200(t *testing.T) {
	h, projectID := newTriageTestHandlers(t)

	body, _ := json.Marshal(map[string]string{"status": "risk_accepted", "reason": "mitigado por WAF"})
	rec := httptest.NewRecorder()
	h.TriageFinding(rec, triageRequest(t, projectID, "fp-handler-1", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestTriageFindingHandler_EmptyReason_Returns400(t *testing.T) {
	h, projectID := newTriageTestHandlers(t)

	body, _ := json.Marshal(map[string]string{"status": "risk_accepted", "reason": ""})
	rec := httptest.NewRecorder()
	h.TriageFinding(rec, triageRequest(t, projectID, "fp-handler-2", body))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (reason is required)", rec.Code)
	}
}

func TestTriageFindingHandler_ExpiresAtInThePast_Returns400(t *testing.T) {
	h, projectID := newTriageTestHandlers(t)

	past := time.Now().Add(-time.Hour)
	body, _ := json.Marshal(map[string]any{"status": "wont_fix", "reason": "motivo válido", "expires_at": past})
	rec := httptest.NewRecorder()
	h.TriageFinding(rec, triageRequest(t, projectID, "fp-handler-3", body))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (expires_at in the past)", rec.Code)
	}
}

func TestTriageFindingHandler_ExpiresAtInTheFuture_RoundTripsThroughHistory(t *testing.T) {
	h, projectID := newTriageTestHandlers(t)

	future := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	body, _ := json.Marshal(map[string]any{"status": "risk_accepted", "reason": "motivo válido", "expires_at": future})
	rec := httptest.NewRecorder()
	h.TriageFinding(rec, triageRequest(t, projectID, "fp-handler-4", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	histReq := httptest.NewRequest(http.MethodGet, "/scanning/projects/"+projectID+"/findings-history", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectID", projectID)
	histReq = histReq.WithContext(context.WithValue(histReq.Context(), chi.RouteCtxKey, rctx))
	histRec := httptest.NewRecorder()
	h.ListProjectFindingsHistory(histRec, histReq)

	// fp-handler-4 nunca apareceu em nenhum scan de verdade (só foi
	// triado direto), então não aparece em ListProjectFindingsHistory
	// (que só lista fingerprints vistos em scan_findings) — este teste
	// só confirma que a REQUISIÇÃO de triagem com expires_at no futuro é
	// aceita e não quebra nada a jusante; o round-trip completo
	// (TriageStatus/TriageExpiresAt aparecendo na history de um achado
	// real) já é coberto por application.TestTriageFinding_AppearsInProjectFindingHistory.
	if histRec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body=%s", histRec.Code, histRec.Body.String())
	}
}

func TestUntriageFindingHandler_Returns200(t *testing.T) {
	h, projectID := newTriageTestHandlers(t)

	body, _ := json.Marshal(map[string]string{"status": "false_positive", "reason": "motivo"})
	triageRec := httptest.NewRecorder()
	h.TriageFinding(triageRec, triageRequest(t, projectID, "fp-handler-5", body))
	if triageRec.Code != http.StatusOK {
		t.Fatalf("setup TriageFinding: status = %d, body=%s", triageRec.Code, triageRec.Body.String())
	}

	r := httptest.NewRequest(http.MethodDelete, "/scanning/projects/"+projectID+"/findings/fp-handler-5/triage", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectID", projectID)
	rctx.URLParams.Add("fingerprint", "fp-handler-5")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.UntriageFinding(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}
