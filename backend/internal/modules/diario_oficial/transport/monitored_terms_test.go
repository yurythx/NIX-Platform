// Testes das rotas de monitoramento (MVP de monitoramento real do Diário
// Oficial via DJEN) — mesmo padrão de handlers_test.go: rodam contra o
// Postgres real usado por todo este backend, pulando se
// TEST_DATABASE_URL não estiver definida.
package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestCreateMonitoredTerm_InvalidBody_Returns422(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: true}), testLogger())

	r := httptest.NewRequest(http.MethodPost, "/diario-oficial/monitored-terms", strings.NewReader(`{"label":"sem critério nenhum"}`))
	rec := httptest.NewRecorder()

	h.CreateMonitoredTerm(rec, r)

	if rec.Code < 400 || rec.Code >= 500 {
		t.Errorf("status = %d, want a 4xx (term with no search criteria should be rejected)", rec.Code)
	}
}

type monitoredTermDTO struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

func TestCreateAndListAndDeleteMonitoredTerm_FullLifecycle(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: true}), testLogger())

	createReq := httptest.NewRequest(http.MethodPost, "/diario-oficial/monitored-terms", strings.NewReader(
		`{"label":"Dr. Fulano — OAB/MG 419","oab_number":"419","oab_uf":"MG"}`,
	))
	createRec := httptest.NewRecorder()
	h.CreateMonitoredTerm(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body=%s", createRec.Code, createRec.Body.String())
	}
	created := decodeEnvelope[monitoredTermDTO](t, createRec.Body.Bytes())
	if created.Label != "Dr. Fulano — OAB/MG 419" {
		t.Errorf("Label = %q, want the label sent", created.Label)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/diario-oficial/monitored-terms", nil)
	listRec := httptest.NewRecorder()
	h.ListMonitoredTerms(listRec, listReq)
	terms := decodeEnvelope[[]monitoredTermDTO](t, listRec.Body.Bytes())
	found := false
	for _, term := range terms {
		if term.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Error("created term not found in ListMonitoredTerms")
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/diario-oficial/monitored-terms/"+created.ID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("termID", created.ID)
	deleteReq = deleteReq.WithContext(context.WithValue(deleteReq.Context(), chi.RouteCtxKey, rctx))
	deleteRec := httptest.NewRecorder()
	h.DeleteMonitoredTerm(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200 (envelope vazio, não 204 — apiClient.delete sempre decodifica JSON), body=%s", deleteRec.Code, deleteRec.Body.String())
	}

	deleteAgainRec := httptest.NewRecorder()
	h.DeleteMonitoredTerm(deleteAgainRec, deleteReq)
	if deleteAgainRec.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404 (already deleted)", deleteAgainRec.Code)
	}
}

func TestDeleteMonitoredTerm_InvalidID_Returns400(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: true}), testLogger())

	r := httptest.NewRequest(http.MethodDelete, "/diario-oficial/monitored-terms/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("termID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.DeleteMonitoredTerm(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestListPublicationsForTerm_UnknownTerm_ReturnsEmptyPage(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: true}), testLogger())

	unknown := uuid.New().String()
	r := httptest.NewRequest(http.MethodGet, "/diario-oficial/monitored-terms/"+unknown+"/publications", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("termID", unknown)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ListPublicationsForTerm(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an unknown term id is just an empty page, not a 404)", rec.Code)
	}
	items := decodeEnvelope[[]monitoredTermDTO](t, rec.Body.Bytes())
	if len(items) != 0 {
		t.Errorf("items = %d, want 0", len(items))
	}
}
