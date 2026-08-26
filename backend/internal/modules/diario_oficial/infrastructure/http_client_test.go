package infrastructure

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestHTTPClient_Search_NotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	client := NewHTTPClient("", time.Second, testLogger())

	_, err := client.Search(context.Background(), domain.SearchQuery{OABNumber: "419", OABState: "MG"})
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != "INTEGRATION_UNAVAILABLE" {
		t.Fatalf("err = %v, want an INTEGRATION_UNAVAILABLE apperrors.Error", err)
	}
}

// TestHTTPClient_Search_SendsExpectedQueryParamsAndParsesResponse fixa um
// servidor fake com o formato REAL de resposta do DJEN (capturado contra
// comunicaapi.pje.jus.br durante o desenvolvimento deste cliente, não
// inventado) — confirma tanto os parâmetros de query que Search monta
// quanto o parsing de volta pra domain.SearchResultItem.
func TestHTTPClient_Search_SendsExpectedQueryParamsAndParsesResponse(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status": "success",
			"message": "Sucesso",
			"count": 1,
			"items": [{
				"id": 667062426,
				"data_disponibilizacao": "2026-08-26",
				"siglaTribunal": "TJMG",
				"tipoComunicacao": "Intimação",
				"nomeOrgao": "TJMG - 1ª CÂMARA CRIMINAL",
				"texto": "publicação de teste",
				"numero_processo": "50015349420258130351",
				"link": "https://www4.tjmg.jus.br/example",
				"numeroprocessocommascara": "5001534-94.2025.8.13.0351"
			}]
		}`))
	}))
	defer srv.Close()

	client := &HTTPClient{baseURL: srv.URL, client: srv.Client(), breaker: NewHTTPClient(srv.URL, time.Second, testLogger()).breaker}
	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	result, err := client.Search(context.Background(), domain.SearchQuery{
		OABNumber: "419", OABState: "MG", Since: &since, Page: 2, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if got := gotQuery.Get("numeroOab"); got != "419" {
		t.Errorf("numeroOab = %q, want 419", got)
	}
	if got := gotQuery.Get("ufOab"); got != "MG" {
		t.Errorf("ufOab = %q, want MG", got)
	}
	if got := gotQuery.Get("dataDisponibilizacaoInicio"); got != "2026-08-01" {
		t.Errorf("dataDisponibilizacaoInicio = %q, want 2026-08-01", got)
	}
	if got := gotQuery.Get("pagina"); got != "2" {
		t.Errorf("pagina = %q, want 2", got)
	}
	if got := gotQuery.Get("itensPorPagina"); got != "10" {
		t.Errorf("itensPorPagina = %q, want 10", got)
	}

	if result.TotalCount != 1 {
		t.Errorf("TotalCount = %d, want 1", result.TotalCount)
	}
	if len(result.Items) != 1 {
		t.Fatalf("Items = %d, want 1", len(result.Items))
	}
	item := result.Items[0]
	if item.ExternalID != 667062426 {
		t.Errorf("ExternalID = %d, want 667062426", item.ExternalID)
	}
	if item.Tribunal != "TJMG" {
		t.Errorf("Tribunal = %q, want TJMG", item.Tribunal)
	}
	if item.ProcessNumberMasked != "5001534-94.2025.8.13.0351" {
		t.Errorf("ProcessNumberMasked = %q, want 5001534-94.2025.8.13.0351", item.ProcessNumberMasked)
	}
	wantDate := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	if !item.AvailabilityDate.Equal(wantDate) {
		t.Errorf("AvailabilityDate = %v, want %v", item.AvailabilityDate, wantDate)
	}
	var raw map[string]any
	if err := json.Unmarshal(item.RawPayload, &raw); err != nil {
		t.Fatalf("RawPayload is not valid JSON: %v", err)
	}
	if raw["id"].(float64) != 667062426 {
		t.Errorf("RawPayload[id] = %v, want 667062426 (payload bruto deve ser preservado sem perda)", raw["id"])
	}
}

func TestHTTPClient_Search_MalformedItem_SkipsItButKeepsTheRest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status": "success", "message": "Sucesso", "count": 2,
			"items": [
				{"id": 1, "data_disponibilizacao": "not-a-date", "siglaTribunal": "TJMG"},
				{"id": 2, "data_disponibilizacao": "2026-08-26", "siglaTribunal": "TJSP"}
			]
		}`))
	}))
	defer srv.Close()

	client := &HTTPClient{baseURL: srv.URL, client: srv.Client(), breaker: NewHTTPClient(srv.URL, time.Second, testLogger()).breaker}
	result, err := client.Search(context.Background(), domain.SearchQuery{FreeText: "teste"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("Items = %d, want 1 (item com data inválida deve ser pulado, não derrubar a página inteira)", len(result.Items))
	}
	if result.Items[0].ExternalID != 2 {
		t.Errorf("ExternalID = %d, want 2", result.Items[0].ExternalID)
	}
}
