// Testes de Health (handlers.go). Diferente do resto deste pacote,
// CheckHealth não toca banco nenhum — mas newTestServiceWithClient ainda
// constrói o Service inteiro (incluindo o repositório sobre pool), então
// este teste segue o mesmo padrão de pular sem TEST_DATABASE_URL que todo
// outro teste deste pacote já segue, por uma limitação de infraestrutura
// de teste, não porque o handler em si precise de banco.
package transport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
)

type sourceHealthResponseDTO struct {
	Source  string `json:"source"`
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

func TestHealth_ReportsHealthyWhenClientSucceeds(t *testing.T) {
	pool := testPool(t)
	svc := newTestServiceWithClient(pool, &fakeClient{result: &domain.CheckResult{StatusCode: 200, Summary: "ok"}})
	h := NewHandlers(svc, testLogger())

	r := httptest.NewRequest(http.MethodGet, "/diario-oficial/health", nil)
	rec := httptest.NewRecorder()
	h.Health(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[sourceHealthResponseDTO](t, rec.Body.Bytes())
	if !got.Healthy || got.Source != "djen" {
		t.Errorf("got %+v, want healthy=true source=djen", got)
	}
}

func TestHealth_ReportsUnhealthyWhenClientFails(t *testing.T) {
	pool := testPool(t)
	svc := newTestServiceWithClient(pool, &fakeClient{err: errors.New("connection refused")})
	h := NewHandlers(svc, testLogger())

	r := httptest.NewRequest(http.MethodGet, "/diario-oficial/health", nil)
	rec := httptest.NewRecorder()
	h.Health(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a fonte fora do ar não é erro HTTP, é um dado do payload), body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[sourceHealthResponseDTO](t, rec.Body.Bytes())
	if got.Healthy {
		t.Error("Healthy = true, want false")
	}
}
