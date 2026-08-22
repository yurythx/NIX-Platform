package idempotency

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/yurythx/nix-platform/internal/platform/auth"
)

// fakeStore é uma implementação de Store inteiramente em memória, para
// testar o middleware sem depender de um Postgres real — o middleware só
// enxerga a interface Store, então uma implementação falsa (fake) exercita
// exatamente a mesma lógica de decisão (replay/conflito/reuso) que o
// PostgresStore exercitaria, só que sem infraestrutura.
type fakeStore struct {
	mu      sync.Mutex
	records map[string]*Record
}

func newFakeStore() *fakeStore {
	return &fakeStore{records: map[string]*Record{}}
}

func (s *fakeStore) Claim(_ context.Context, key, requestHash string) (*Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.records[key]
	if !ok {
		s.records[key] = &Record{Key: key, RequestHash: requestHash, Status: StatusProcessing}
		return nil, true, nil
	}
	if existing.Status == StatusFailed && existing.RequestHash == requestHash {
		existing.Status = StatusProcessing
		existing.ResponseStatus = 0
		existing.ResponseBody = nil
		existing.ContentType = ""
		return nil, true, nil
	}
	cp := *existing
	return &cp, false, nil
}

func (s *fakeStore) Complete(_ context.Context, key string, status int, body []byte, contentType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[key]
	rec.Status = StatusCompleted
	rec.ResponseStatus = status
	rec.ResponseBody = body
	rec.ContentType = contentType
	return nil
}

func (s *fakeStore) Fail(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key].Status = StatusFailed
	return nil
}

var _ Store = (*fakeStore)(nil)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// withIdentity simula o que auth.RequireAuthentication faz normalmente —
// este middleware roda depois dele na cadeia real, então os testes
// precisam da mesma pré-condição.
func withIdentity(r *http.Request, subject string) *http.Request {
	ctx := auth.WithIdentity(r.Context(), auth.Identity{Subject: subject})
	return r.WithContext(ctx)
}

func countingHandler(calls *int, status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func TestMiddleware_NoHeaderPassesThrough(t *testing.T) {
	store := newFakeStore()
	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusOK, `{"ok":true}`))

	req := withIdentity(httptest.NewRequest(http.MethodPost, "/api/v1/x", nil), "user-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if calls != 1 {
		t.Fatalf("handler chamado %d vezes, want 1 (sem header, deve passar direto)", calls)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMiddleware_SecondRequestReplaysStoredResponse(t *testing.T) {
	store := newFakeStore()
	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusAccepted, `{"job_id":"1"}`))

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/diario-oficial/test", strings.NewReader(`{}`))
		r.Header.Set(Header, "same-key")
		return withIdentity(r, "user-1")
	}

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, newReq())
	if rec1.Code != http.StatusAccepted || rec1.Body.String() != `{"job_id":"1"}` {
		t.Fatalf("primeira chamada: status=%d body=%q", rec1.Code, rec1.Body.String())
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, newReq())

	if calls != 1 {
		t.Fatalf("handler chamado %d vezes, want 1 (a segunda chamada deve ser um replay, não reexecutar)", calls)
	}
	if rec2.Code != http.StatusAccepted {
		t.Errorf("status do replay = %d, want 202 (o mesmo da resposta original)", rec2.Code)
	}
	if rec2.Body.String() != `{"job_id":"1"}` {
		t.Errorf("body do replay = %q, want %q", rec2.Body.String(), `{"job_id":"1"}`)
	}
	if rec2.Header().Get("Idempotent-Replay") != "true" {
		t.Error("esperava o header Idempotent-Replay: true na resposta reproduzida")
	}
}

func TestMiddleware_ConcurrentRequestWhileProcessingGets409(t *testing.T) {
	store := newFakeStore()
	key := "user-1:concurrent-key"

	// Simula a primeira requisição já ter reivindicado a chave e ainda
	// estar "em processamento" (o handler dela nunca terminou).
	if _, claimed, err := store.Claim(context.Background(), key, hashRequest(http.MethodPost, "/api/v1/x", []byte("{}"))); err != nil || !claimed {
		t.Fatalf("setup Claim: claimed=%v err=%v", claimed, err)
	}

	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusOK, `{}`))

	r := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(`{}`))
	r.Header.Set(Header, "concurrent-key")
	r = withIdentity(r, "user-1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if calls != 0 {
		t.Fatalf("handler não deveria ter sido chamado enquanto a chave está 'processing', foi chamado %d vez(es)", calls)
	}
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestMiddleware_SameKeyDifferentPayloadIsRejected(t *testing.T) {
	store := newFakeStore()
	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusAccepted, `{"job_id":"1"}`))

	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(`{"a":1}`))
	r1.Header.Set(Header, "reused-key")
	handler.ServeHTTP(httptest.NewRecorder(), withIdentity(r1, "user-1"))

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(`{"a":2}`))
	r2.Header.Set(Header, "reused-key")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, withIdentity(r2, "user-1"))

	if calls != 1 {
		t.Fatalf("handler chamado %d vezes, want 1 (a segunda requisição tem payload diferente e deve ser rejeitada, não reprocessada nem reproduzida)", calls)
	}
	if rec2.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (reuso de chave com payload diferente)", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "IDEMPOTENCY_KEY_REUSED") {
		t.Errorf("body = %q, want conter o código IDEMPOTENCY_KEY_REUSED", rec2.Body.String())
	}
}

func TestMiddleware_DifferentUsersWithSameKeyDoNotCollide(t *testing.T) {
	store := newFakeStore()
	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusAccepted, `{"job_id":"1"}`))

	for _, user := range []string{"user-1", "user-2"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(`{}`))
		r.Header.Set(Header, "same-literal-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, withIdentity(r, user))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("usuário %s: status = %d, want 202", user, rec.Code)
		}
	}

	if calls != 2 {
		t.Fatalf("handler chamado %d vezes, want 2 — usuários diferentes com o mesmo valor de Idempotency-Key não podem colidir", calls)
	}
}

func TestMiddleware_ServerErrorReleasesKeyForRetry(t *testing.T) {
	store := newFakeStore()
	calls := 0
	handler := Middleware(store, testLogger())(countingHandler(&calls, http.StatusInternalServerError, `{"error":"boom"}`))

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(`{}`))
		r.Header.Set(Header, "retry-key")
		return withIdentity(r, "user-1")
	}

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, newReq())
	if rec1.Code != http.StatusInternalServerError {
		t.Fatalf("primeira chamada: status = %d, want 500", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, newReq())

	if calls != 2 {
		t.Fatalf("handler chamado %d vezes, want 2 — um 500 deve liberar a chave para uma nova tentativa completa", calls)
	}
	if rec2.Code != http.StatusInternalServerError {
		t.Errorf("segunda chamada: status = %d, want 500 (reexecutou de verdade, não foi um replay)", rec2.Code)
	}
}
