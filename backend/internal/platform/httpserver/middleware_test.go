package httpserver

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yurythx/nix-platform/internal/platform/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var captured string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = logging.RequestID(r.Context())
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == "" {
		t.Error("expected a generated request id in context")
	}
	if rec.Header().Get(RequestIDHeader) != captured {
		t.Error("expected the response header to echo the generated request id")
	}
}

func TestRequestID_HonorsInboundHeader(t *testing.T) {
	var captured string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = logging.RequestID(r.Context())
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(RequestIDHeader, "client-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured != "client-supplied-id" {
		t.Errorf("captured = %q, want client-supplied-id", captured)
	}
	if rec.Header().Get(RequestIDHeader) != "client-supplied-id" {
		t.Error("expected the response header to echo the client-supplied id")
	}
}

// Achado real desta revisão: logging.WithCorrelationID nunca era chamado
// em lugar nenhum do código — o campo correlation_id nunca aparecia em
// nenhum log passando por logging.FromContext (a própria linha de acesso
// HTTP incluída), apesar do comentário de FromContext e do README
// prometerem os três campos "sempre que disponíveis". Este teste tranca
// a correção: o mesmo valor do request_id também precisa aparecer como
// correlation_id no contexto.
func TestRequestID_AlsoSetsCorrelationID(t *testing.T) {
	var gotRequestID, gotCorrelationID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestID = logging.RequestID(r.Context())
		gotCorrelationID = logging.CorrelationID(r.Context())
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotCorrelationID == "" {
		t.Fatal("expected a correlation id in context, got empty string")
	}
	if gotCorrelationID != gotRequestID {
		t.Errorf("correlation_id = %q, want the same value as request_id (%q)", gotCorrelationID, gotRequestID)
	}
}

func TestRecoverer_ConvertsPanicToJSON500(t *testing.T) {
	handler := Recoverer(testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Não pode vazar um panic para fora de ServeHTTP.
	handler.ServeHTTP(rec, req)

	if rec.Code != 500 {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestSecurityHeaders_SetsBaselineHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
}

func TestRateLimit_AllowsWithinBurstThenRejects(t *testing.T) {
	handler := RateLimit(testLogger(), NewInMemoryLimiter(0, 2), func(r *http.Request) string { return "same-key" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	req := httptest.NewRequest("GET", "/", nil)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst)", i, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once burst is exhausted", rec.Code)
	}
}

func TestRateLimit_DifferentKeysAreIndependent(t *testing.T) {
	callCount := map[string]int{}
	handler := RateLimit(testLogger(), NewInMemoryLimiter(0, 1), func(r *http.Request) string { return r.Header.Get("X-User") })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount[r.Header.Get("X-User")]++
			w.WriteHeader(http.StatusOK)
		}),
	)

	for _, user := range []string{"alice", "bob"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-User", user)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("user %s: status = %d, want 200", user, rec.Code)
		}
	}
}

// fakeHijackableWriter é um http.ResponseWriter mínimo que também
// implementa http.Hijacker, para testar que statusRecorder repassa
// Hijack() em vez de escondê-lo atrás do embedding de uma interface (o
// bug real que quebrava GET /ws atrás de AccessLog/Metrics — ver o
// comentário de statusRecorder.Hijack).
type fakeHijackableWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (f *fakeHijackableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	return nil, nil, nil
}

func TestStatusRecorder_HijackDelegatesToUnderlyingWriter(t *testing.T) {
	underlying := &fakeHijackableWriter{ResponseWriter: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}

	hijacker, ok := (http.ResponseWriter(rec)).(http.Hijacker)
	if !ok {
		t.Fatal("statusRecorder does not satisfy http.Hijacker — WebSocket upgrades behind AccessLog/Metrics would fail")
	}
	if _, _, err := hijacker.Hijack(); err != nil {
		t.Fatalf("Hijack: unexpected error %v", err)
	}
	if !underlying.hijacked {
		t.Error("expected the underlying ResponseWriter's Hijack to have been called")
	}
}

func TestStatusRecorder_HijackErrorsWhenUnderlyingDoesNotSupportIt(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}

	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("expected an error when the underlying ResponseWriter does not implement http.Hijacker")
	}
}
