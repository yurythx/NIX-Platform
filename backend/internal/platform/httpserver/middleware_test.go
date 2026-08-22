package httpserver

import (
	"log/slog"
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
