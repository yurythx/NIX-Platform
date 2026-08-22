package httpserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandler_AlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	HealthHandler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyHandler_AllChecksPass(t *testing.T) {
	checks := []Check{
		{Name: "postgres", Fn: func(ctx context.Context) error { return nil }},
		{Name: "rabbitmq", Fn: func(ctx context.Context) error { return nil }},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	ReadyHandler(checks, time.Second).ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyHandler_OneCheckFails(t *testing.T) {
	checks := []Check{
		{Name: "postgres", Fn: func(ctx context.Context) error { return nil }},
		{Name: "rabbitmq", Fn: func(ctx context.Context) error { return errors.New("connection refused") }},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	ReadyHandler(checks, time.Second).ServeHTTP(rec, req)

	if rec.Code != 503 {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestReadyHandler_NoChecksIsReady(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	ReadyHandler(nil, time.Second).ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
