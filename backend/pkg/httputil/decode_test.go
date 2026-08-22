package httputil

import (
	"net/http/httptest"
	"strings"
	"testing"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

type sampleDTO struct {
	Name string `json:"name"`
}

func TestDecodeJSON_Valid(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"nix"}`))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	if err := DecodeJSON(rec, req, &dst); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if dst.Name != "nix" {
		t.Errorf("Name = %q", dst.Name)
	}
}

func TestDecodeJSON_EmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	err := DecodeJSON(rec, req, &dst)
	if err == nil {
		t.Fatal("expected an error for empty body")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeBadRequest {
		t.Errorf("expected BAD_REQUEST, got %v", err)
	}
}

func TestDecodeJSON_UnknownFieldsRejected(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"nix","unexpected":true}`))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	err := DecodeJSON(rec, req, &dst)
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestDecodeJSON_TrailingGarbageRejected(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"nix"}{"name":"again"}`))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	err := DecodeJSON(rec, req, &dst)
	if err == nil {
		t.Fatal("expected an error for trailing JSON content")
	}
}

func TestDecodeJSON_OversizedBodyRejected(t *testing.T) {
	huge := strings.Repeat("a", MaxRequestBodyBytes+1)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"`+huge+`"}`))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	err := DecodeJSON(rec, req, &dst)
	if err == nil {
		t.Fatal("expected an error for an oversized body")
	}
}

func TestDecodeJSON_MalformedJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()

	var dst sampleDTO
	if err := DecodeJSON(rec, req, &dst); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
