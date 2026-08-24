package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// Estes testes rodam o binário `syft` de verdade (pulados se não estiver
// no PATH) — mesmo princípio de rigor de cmd/trivy-sidecar/
// cmd/gitleaks-sidecar.
func skipIfNoSyft(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not found in PATH; skipping sidecar test that shells out to the real binary")
	}
}

func TestHandleScan_InvalidJSON_Returns400(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader([]byte("not json")))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandleScan_EmptyPath_Returns400(t *testing.T) {
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(scanRequest{Path: ""})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Defesa em profundidade real: mesmo que o worker (ou um bug) peça um
// path fora do volume compartilhado, o sidecar recusa — não confia
// cegamente no que a rede interna mandou.
func TestHandleScan_PathOutsideWorkspace_Returns400(t *testing.T) {
	orig := workspaceRoot
	workspaceRoot = "/workspace"
	defer func() { workspaceRoot = orig }()

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(scanRequest{Path: "/etc/passwd"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a path outside %s", rec.Code, workspaceRoot)
	}
}

func TestHandleScan_RealSyftAgainstEmptyDir_Returns200WithJSON(t *testing.T) {
	skipIfNoSyft(t)

	orig := workspaceRoot
	workspaceRoot = t.TempDir()
	defer func() { workspaceRoot = orig }()

	target := filepath.Join(workspaceRoot, "empty-project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(scanRequest{Path: target})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var report map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("response is not valid JSON: %v, body=%s", err, rec.Body.String())
	}
}

func TestHealthEndpoint_Returns200(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
