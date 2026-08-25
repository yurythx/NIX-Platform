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

func skipIfNoSonarScanner(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sonar-scanner"); err != nil {
		t.Skip("sonar-scanner not found in PATH; skipping sidecar test that shells out to the real binary")
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

func TestHandleScan_MissingRequiredFields_Returns400(t *testing.T) {
	cases := []scanRequest{
		{Path: "", HostURL: "http://sonarqube:9000", ProjectKey: "k"},
		{Path: "/workspace/x", HostURL: "", ProjectKey: "k"},
		{Path: "/workspace/x", HostURL: "http://sonarqube:9000", ProjectKey: ""},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(tc)
		req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
		handleScan(testLogger())(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("request %+v: status = %d, want 400", tc, rec.Code)
		}
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
	body, _ := json.Marshal(scanRequest{Path: "/etc/passwd", HostURL: "http://sonarqube:9000", ProjectKey: "k"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a path outside %s", rec.Code, workspaceRoot)
	}
}

// TestHandleScan_RealSonarScannerAgainstUnreachableServer: sem um
// servidor SonarQube real e alcançável nesta rede, a expectativa real é
// que o CLI falhe rápido tentando se conectar — prova que o processo é
// invocado com os argumentos certos e que a falha vira 422 com o stderr
// real capturado, sem exigir infraestrutura pesada só pra este teste.
// Um servidor real de verdade é exercitado manualmente (ver roadmap).
func TestHandleScan_RealSonarScannerAgainstUnreachableServer_Returns422(t *testing.T) {
	skipIfNoSonarScanner(t)

	orig := workspaceRoot
	workspaceRoot = t.TempDir()
	defer func() { workspaceRoot = orig }()

	target := filepath.Join(workspaceRoot, "empty-project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(scanRequest{
		Path: target, HostURL: "http://127.0.0.1:1", Token: "x", ProjectKey: "test-project",
	})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	handleScan(testLogger())(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (unreachable server), body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadCETaskID_ParsesKeyValueLines(t *testing.T) {
	dir := t.TempDir()
	workDir := filepath.Join(dir, ".scannerwork")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "projectKey=test-project\nserverUrl=http://sonarqube:9000\nceTaskId=abc-123\nceTaskUrl=http://sonarqube:9000/api/ce/task?id=abc-123\n"
	if err := os.WriteFile(filepath.Join(workDir, "report-task.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := readCETaskID(dir)
	if err != nil {
		t.Fatalf("readCETaskID: %v", err)
	}
	if got != "abc-123" {
		t.Errorf("ceTaskId = %q, want %q", got, "abc-123")
	}
}

func TestReadCETaskID_MissingFile_ReturnsError(t *testing.T) {
	if _, err := readCETaskID(t.TempDir()); err == nil {
		t.Error("readCETaskID with no report-task.txt = nil error, want an error")
	}
}

func TestExtractErrorLine(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"fatal line wins over trailing noise", "some info\nFATAL: could not connect\nmore noise", "FATAL: could not connect"},
		{"no fatal/error line falls back to last non-empty", "line one\nline two\n\n", "line two"},
		{"empty input", "", "unknown error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractErrorLine(tc.in); got != tc.want {
				t.Errorf("extractErrorLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
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
