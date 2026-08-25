package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só o parsing do JSON de saída do semgrep — nenhum
// chama o binário semgrep de verdade. As fixtures abaixo espelham a
// saída real observada rodando `semgrep scan --config p/owasp-top-ten
// --json` contra um projeto Python deliberadamente vulnerável
// (OWASP/PyGoat), incluindo a inconsistência real de tipo do campo
// "owasp" entre regras da comunidade (lista vs. string única).

func TestParseSemgrepReport_ListAndStringOWASPMetadata(t *testing.T) {
	raw := []byte(`{
		"results": [
			{
				"check_id": "python.django.security.injection.command.subprocess-injection.subprocess-injection",
				"path": "/scan/challenge/views.py",
				"start": {"line": 81},
				"extra": {
					"message": "Detected subprocess function with process ID unsanitized input",
					"severity": "ERROR",
					"metadata": {"owasp": ["A01:2017 - Injection", "A03:2021 - Injection"]}
				}
			},
			{
				"check_id": "python.flask.security.audit.debug-enabled.debug-enabled",
				"path": "/scan/app.py",
				"start": {"line": 123},
				"extra": {
					"message": "Detected Flask app with debug=True",
					"severity": "WARNING",
					"metadata": {"owasp": "A06:2017 - Security Misconfiguration"}
				}
			},
			{
				"check_id": "generic.secrets.security.detected-generic-secret",
				"path": "/scan/config.py",
				"start": {"line": 5},
				"extra": {
					"message": "hardcoded secret",
					"severity": "INFO",
					"metadata": {}
				}
			}
		]
	}`)

	findings, err := parseSemgrepReport(raw, "/scan")
	if err != nil {
		t.Fatalf("parseSemgrepReport: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}

	injection := findings[0]
	if injection.Severity != domain.SeverityHigh {
		t.Errorf("ERROR severity = %q, want HIGH", injection.Severity)
	}
	if injection.OWASPCategory != "A01:2017 - Injection" {
		t.Errorf("OWASPCategory (list) = %q, want the first list entry", injection.OWASPCategory)
	}
	if injection.File != "challenge/views.py" {
		t.Errorf("File = %q, want the path relative to the scan dir", injection.File)
	}
	if injection.Line != 81 {
		t.Errorf("Line = %d, want 81", injection.Line)
	}

	misconfig := findings[1]
	if misconfig.Severity != domain.SeverityMedium {
		t.Errorf("WARNING severity = %q, want MEDIUM", misconfig.Severity)
	}
	if misconfig.OWASPCategory != "A06:2017 - Security Misconfiguration" {
		t.Errorf("OWASPCategory (single string) = %q, want the string value", misconfig.OWASPCategory)
	}

	noMetadata := findings[2]
	if noMetadata.Severity != domain.SeverityLow {
		t.Errorf("INFO severity = %q, want LOW", noMetadata.Severity)
	}
	if noMetadata.OWASPCategory != "" {
		t.Errorf("OWASPCategory (absent) = %q, want empty", noMetadata.OWASPCategory)
	}
}

// TestParseSemgrepReport_CapturesSnippetFromRealFile cobre a Fase 12
// (snippet de código no achado): r.Path já vem ABSOLUTO na saída real do
// semgrep, direto utilizável por captureSnippet sem remontar a partir do
// File relativo — este teste escreve um arquivo de verdade em disco pra
// provar que o snippet capturado é o conteúdo real ao redor da linha, não
// um valor inventado.
func TestParseSemgrepReport_CapturesSnippetFromRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "views.py")
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i+1)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	raw := []byte(fmt.Sprintf(`{
		"results": [
			{
				"check_id": "python.django.security.injection.command.subprocess-injection.subprocess-injection",
				"path": %q,
				"start": {"line": 10},
				"extra": {"message": "achado de teste", "severity": "ERROR", "metadata": {}}
			}
		]
	}`, path))

	findings, err := parseSemgrepReport(raw, dir)
	if err != nil {
		t.Fatalf("parseSemgrepReport: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Snippet, "line 10") {
		t.Errorf("Snippet = %q, want it to contain the real file's line 10", findings[0].Snippet)
	}
}

func TestParseSemgrepReport_NoFindings_ReturnsEmptyNotError(t *testing.T) {
	findings, err := parseSemgrepReport([]byte(`{"results": []}`), "/scan")
	if err != nil {
		t.Fatalf("parseSemgrepReport: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none for a clean scan", findings)
	}
}

func TestFirstOWASPCategory(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"list with entries", `["A03:2021 - Injection", "A05:2025 - Injection"]`, "A03:2021 - Injection"},
		{"single string", `"A06:2017 - Security Misconfiguration"`, "A06:2017 - Security Misconfiguration"},
		{"empty list", `[]`, ""},
		{"absent", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firstOWASPCategory(json.RawMessage(tc.raw))
			if got != tc.want {
				t.Errorf("firstOWASPCategory(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeSemgrepSeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"ERROR":   domain.SeverityHigh,
		"WARNING": domain.SeverityMedium,
		"INFO":    domain.SeverityLow,
		"garbage": domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeSemgrepSeverity(input); got != want {
			t.Errorf("normalizeSemgrepSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

// Containerização (§ docs/roadmap-secops-orchestrator.md): mesmos três
// testes que TrivyScanner/GitleaksScanner já têm pro par Execute
// (indisponível sem sidecar)/scanRemote (chamada HTTP de verdade contra
// um servidor de teste), mais um cobrindo a única diferença real de
// contrato — o corpo da requisição também carrega `config` (ver
// comentário em scanRemote).

func TestSemgrepScanner_Execute_NotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewSemgrepScanner("semgrep", "", "", "", 0, testLogger(t))

	_, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_SEMGREP_SERVICE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestSemgrepScanner_ScanRemote_SendsPathAndConfig_ParsesSidecarResponse(t *testing.T) {
	var gotPath, gotConfig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path   string `json:"path"`
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode sidecar request body: %v", err)
		}
		gotPath = body.Path
		gotConfig = body.Config

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":[
			{"check_id":"achado.via.sidecar","path":"/workspace/nix-scan-abc123/app.py","start":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{}}}
		]}`))
	}))
	defer srv.Close()

	scanner := &SemgrepScanner{serviceURL: srv.URL, config: "p/owasp-top-ten", httpClient: srv.Client()}
	findings, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err != nil {
		t.Fatalf("scanRemote: %v", err)
	}

	if gotPath != "/workspace/nix-scan-abc123" {
		t.Errorf("sidecar received path = %q, want the exact dir passed to scanRemote", gotPath)
	}
	if gotConfig != "p/owasp-top-ten" {
		t.Errorf("sidecar received config = %q, want the scanner's own config (semgrep-sidecar has no fixed ruleset)", gotConfig)
	}
	if len(findings) != 1 || findings[0].ID != "achado.via.sidecar" {
		t.Errorf("findings = %+v, want the sidecar's response parsed via parseSemgrepReport", findings)
	}
}

func TestSemgrepScanner_ScanRemote_SidecarErrorStatus_ReturnsDependencyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"invalid configuration file"}`))
	}))
	defer srv.Close()

	scanner := &SemgrepScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	_, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err == nil {
		t.Fatal("expected an error when the sidecar responds with a non-200 status")
	}
	if !strings.Contains(err.Error(), "invalid configuration file") {
		t.Errorf("err = %v, want it to carry the sidecar's real error message through", err)
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestRelativeToScanDir(t *testing.T) {
	cases := []struct{ path, scanDir, want string }{
		{"/scan/app.py", "/scan", "app.py"},
		{"/scan/sub/dir/app.py", "/scan", "sub/dir/app.py"},
		{"app.py", "/scan", "app.py"}, // já relativo — nada a fazer
	}
	for _, tc := range cases {
		if got := relativeToScanDir(tc.path, tc.scanDir); got != tc.want {
			t.Errorf("relativeToScanDir(%q, %q) = %q, want %q", tc.path, tc.scanDir, got, tc.want)
		}
	}
}
