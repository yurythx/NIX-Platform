package infrastructure

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só o parsing do JSON de saída do trivy — nenhum
// chama o binário trivy de verdade (ver git_clone_test.go para a
// validação de alvo/SSRF compartilhada, e trivy_scanner.go para a
// verificação de ponta a ponta feita manualmente contra um repositório
// público real, registrada no roadmap).

func TestParseTrivyReport_VulnerabilitiesAndMisconfigurations(t *testing.T) {
	// Dockerfile de verdade em disco (Fase 12 — snippet): a
	// misconfiguration abaixo aponta StartLine=3, dentro deste arquivo —
	// prova que captureSnippet lê o conteúdo real, não só que a função
	// existe.
	dir := t.TempDir()
	dockerfile := "FROM alpine:3.20\n\nUSER root\n\nCMD [\"sh\"]\n"
	if err := os.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write test Dockerfile: %v", err)
	}

	raw := []byte(`{
		"Results": [
			{
				"Target": "go.mod",
				"Vulnerabilities": [
					{"VulnerabilityID": "CVE-2026-0001", "PkgName": "example.com/dep", "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1", "Severity": "CRITICAL", "Title": "dependência vulnerável"}
				]
			},
			{
				"Target": "Dockerfile",
				"Misconfigurations": [
					{"ID": "DS002", "Title": "usuário root", "Message": "container roda como root", "Severity": "HIGH", "CauseMetadata": {"StartLine": 3}}
				]
			}
		]
	}`)

	findings, err := parseTrivyReport(raw, dir)
	if err != nil {
		t.Fatalf("parseTrivyReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}

	vuln := findings[0]
	if vuln.ID != "CVE-2026-0001" || vuln.Severity != domain.SeverityCritical || vuln.OWASPCategory != "A06:2021-Vulnerable and Outdated Components" {
		t.Errorf("vuln finding = %+v, unexpected fields", vuln)
	}
	if !strings.Contains(vuln.Description, "example.com/dep@1.0.0") {
		t.Errorf("vuln description = %q, want it to mention the package/version", vuln.Description)
	}
	if vuln.Snippet != "" {
		t.Errorf("vuln Snippet = %q, want empty — a dependency vulnerability has no specific line", vuln.Snippet)
	}

	misconf := findings[1]
	if misconf.ID != "DS002" || misconf.Severity != domain.SeverityHigh || misconf.OWASPCategory != "A05:2021-Security Misconfiguration" {
		t.Errorf("misconfig finding = %+v, unexpected fields", misconf)
	}
	if misconf.Line != 3 {
		t.Errorf("misconfig line = %d, want 3", misconf.Line)
	}
	if !strings.Contains(misconf.Snippet, "USER root") {
		t.Errorf("misconfig Snippet = %q, want it to contain the real Dockerfile line around StartLine=3", misconf.Snippet)
	}
}

func TestParseTrivyReport_NoFindings_ReturnsEmptyNotError(t *testing.T) {
	findings, err := parseTrivyReport([]byte(`{"Results": []}`), "")
	if err != nil {
		t.Fatalf("parseTrivyReport: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none for a clean scan", findings)
	}
}

// A partir daqui: Execute (§ Containerização — decisão do usuário de
// isolar cada scanner no próprio container, ver
// docs/roadmap-secops-orchestrator.md). Diferente do parsing acima, este
// caminho chama um sidecar HTTP (cmd/trivy-sidecar) em vez do binário
// `trivy` local — testado com um httptest.Server fazendo o papel do
// sidecar, nunca o binário de verdade (esse continua só verificado
// manualmente contra um repositório público real, registrado no
// roadmap).

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestTrivyScanner_Execute_NotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewTrivyScanner("trivy", "", "", time.Minute, testLogger(t))

	_, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_TRIVY_SERVICE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestTrivyScanner_ScanRemote_SendsPathAndParsesSidecarResponse(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode sidecar request body: %v", err)
		}
		gotPath = body.Path

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Results":[{"Target":"go.mod","Vulnerabilities":[
			{"VulnerabilityID":"CVE-2026-9999","PkgName":"pkg","InstalledVersion":"1.0","Severity":"HIGH","Title":"achado via sidecar"}
		]}]}`))
	}))
	defer srv.Close()

	scanner := &TrivyScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	findings, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err != nil {
		t.Fatalf("scanRemote: %v", err)
	}

	if gotPath != "/workspace/nix-scan-abc123" {
		t.Errorf("sidecar received path = %q, want the exact dir passed to scanRemote", gotPath)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-2026-9999" {
		t.Errorf("findings = %+v, want the sidecar's response parsed via parseTrivyReport", findings)
	}
}

func TestTrivyScanner_ScanRemote_SidecarErrorStatus_ReturnsDependencyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"fatal: could not read Username for 'https://github.com'"}`))
	}))
	defer srv.Close()

	scanner := &TrivyScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	_, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err == nil {
		t.Fatal("expected an error when the sidecar responds with a non-200 status")
	}
	if !strings.Contains(err.Error(), "could not read Username") {
		t.Errorf("err = %v, want it to carry the sidecar's real error message through", err)
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestNormalizeTrivySeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"CRITICAL": domain.SeverityCritical,
		"HIGH":     domain.SeverityHigh,
		"MEDIUM":   domain.SeverityMedium,
		"LOW":      domain.SeverityLow,
		"UNKNOWN":  domain.SeverityLow,
		"garbage":  domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeTrivySeverity(input); got != want {
			t.Errorf("normalizeTrivySeverity(%q) = %q, want %q", input, got, want)
		}
	}
}
