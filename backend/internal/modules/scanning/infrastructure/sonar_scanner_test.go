package infrastructure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só a lógica pura do adapter (project key, parsing
// do report-task.txt, parsing/paginação de issues, severidade) — nenhum
// chama um servidor SonarQube de verdade. O fluxo completo (submeter uma
// análise, esperar a Compute Engine, buscar issues) foi verificado
// manualmente contra um servidor real, registrado no roadmap.

func TestSonarProjectKey_DeterministicAndSanitized(t *testing.T) {
	got := sonarProjectKey("https://github.com/org/repo.git#main")
	want := "nix-scan_github.com_org_repo"
	if got != want {
		t.Errorf("sonarProjectKey = %q, want %q", got, want)
	}

	// O #ref não deve afetar a key — o mesmo repositório em branches
	// diferentes reaproveita o mesmo projeto no SonarQube.
	gotNoRef := sonarProjectKey("https://github.com/org/repo.git")
	if gotNoRef != want {
		t.Errorf("sonarProjectKey without ref = %q, want the same key as with a ref (%q)", gotNoRef, want)
	}
}

func TestReadReportTask_ParsesKeyValueLines(t *testing.T) {
	dir := t.TempDir()
	workDir := filepath.Join(dir, ".scannerwork")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "projectKey=test-project\nserverUrl=http://sonarqube:9000\nceTaskId=abc-123\nceTaskUrl=http://sonarqube:9000/api/ce/task?id=abc-123\n"
	if err := os.WriteFile(filepath.Join(workDir, "report-task.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	props, err := readReportTask(dir)
	if err != nil {
		t.Fatalf("readReportTask: %v", err)
	}
	if props["ceTaskId"] != "abc-123" {
		t.Errorf("ceTaskId = %q, want %q", props["ceTaskId"], "abc-123")
	}
	if props["projectKey"] != "test-project" {
		t.Errorf("projectKey = %q, want %q", props["projectKey"], "test-project")
	}
}

func TestReadReportTask_MissingFile_ReturnsError(t *testing.T) {
	if _, err := readReportTask(t.TempDir()); err == nil {
		t.Error("readReportTask with no report-task.txt = nil error, want an error")
	}
}

func TestNormalizeSonarSeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"BLOCKER":  domain.SeverityCritical,
		"CRITICAL": domain.SeverityCritical,
		"MAJOR":    domain.SeverityHigh,
		"MINOR":    domain.SeverityMedium,
		"INFO":     domain.SeverityLow,
		"garbage":  domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeSonarSeverity(input); got != want {
			t.Errorf("normalizeSonarSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSonarIssuesResponse_ComponentPrefixStripped(t *testing.T) {
	// Fixture espelhando a saída real observada em GET
	// /api/issues/search?componentKeys=test-project contra um servidor
	// SonarQube de verdade.
	raw := []byte(`{
		"paging": {"total": 1},
		"issues": [
			{
				"rule": "python:S4790",
				"severity": "CRITICAL",
				"component": "nix-scan_github.com_org_repo:app.py",
				"line": 5,
				"message": "Make sure that hashing data is safe here."
			}
		]
	}`)

	var resp sonarIssuesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(resp.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(resp.Issues))
	}
	issue := resp.Issues[0]
	projectKey := "nix-scan_github.com_org_repo"

	f := domain.Finding{
		ID:          issue.RuleKey,
		Severity:    normalizeSonarSeverity(issue.Severity),
		Description: issue.Message,
		File:        strings.TrimPrefix(issue.Component, projectKey+":"),
		Line:        issue.Line,
	}
	if f.File != "app.py" {
		t.Errorf("File = %q, want the component with the project key prefix stripped", f.File)
	}
	if f.ID != "python:S4790" || f.Severity != domain.SeverityCritical || f.Line != 5 {
		t.Errorf("finding = %+v, unexpected fields", f)
	}
}
