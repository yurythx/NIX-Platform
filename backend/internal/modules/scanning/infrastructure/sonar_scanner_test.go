package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só a lógica pura do adapter (project key,
// parsing/paginação de issues, severidade) e a chamada HTTP ao sidecar
// (scanRemote) — nenhum chama um sonar-scanner/servidor SonarQube
// de verdade (isso vive em cmd/sonar-sidecar's main_test.go e foi
// verificado manualmente contra um servidor real, registrado no
// roadmap). report-task.txt não é mais lido por este pacote — o sidecar
// lê e devolve só o ceTaskId via HTTP (ver
// cmd/sonar-sidecar/main_test.go's TestReadCETaskID_*).

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

func TestSonarScanner_Execute_ServerURLNotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewSonarScanner("http://sonar-scanner-cli:8080", "", "", "token", 0, 0, testLogger(t))

	_, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_SONARQUBE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestSonarScanner_Execute_SidecarURLNotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewSonarScanner("", "", "http://sonarqube:9000", "token", 0, 0, testLogger(t))

	_, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_SONAR_SCANNER_SERVICE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestSonarScanner_ScanRemote_SendsFieldsAndParsesCETaskID(t *testing.T) {
	var gotBody struct {
		Path       string `json:"path"`
		HostURL    string `json:"host_url"`
		Token      string `json:"token"`
		ProjectKey string `json:"project_key"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode sidecar request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ce_task_id":"abc-123"}`))
	}))
	defer srv.Close()

	scanner := &SonarScanner{serverURL: "http://sonarqube:9000", token: "tok", sidecarURL: srv.URL, httpClient: srv.Client(), scanHTTPClient: srv.Client()}
	taskID, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123", "test-project")
	if err != nil {
		t.Fatalf("scanRemote: %v", err)
	}
	if taskID != "abc-123" {
		t.Errorf("ceTaskId = %q, want %q", taskID, "abc-123")
	}
	if gotBody.Path != "/workspace/nix-scan-abc123" || gotBody.HostURL != "http://sonarqube:9000" ||
		gotBody.Token != "tok" || gotBody.ProjectKey != "test-project" {
		t.Errorf("sidecar received %+v, want the exact fields scanRemote was called with", gotBody)
	}
}

func TestSonarScanner_ScanRemote_SidecarErrorStatus_ReturnsDependencyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"FATAL: could not connect to http://sonarqube:9000"}`))
	}))
	defer srv.Close()

	scanner := &SonarScanner{sidecarURL: srv.URL, httpClient: srv.Client(), scanHTTPClient: srv.Client()}
	_, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123", "test-project")
	if err == nil {
		t.Fatal("expected an error when the sidecar responds with a non-200 status")
	}
	if !strings.Contains(err.Error(), "could not connect") {
		t.Errorf("err = %v, want it to carry the sidecar's real error message through", err)
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
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
