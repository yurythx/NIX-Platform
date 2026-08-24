package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só o parsing do JSON de saída do gitleaks e o
// caminho Execute/sidecar HTTP — nenhum chama o binário gitleaks de
// verdade (mesmo desenho de trivy_scanner_test.go; git_clone_test.go
// cobre a validação de alvo/SSRF compartilhada).

func TestParseGitleaksReport_Findings(t *testing.T) {
	raw := []byte(`[
		{"Description": "AWS Access Key", "RuleID": "aws-access-key", "File": "config/settings.py", "StartLine": 12, "Match": "AKIA1234567890EXAMPLE"},
		{"Description": "Generic API Key", "RuleID": "generic-api-key", "File": "internal/client.go", "StartLine": 4, "Match": "sk_live_abcdefghijklmnop"}
	]`)

	findings, err := parseGitleaksReport(raw, "")
	if err != nil {
		t.Fatalf("parseGitleaksReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}

	f := findings[0]
	if f.ID != "aws-access-key" || f.Severity != domain.SeverityCritical {
		t.Errorf("finding = %+v, want ID=aws-access-key and Severity=CRITICAL (gitleaks tem só binário achou/não achou)", f)
	}
	if f.OWASPCategory != "A07:2021-Identification and Authentication Failures" {
		t.Errorf("OWASPCategory = %q, want A07:2021 (onde o OWASP mapeia CWE-798, hardcoded credentials)", f.OWASPCategory)
	}
	if f.File != "config/settings.py" || f.Line != 12 {
		t.Errorf("finding location = %s:%d, want config/settings.py:12", f.File, f.Line)
	}
	if strings.Contains(f.Snippet, "1234567890") {
		t.Errorf("Snippet = %q, o segredo real nunca pode aparecer em claro no achado persistido", f.Snippet)
	}
}

func TestParseGitleaksReport_NoFindings_ReturnsEmptyNotError(t *testing.T) {
	// gitleaks não escreve "[]" quando não acha nada — não escreve NADA
	// em stdout (--report-path /dev/stdout com zero achados é vazio).
	for _, raw := range [][]byte{nil, []byte(""), []byte("  \n")} {
		findings, err := parseGitleaksReport(raw, "")
		if err != nil {
			t.Fatalf("parseGitleaksReport(%q): %v", raw, err)
		}
		if len(findings) != 0 {
			t.Errorf("parseGitleaksReport(%q) = %v, want none for a clean scan", raw, findings)
		}
	}
}

// TestParseGitleaksReport_StripsBaseDirFromFile cobre um comportamento
// real observado contra o gitleaks de verdade (não hipotético): ao
// contrário do trivy, que já normaliza "Target" pra um caminho relativo, o
// gitleaks devolve "File" com o --source (aqui, o diretório de clone
// efêmero) embutido no meio do caminho — sem este trim, o achado mostrado
// ao usuário vazaria o nome interno do diretório temporário
// (ex.: "/workspace/nix-scan-3216795497/new_key" em vez de "new_key").
func TestParseGitleaksReport_StripsBaseDirFromFile(t *testing.T) {
	raw := []byte(`[{"Description":"AWS Access Key","RuleID":"aws-access-token","File":"/workspace/nix-scan-3216795497/new_key","StartLine":2,"Match":"AKIAEXAMPLE"}]`)

	findings, err := parseGitleaksReport(raw, "/workspace/nix-scan-3216795497")
	if err != nil {
		t.Fatalf("parseGitleaksReport: %v", err)
	}
	if len(findings) != 1 || findings[0].File != "new_key" {
		t.Errorf("findings = %+v, want File=\"new_key\" with the ephemeral clone dir stripped", findings)
	}
}

func TestMaskSecretSnippet_NeverReturnsTheSecretInClear(t *testing.T) {
	cases := []string{"AKIA1234567890EXAMPLE", "short", "sk_live_abcdefghijklmnopqrstuvwxyz"}
	for _, secret := range cases {
		masked := maskSecretSnippet(secret)
		if masked == secret {
			t.Errorf("maskSecretSnippet(%q) = %q, want it masked, never identical to the input", secret, masked)
		}
		if len(masked) != len(secret) {
			t.Errorf("maskSecretSnippet(%q) length = %d, want %d (same length, only masked)", secret, len(masked), len(secret))
		}
	}
}

func TestGitleaksScanner_Execute_NotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewGitleaksScanner("gitleaks", "", "", time.Minute, testLogger(t))

	_, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_GITLEAKS_SERVICE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestGitleaksScanner_ScanRemote_SendsPathAndParsesSidecarResponse(t *testing.T) {
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
		_, _ = w.Write([]byte(`[{"Description":"achado via sidecar","RuleID":"generic-api-key","File":"a.go","StartLine":1,"Match":"secretvalue"}]`))
	}))
	defer srv.Close()

	scanner := &GitleaksScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	findings, err := scanner.scanRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err != nil {
		t.Fatalf("scanRemote: %v", err)
	}

	if gotPath != "/workspace/nix-scan-abc123" {
		t.Errorf("sidecar received path = %q, want the exact dir passed to scanRemote", gotPath)
	}
	if len(findings) != 1 || findings[0].ID != "generic-api-key" {
		t.Errorf("findings = %+v, want the sidecar's response parsed via parseGitleaksReport", findings)
	}
}

func TestGitleaksScanner_ScanRemote_SidecarErrorStatus_ReturnsDependencyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"fatal: could not read Username for 'https://github.com'"}`))
	}))
	defer srv.Close()

	scanner := &GitleaksScanner{serviceURL: srv.URL, httpClient: srv.Client()}
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
