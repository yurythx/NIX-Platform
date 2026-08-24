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

// Estes testes cobrem só o parsing do JSON nativo do syft e o caminho
// Inventory/sidecar HTTP — nenhum chama o binário syft de verdade (mesmo
// desenho de trivy_scanner_test.go/gitleaks_scanner_test.go).

func TestParseSyftReport_Artifacts(t *testing.T) {
	raw := []byte(`{
		"artifacts": [
			{"name": "github.com/example/dep", "version": "v1.2.3", "type": "go-module", "licenses": [{"value": "MIT"}]},
			{"name": "left-pad", "version": "1.3.0", "type": "npm", "licenses": []}
		]
	}`)

	packages, err := parseSyftReport(raw)
	if err != nil {
		t.Fatalf("parseSyftReport: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(packages))
	}

	dep := packages[0]
	if dep.Name != "github.com/example/dep" || dep.Version != "v1.2.3" || dep.Type != "go-module" || dep.License != "MIT" {
		t.Errorf("package = %+v, unexpected fields", dep)
	}

	noLicense := packages[1]
	if noLicense.Name != "left-pad" || noLicense.License != "" {
		t.Errorf("package = %+v, want an empty License when syft reports none", noLicense)
	}
}

func TestParseSyftReport_NoArtifacts_ReturnsEmptyNotError(t *testing.T) {
	packages, err := parseSyftReport([]byte(`{"artifacts": []}`))
	if err != nil {
		t.Fatalf("parseSyftReport: %v", err)
	}
	if len(packages) != 0 {
		t.Errorf("packages = %v, want none for a project with no detected packages", packages)
	}
}

func TestSyftScanner_Execute_NeverProducesFindings(t *testing.T) {
	// Execute é sempre um no-op — ver o comentário do tipo em
	// syft_scanner.go: SyftScanner nunca aparece na lista de achados de
	// nenhum scan, mesmo sem SCANNING_SYFT_SERVICE_URL configurado.
	scanner := NewSyftScanner("syft", "", "", time.Minute, testLogger(t))

	findings, err := scanner.Execute(context.Background(), "https://example.com/repo.git")
	if err != nil {
		t.Fatalf("Execute: %v, want it to always succeed (no-op)", err)
	}
	if findings != nil {
		t.Errorf("findings = %v, want nil (Syft never produces findings)", findings)
	}
}

func TestSyftScanner_Inventory_NotConfigured_ReturnsDependencyUnavailable(t *testing.T) {
	scanner := NewSyftScanner("syft", "", "", time.Minute, testLogger(t))

	_, err := scanner.Inventory(context.Background(), "https://example.com/repo.git")
	if err == nil {
		t.Fatal("expected an error when SCANNING_SYFT_SERVICE_URL is not configured")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeDependencyUnavailable {
		t.Errorf("err = %v, want a DEPENDENCY_UNAVAILABLE apperrors.Error", err)
	}
}

func TestSyftScanner_InventoryRemote_SendsPathAndParsesSidecarResponse(t *testing.T) {
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
		_, _ = w.Write([]byte(`{"artifacts":[{"name":"pkg-via-sidecar","version":"1.0","type":"go-module","licenses":[]}]}`))
	}))
	defer srv.Close()

	scanner := &SyftScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	packages, err := scanner.inventoryRemote(context.Background(), "/workspace/nix-scan-abc123")
	if err != nil {
		t.Fatalf("inventoryRemote: %v", err)
	}

	if gotPath != "/workspace/nix-scan-abc123" {
		t.Errorf("sidecar received path = %q, want the exact dir passed to inventoryRemote", gotPath)
	}
	if len(packages) != 1 || packages[0].Name != "pkg-via-sidecar" {
		t.Errorf("packages = %+v, want the sidecar's response parsed via parseSyftReport", packages)
	}
}

func TestSyftScanner_InventoryRemote_SidecarErrorStatus_ReturnsDependencyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"fatal: could not read Username for 'https://github.com'"}`))
	}))
	defer srv.Close()

	scanner := &SyftScanner{serviceURL: srv.URL, httpClient: srv.Client()}
	_, err := scanner.inventoryRemote(context.Background(), "/workspace/nix-scan-abc123")
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

func TestSyftScanner_ImplementsBothInterfaces(t *testing.T) {
	var _ domain.CodeScanner = (*SyftScanner)(nil)
	var _ domain.InventoryProvider = (*SyftScanner)(nil)
}
