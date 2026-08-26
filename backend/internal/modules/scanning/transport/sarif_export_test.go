// Testes de sarif_export.go.
package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

func TestExportFindingsSarif_InvalidScanID_Returns400(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger(), testSonarQubePublicURL)

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/not-a-uuid/findings.sarif", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportFindingsSarif(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExportFindingsSarif_UnknownScanID_Returns404(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger(), testSonarQubePublicURL)

	unknown := uuid.New().String()
	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+unknown+"/findings.sarif", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", unknown)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportFindingsSarif(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// TestExportFindingsSarif_KnownScan_WritesValidSarifDocument roda um scan
// com 2 scanners (trivy com 2 achados incluindo um CVE repetido em 2
// arquivos, gitleaks com 0 achados) e verifica: o documento raiz (sem
// envelope {data,...}), um run por scanner (inclusive o que não achou
// nada), rules deduplicadas por Finding.ID, e level/security-severity
// coerentes com a severidade original.
func TestExportFindingsSarif_KnownScan_WritesValidSarifDocument(t *testing.T) {
	pool := testPool(t)
	trivy := &fakeScanner{name: "trivy", findings: []domain.Finding{
		{ID: "CVE-2026-SARIF", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityCritical, Description: "dependência vulnerável em go.sum", File: "go.sum", Line: 7},
		{ID: "CVE-2026-SARIF", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityCritical, Description: "mesma CVE, outro arquivo", File: "vendor/go.sum", Line: 3},
		{ID: "nix-sca-low-001", Severity: domain.SeverityLow, Description: "achado de baixa severidade", File: "README.md", Line: 1},
	}}
	gitleaks := &fakeScanner{name: "gitleaks", findings: nil}
	svc := newTestService(pool, trivy, gitleaks)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)

	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", strings.NewReader(
		`{"scanners":["trivy","gitleaks"],"target":"https://example.com/repo.git"}`,
	))
	createRec := httptest.NewRecorder()
	h.CreateScan(createRec, createReq)
	job := decodeEnvelope[scanJobResponse](t, createRec.Body.Bytes())
	jobID, err := uuid.Parse(job.JobID)
	if err != nil {
		t.Fatalf("parse job id: %v", err)
	}
	if err := svc.ProcessScanJob(context.Background(), jobID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+job.JobID+"/findings.sarif", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", job.JobID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportFindingsSarif(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/sarif+json") {
		t.Errorf("Content-Type = %q, want application/sarif+json", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".sarif") {
		t.Errorf("Content-Disposition = %q, want an attachment with a .sarif filename", cd)
	}

	var doc sarifLog
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response body is not valid JSON matching sarifLog: %v\nbody=%s", err, rec.Body.String())
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("runs = %d, want 2 (trivy + gitleaks, mesmo gitleaks sem achado nenhum)", len(doc.Runs))
	}

	// buildSarifLog ordena por nome de scanner — gitleaks vem antes de trivy.
	gitleaksRun, trivyRun := doc.Runs[0], doc.Runs[1]
	if gitleaksRun.Tool.Driver.Name != "gitleaks" {
		t.Errorf("runs[0].tool.driver.name = %q, want gitleaks", gitleaksRun.Tool.Driver.Name)
	}
	if len(gitleaksRun.Results) != 0 {
		t.Errorf("gitleaks results = %d, want 0 (scanner rodou, não achou nada — run precisa existir mesmo assim)", len(gitleaksRun.Results))
	}

	if trivyRun.Tool.Driver.Name != "trivy" {
		t.Errorf("runs[1].tool.driver.name = %q, want trivy", trivyRun.Tool.Driver.Name)
	}
	if len(trivyRun.Results) != 3 {
		t.Fatalf("trivy results = %d, want 3 (2 CVE repetida + 1 low)", len(trivyRun.Results))
	}
	if len(trivyRun.Tool.Driver.Rules) != 2 {
		t.Fatalf("trivy rules = %d, want 2 (CVE-2026-SARIF deduplicada + nix-sca-low-001)", len(trivyRun.Tool.Driver.Rules))
	}

	var criticalResult *sarifResult
	for i := range trivyRun.Results {
		if trivyRun.Results[i].RuleID == "CVE-2026-SARIF" {
			criticalResult = &trivyRun.Results[i]
			break
		}
	}
	if criticalResult == nil {
		t.Fatal("nenhum result com ruleId CVE-2026-SARIF")
	}
	if criticalResult.Level != "error" {
		t.Errorf("level do achado CRITICAL = %q, want error", criticalResult.Level)
	}
	if len(criticalResult.Locations) != 1 || criticalResult.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Errorf("locations do achado CRITICAL = %+v, want 1 location com artifactLocation.uri preenchido", criticalResult.Locations)
	}
	if criticalResult.Locations[0].PhysicalLocation.Region == nil || criticalResult.Locations[0].PhysicalLocation.Region.StartLine == 0 {
		t.Errorf("region do achado CRITICAL = %+v, want startLine > 0", criticalResult.Locations[0].PhysicalLocation.Region)
	}

	var criticalRule *sarifRule
	for i := range trivyRun.Tool.Driver.Rules {
		if trivyRun.Tool.Driver.Rules[i].ID == "CVE-2026-SARIF" {
			criticalRule = &trivyRun.Tool.Driver.Rules[i]
			break
		}
	}
	if criticalRule == nil {
		t.Fatal("nenhuma rule com id CVE-2026-SARIF")
	}
	if criticalRule.Properties == nil || criticalRule.Properties.SecuritySeverity != "9.5" {
		t.Errorf("security-severity da rule CRITICAL = %+v, want 9.5", criticalRule.Properties)
	}
}
