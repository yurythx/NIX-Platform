// Testes de csv_export.go (Fase 14 — Maturidade de AppSec).
package transport

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

func TestExportFindings_InvalidScanID_Returns400(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger(), testSonarQubePublicURL)

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/not-a-uuid/findings.csv", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportFindings(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExportFindings_KnownScan_WritesValidCSVWithHeadersAndRows(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{
		{ID: "CVE-2026-CSV", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityCritical, Description: "achado exportável", File: "go.sum", Line: 7},
	}}
	svc := newTestService(pool, scanner)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)

	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", strings.NewReader(
		`{"scanners":["trivy"],"target":"https://example.com/repo.git"}`,
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

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+job.JobID+"/findings.csv", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", job.JobID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportFindings(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition = %q, want an attachment with a .csv filename", cd)
	}

	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("the response body is not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (1 header + 1 finding)", len(rows))
	}
	if rows[0][0] != "severity" {
		t.Errorf("header row = %v, want it to start with \"severity\"", rows[0])
	}
	if rows[1][0] != "CRITICAL" || rows[1][2] != "CVE-2026-CSV" {
		t.Errorf("data row = %v, want severity=CRITICAL finding_id=CVE-2026-CSV", rows[1])
	}
}

func TestExportProjectFindingsHistory_KnownProject_IncludesTriageColumns(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	finding := domain.Finding{ID: "CVE-2026-HIST-CSV", Severity: domain.SeverityHigh, Description: "achado do histórico", File: "app.py", Line: 12}
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{finding}}
	svc := newTestService(pool, scanner)
	svc = svc.WithTriageRepository(repo)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)
	ctx := context.Background()

	project, err := svc.CreateProjectGit(ctx, "test-project-csv-export", "https://example.com/repo-csv.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}
	job, err := svc.CreateProjectScanJob(ctx, uuid.New(), []string{"trivy"}, project.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob: %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job.ID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}
	fingerprint := domain.Fingerprint("trivy", finding.ID, finding.File, finding.Line)
	if err := svc.TriageFinding(ctx, project.ID, fingerprint, domain.TriageWontFix, "aceito por ora", nil); err != nil {
		t.Fatalf("TriageFinding: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/scanning/projects/"+project.ID.String()+"/findings-history.csv", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectID", project.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ExportProjectFindingsHistory(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("the response body is not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (1 header + 1 history entry)", len(rows))
	}
	header := rows[0]
	dataRow := rows[1]
	colIndex := func(name string) int {
		for i, c := range header {
			if c == name {
				return i
			}
		}
		t.Fatalf("header %v missing column %q", header, name)
		return -1
	}
	if got := dataRow[colIndex("triage_status")]; got != "wont_fix" {
		t.Errorf("triage_status column = %q, want %q", got, "wont_fix")
	}
	if got := dataRow[colIndex("triage_reason")]; got != "aceito por ora" {
		t.Errorf("triage_reason column = %q, want %q", got, "aceito por ora")
	}
	if got := dataRow[colIndex("still_present")]; got != "true" {
		t.Errorf("still_present column = %q, want %q", got, "true")
	}
}
