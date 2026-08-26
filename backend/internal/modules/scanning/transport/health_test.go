// Testes do handler ScannersHealth (revisão de exibição de resultados).
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// fakeHealthCheckScanner: mesmo raciocínio de
// application/health_test.go's tipo homônimo — implementa
// domain.CodeScanner + domain.HealthChecker sem precisar de sidecar
// nenhum de verdade no ar.
type fakeHealthCheckScanner struct {
	name string
	err  error
}

func (f *fakeHealthCheckScanner) Name() string { return f.name }
func (f *fakeHealthCheckScanner) Execute(context.Context, string) ([]domain.Finding, error) {
	return nil, nil
}
func (f *fakeHealthCheckScanner) HealthCheck(ctx context.Context) error { return f.err }

var _ domain.HealthChecker = (*fakeHealthCheckScanner)(nil)

func TestScannersHealth_ReturnsEnvelopeWithEachScanner(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(
		newTestService(pool, &fakeHealthCheckScanner{name: "healthy"}, &fakeHealthCheckScanner{name: "broken", err: errors.New("fora do ar")}),
		testLogger(), testSonarQubePublicURL,
	)

	r := httptest.NewRequest(http.MethodGet, "/scanning/scanners/health", nil)
	rec := httptest.NewRecorder()

	h.ScannersHealth(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	results := decodeEnvelope[[]ScannerHealthResponse](t, rec.Body.Bytes())
	byName := make(map[string]ScannerHealthResponse, len(results))
	for _, r := range results {
		byName[r.Scanner] = r
	}
	if h, ok := byName["healthy"]; !ok || !h.Healthy || h.Message != "" {
		t.Errorf("healthy = %+v, want Healthy=true Message=\"\"", h)
	}
	if b, ok := byName["broken"]; !ok || b.Healthy || b.Message != "fora do ar" {
		t.Errorf("broken = %+v, want Healthy=false Message=%q", b, "fora do ar")
	}
}

// TestGetScanStatusHandler_IncludesFindingsBySeverity fecha o
// round-trip de ponta a ponta (HTTP, não só application.ScanStatus já
// coberto em application/scans_test.go): a resposta JSON de
// GET /scanning/scans/{scanID} inclui findings_by_severity.
func TestGetScanStatusHandler_IncludesFindingsBySeverity(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{
		{ID: "CVE-STATUS-HANDLER", Severity: domain.SeverityCritical, Description: "crítico via handler"},
	}}
	svc := newTestService(pool, scanner)
	h := NewHandlers(svc, testLogger(), testSonarQubePublicURL)

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy"}, Target: "https://example.com/status-handler.git"})
	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
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

	status := getScanStatus(t, h, job.JobID)
	if status.FindingsBySeverity["CRITICAL"] != 1 {
		t.Errorf("FindingsBySeverity[\"CRITICAL\"] = %d, want 1 (got %+v)", status.FindingsBySeverity["CRITICAL"], status.FindingsBySeverity)
	}
}
