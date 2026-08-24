package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// application.Service é transacional de verdade (job + evento de outbox
// gravados atomicamente) e recebe um *pgxpool.Pool diretamente — mesma
// justificativa de diario_oficial/transport/handlers_test.go: este teste
// roda contra o Postgres real usado por todo este backend, pulando se
// TEST_DATABASE_URL não estiver definida. Só o CodeScanner em si é fake.

type fakeScanner struct {
	name     string
	findings []domain.Finding
	err      error
}

func (f *fakeScanner) Name() string { return f.name }

func (f *fakeScanner) Execute(_ context.Context, _ string) ([]domain.Finding, error) {
	return f.findings, f.err
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live scanning transport test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestService(pool *pgxpool.Pool, scanners ...domain.CodeScanner) *application.Service {
	repo := infrastructure.NewPostgresRepository(pool)
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	return application.NewService(pool, repo, jobsRepo, outboxWriter, nil, testLogger(), scanners...)
}

func decodeEnvelope[T any](t *testing.T, body []byte) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response envelope: %v, body=%s", err, body)
	}
	return env.Data
}

func TestCreateScan_ValidRequest_Returns202(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, &fakeScanner{name: "trivy"}), testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy"}, Target: "https://example.com/repo.git"})
	r := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.CreateScan(rec, r)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[scanJobResponse](t, rec.Body.Bytes())
	if got.JobID == "" {
		t.Error("expected a non-empty job_id")
	}
	if got.Status != string(jobs.StatusQueued) {
		t.Errorf("Status = %q, want %q", got.Status, jobs.StatusQueued)
	}
}

func TestCreateScan_UnknownScanner_Returns404(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger()) // nenhum scanner registrado

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"does-not-exist"}, Target: "https://example.com/repo.git"})
	r := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.CreateScan(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestCreateScan_MultipleScanners_RunConcurrentlyAndAggregateFindings(t *testing.T) {
	pool := testPool(t)
	trivy := &fakeScanner{name: "trivy", findings: []domain.Finding{{ID: "CVE-1", Severity: domain.SeverityHigh, Description: "trivy achou algo"}}}
	semgrep := &fakeScanner{name: "semgrep", findings: []domain.Finding{{ID: "rule-1", Severity: domain.SeverityMedium, Description: "semgrep achou algo"}}}
	svc := newTestService(pool, trivy, semgrep)
	h := NewHandlers(svc, testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy", "semgrep"}, Target: "https://example.com/repo.git"})
	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
	createRec := httptest.NewRecorder()
	h.CreateScan(createRec, createReq)
	if createRec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", createRec.Code, createRec.Body.String())
	}
	job := decodeEnvelope[scanJobResponse](t, createRec.Body.Bytes())

	jobID, err := uuid.Parse(job.JobID)
	if err != nil {
		t.Fatalf("parse job id: %v", err)
	}
	if err := svc.ProcessScanJob(context.Background(), jobID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+job.JobID+"/findings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", job.JobID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.ListFindings(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"scanner":"trivy"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"scanner":"semgrep"`)) {
		t.Errorf("response should contain findings from both scanners, got: %s", rec.Body.String())
	}
}

func TestListFindings_InvalidScanID_Returns400(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/not-a-uuid/findings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ListFindings(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestListFindings_KnownScan_ReturnsSnakeCaseFields(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{
		{ID: "CVE-2026-0003", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityHigh, Description: "achado de teste", File: "go.sum"},
	}}
	svc := newTestService(pool, scanner)
	h := NewHandlers(svc, testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy"}, Target: "https://example.com/repo.git"})
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

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+job.JobID+"/findings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", job.JobID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.ListFindings(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"finding_id":"CVE-2026-0003"`)) {
		t.Errorf("response body missing snake_case finding_id field, got: %s", rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"RecordID"`)) || bytes.Contains(rec.Body.Bytes(), []byte(`"OWASPCategory"`)) {
		t.Errorf("response body leaked a PascalCase Go field name, got: %s", rec.Body.String())
	}
}

func TestListRecentFindings_IncludesJustCreatedFinding(t *testing.T) {
	pool := testPool(t)
	const marker = "recent-findings-handler-marker"
	scanner := &fakeScanner{name: marker, findings: []domain.Finding{
		{ID: "HANDLER-MARKER-1", Severity: domain.SeverityHigh, Description: "achado do teste do handler"},
	}}
	svc := newTestService(pool, scanner)
	h := NewHandlers(svc, testLogger())

	if _, _, err := svc.RunScan(context.Background(), marker, "target", uuid.New(), nil); err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/scanning/findings?limit=200", nil)
	rec := httptest.NewRecorder()
	h.ListRecentFindings(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"finding_id":"HANDLER-MARKER-1"`)) {
		t.Errorf("response should include the finding just created, got: %s", rec.Body.String())
	}
}

func TestListRecentFindings_InvalidLimit_FallsBackToDefaultInsteadOfErroring(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/scanning/findings?limit=not-a-number", nil)
	rec := httptest.NewRecorder()
	h.ListRecentFindings(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (an unparseable limit should fall back to the default, not fail the request)", rec.Code)
	}
}
