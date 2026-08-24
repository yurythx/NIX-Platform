package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
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

// A partir daqui: GetScanStatus — a resposta ao pedido do usuário de
// saber "qual ferramenta achou o erro" e "que tipo de erro/como
// corrigir" pra um scan que falhou, algo que antes só existia no log do
// worker.

func TestGetScanStatus_InvalidScanID_Returns400(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.GetScanStatus(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestGetScanStatus_UnknownScanID_Returns404(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger())

	unknown := uuid.New().String()
	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+unknown, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", unknown)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.GetScanStatus(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func getScanStatus(t *testing.T, h *Handlers, jobID string) ScanStatusResponse {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/scanning/scans/"+jobID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", jobID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	h.GetScanStatus(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	return decodeEnvelope[ScanStatusResponse](t, rec.Body.Bytes())
}

// Reproduz o bug real que motivou GetScanStatus: um alvo cujo git clone
// falha (mesma forma de erro confirmada contra o binário git de verdade
// nesta sessão — motivo em "fatal: ...", não na primeira linha de
// stderr) precisa aparecer com o scanner certo, o Code certo
// (DEPENDENCY_UNAVAILABLE) e um Hint que não seja o genérico — a
// mensagem bate no case "git clone failed" de remediationHint.
func TestGetScanStatus_PartialFailure_IncludesScannerAndHint(t *testing.T) {
	pool := testPool(t)
	ok := &fakeScanner{name: "trivy", findings: []domain.Finding{{ID: "CVE-1", Severity: domain.SeverityHigh, Description: "achado real"}}}
	broken := &fakeScanner{name: "semgrep", err: apperrors.DependencyUnavailable(
		"scanning: git clone failed: fatal: could not read Username for 'https://github.com': No such device or address")}
	svc := newTestService(pool, ok, broken)
	h := NewHandlers(svc, testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy", "semgrep"}, Target: "https://example.com/repo.git"})
	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
	createRec := httptest.NewRecorder()
	h.CreateScan(createRec, createReq)
	job := decodeEnvelope[scanJobResponse](t, createRec.Body.Bytes())

	jobID, err := uuid.Parse(job.JobID)
	if err != nil {
		t.Fatalf("parse job id: %v", err)
	}
	if err := svc.ProcessScanJob(context.Background(), jobID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob (partial failure should not return an error): %v", err)
	}

	status := getScanStatus(t, h, job.JobID)
	if status.Status != "completed" {
		t.Errorf("Status = %q, want completed (partial failure still completes the job)", status.Status)
	}
	if len(status.SucceededScanners) != 1 || status.SucceededScanners[0] != "trivy" {
		t.Errorf("SucceededScanners = %v, want [trivy]", status.SucceededScanners)
	}
	if len(status.FailedScanners) != 1 {
		t.Fatalf("FailedScanners = %v, want exactly 1 entry", status.FailedScanners)
	}
	got := status.FailedScanners[0]
	if got.Scanner != "semgrep" {
		t.Errorf("FailedScanners[0].Scanner = %q, want semgrep", got.Scanner)
	}
	if got.Code != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("FailedScanners[0].Code = %q, want DEPENDENCY_UNAVAILABLE", got.Code)
	}
	if !bytes.Contains([]byte(got.Message), []byte("fatal: could not read Username")) {
		t.Errorf("FailedScanners[0].Message = %q, want it to contain the real git error", got.Message)
	}
	if !bytes.Contains([]byte(got.Hint), []byte("autenticação")) {
		t.Errorf("FailedScanners[0].Hint = %q, want the credential-specific hint, not the generic fallback", got.Hint)
	}

	// O job já terminou (completed) — os dois scanners pedidos devem
	// aparecer em ScannerRuns com status terminal, e o progresso deve
	// estar em 100% (nenhum ainda "running").
	if status.ProgressPercent != 100 {
		t.Errorf("ProgressPercent = %d, want 100 (job already completed)", status.ProgressPercent)
	}
	if len(status.ScannerRuns) != 2 {
		t.Fatalf("ScannerRuns = %+v, want an entry for each of the 2 requested scanners", status.ScannerRuns)
	}
	for _, run := range status.ScannerRuns {
		if run.Status == "running" {
			t.Errorf("ScannerRuns has %q still \"running\" after the job completed", run.Scanner)
		}
		if run.DurationMs == nil {
			t.Errorf("ScannerRuns[%q].DurationMs = nil, want set once a scanner has a FinishedAt", run.Scanner)
		}
	}
}

// Quando TODOS os scanners falham, o job vira dead_letter só depois de
// esgotar os retries — este teste simula isso chamando
// HandleScanDeadLetter diretamente (mesmo padrão de
// application/service_test.go), e confirma que GetScanStatus consegue
// decodificar o motivo estruturado de volta, não só o texto genérico
// "max retries exceeded" que HandleScanDeadLetter gravava antes da
// correção.
func TestGetScanStatus_DeadLetter_PreservesRealFailureReason(t *testing.T) {
	pool := testPool(t)
	broken := &fakeScanner{name: "zap", err: apperrors.DependencyUnavailable(
		"zap: no hosts are allowlisted (SCANNING_ZAP_ALLOWED_HOSTS is empty) — refusing to scan any target")}
	svc := newTestService(pool, broken)
	h := NewHandlers(svc, testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"zap"}, Target: "https://example.com"})
	createReq := httptest.NewRequest(http.MethodPost, "/scanning/scans", bytes.NewReader(body))
	createRec := httptest.NewRecorder()
	h.CreateScan(createRec, createReq)
	job := decodeEnvelope[scanJobResponse](t, createRec.Body.Bytes())

	jobID, err := uuid.Parse(job.JobID)
	if err != nil {
		t.Fatalf("parse job id: %v", err)
	}
	if err := svc.ProcessScanJob(context.Background(), jobID, uuid.New()); err == nil {
		t.Fatal("expected ProcessScanJob to fail when the only scanner fails")
	}
	if err := svc.HandleScanDeadLetter(context.Background(), jobID, uuid.New()); err != nil {
		t.Fatalf("HandleScanDeadLetter: %v", err)
	}

	status := getScanStatus(t, h, job.JobID)
	if status.Status != "dead_letter" {
		t.Errorf("Status = %q, want dead_letter", status.Status)
	}
	if len(status.FailedScanners) != 1 {
		t.Fatalf("FailedScanners = %v, want exactly 1 entry", status.FailedScanners)
	}
	got := status.FailedScanners[0]
	if got.Scanner != "zap" || got.Code != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("FailedScanners[0] = %+v, want scanner=zap code=DEPENDENCY_UNAVAILABLE", got)
	}
	if !bytes.Contains([]byte(got.Hint), []byte("SCANNING_ZAP_ALLOWED_HOSTS")) {
		t.Errorf("FailedScanners[0].Hint = %q, want the allowlist-specific hint", got.Hint)
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

// A partir daqui: ListScans — "resultados separados por scan" (pedido do
// usuário), a lista de execuções recentes que /seguranca usa em vez de
// só o feed de achados de ListRecentFindings, que mistura todo scan
// junto.

func TestListScans_IncludesJustCreatedScan(t *testing.T) {
	pool := testPool(t)
	const marker = "https://example.com/list-scans-handler-marker.git"
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{{ID: "OK-1", Severity: domain.SeverityLow}}}
	svc := newTestService(pool, scanner)
	h := NewHandlers(svc, testLogger())

	body, _ := json.Marshal(createScanRequest{Scanners: []string{"trivy"}, Target: marker})
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

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans?limit=100", nil)
	rec := httptest.NewRecorder()
	h.ListScans(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	scans := decodeEnvelope[[]ScanStatusResponse](t, rec.Body.Bytes())
	found := false
	for _, s := range scans {
		if s.JobID != job.JobID {
			continue
		}
		found = true
		if s.Target != marker {
			t.Errorf("Target = %q, want %q", s.Target, marker)
		}
		if s.Status != "completed" {
			t.Errorf("Status = %q, want completed", s.Status)
		}
	}
	if !found {
		t.Errorf("ListScans response did not include the scan just created (job_id=%s)", job.JobID)
	}
}

func TestListScans_InvalidLimit_FallsBackToDefaultInsteadOfErroring(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool), testLogger())

	r := httptest.NewRequest(http.MethodGet, "/scanning/scans?limit=not-a-number", nil)
	rec := httptest.NewRecorder()
	h.ListScans(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (an unparseable limit should fall back to the default, not fail the request)", rec.Code)
	}
}

// scanProgressPercent não precisa de Postgres nenhum — testes puros
// sobre a struct em memória.

func TestScanProgressPercent_TerminalStatusIsAlways100EvenWithoutScannerRuns(t *testing.T) {
	// Reproduz o caso real encontrado com dados de verdade deste
	// ambiente: um job completado ANTES da tabela
	// scanning_scanner_runs existir (migration 000016) não tem nenhuma
	// linha de progresso granular — sem este caso especial, apareceria
	// travado em 0% pra sempre, mesmo já tendo terminado há muito tempo.
	for _, status := range []string{"completed", "failed", "dead_letter"} {
		t.Run(status, func(t *testing.T) {
			s := &application.ScanStatus{
				Status:            status,
				RequestedScanners: []string{"trivy", "zap"},
				ScannerRuns:       nil,
			}
			if got := toScanStatusResponse(s).ProgressPercent; got != 100 {
				t.Errorf("ProgressPercent = %d, want 100 for a terminal status even without ScannerRuns rows", got)
			}
		})
	}
}

func TestScanProgressPercent_InProgress_ReflectsFinishedScannerRuns(t *testing.T) {
	s := &application.ScanStatus{
		Status:            "processing",
		RequestedScanners: []string{"trivy", "semgrep", "zap"},
		ScannerRuns: []domain.ScannerRun{
			{Scanner: "trivy", Status: domain.ScannerRunSucceeded},
			{Scanner: "semgrep", Status: domain.ScannerRunRunning},
			// zap ainda nem começou a rodar — nenhuma linha ainda, nem
			// "running".
		},
	}
	if got := toScanStatusResponse(s).ProgressPercent; got != 33 {
		t.Errorf("ProgressPercent = %d, want 33 (1 of the 3 requested scanners has a terminal status)", got)
	}
}

// Reproduz o crash real relatado pelo usuário ("não consegui nem acessar
// a página"): application.ScanStatus com RequestedScanners/
// SucceededScanners nil (jobs de scan de antes da Fase 7, sem a chave
// "scanners" no payload) serializava como JSON `null` pra esses campos —
// o frontend, que assume sempre lista (nunca null) em todo campo de
// array desta API, quebrava com "Cannot read properties of null
// (reading 'join')". toScanStatusResponse precisa SEMPRE devolver `[]`,
// nunca `null`, pra qualquer campo de lista, mesmo partindo de um
// application.ScanStatus com slices nil.
func TestToScanStatusResponse_NeverSerializesNullForListFields(t *testing.T) {
	s := &application.ScanStatus{
		Status:            "completed",
		RequestedScanners: nil,
		SucceededScanners: nil,
		FailedScanners:    nil,
		ScannerRuns:       nil,
	}

	data, err := json.Marshal(toScanStatusResponse(s))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	body := string(data)
	for _, field := range []string{"requested_scanners", "succeeded_scanners", "failed_scanners", "scanner_runs"} {
		if strings.Contains(body, `"`+field+`":null`) {
			t.Errorf("response serialized %q as null, want an empty array: %s", field, body)
		}
	}
}
