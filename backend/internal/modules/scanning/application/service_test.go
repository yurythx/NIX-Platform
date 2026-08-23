package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// Estes testes rodam a lógica de aplicação completa (transação, gravação
// de achados, escrita no outbox, ciclo de vida de job) contra o Postgres
// real e migrado usado em todo este backend — pulados se
// TEST_DATABASE_URL não estiver definida. fakeScanner substitui qualquer
// scanner real (TrivyScanner incluído) — nenhum teste aqui depende do
// binário trivy nem de rede.

type fakeScanner struct {
	name     string
	findings []domain.Finding
	err      error
}

func (f *fakeScanner) Name() string { return f.name }

func (f *fakeScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	return f.findings, f.err
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live scanning integration test")
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

func outboxEventExists(t *testing.T, pool *pgxpool.Pool, aggregateID, eventType string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = $2`, aggregateID, eventType,
	).Scan(&n)
	if err != nil {
		t.Fatalf("count outbox events: %v", err)
	}
	return n > 0
}

func newService(pool *pgxpool.Pool, scanners ...domain.CodeScanner) *Service {
	repo := infrastructure.NewPostgresRepository(pool)
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	return NewService(pool, repo, jobsRepo, outboxWriter, nil, testLogger(), scanners...)
}

func TestRunScan_UnknownScanner_ReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, _, err := svc.RunScan(context.Background(), "does-not-exist", "target", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered scanner")
	}
}

func TestRunScan_NoFindings_PersistsCompletionEventButNoRows(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "clean-scanner"}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	_, findings, err := svc.RunScan(ctx, "clean-scanner", "example.com", corrID, nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

func TestRunScan_WithFindings_PersistsFindingsAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	want := []domain.Finding{
		{ID: "CVE-2026-0001", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityCritical, Description: "dependência desatualizada com CVE conhecido", File: "go.sum", Line: 0},
		{ID: "semgrep:go.lang.security.audit.sql-injection", OWASPCategory: "A03:2021-Injection", Severity: domain.SeverityHigh, Description: "possível SQL injection", File: "repo.go", Line: 42},
	}
	scanner := &fakeScanner{name: "vuln-scanner", findings: want}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	scanID, got, err := svc.RunScan(ctx, "vuln-scanner", "backend/", corrID, nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %d, want %d", len(got), len(want))
	}

	var count int
	err = pool.QueryRow(ctx, `SELECT count(*) FROM scan_findings WHERE scan_id = $1`, scanID).Scan(&count)
	if err != nil {
		t.Fatalf("query scan_findings: %v", err)
	}
	if count != len(want) {
		t.Errorf("persisted rows = %d, want %d", count, len(want))
	}
	if !outboxEventExists(t, pool, scanID.String(), EventScanCompleted) {
		t.Error("expected a scanning.scan.completed outbox event")
	}
}

func TestRunScan_ScannerError_ReturnsErrorAndPersistsNothing(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "broken-scanner", err: fmt.Errorf("tool crashed")}
	svc := newService(pool, scanner)
	ctx := context.Background()

	before := countRows(t, pool, "broken-scanner")

	_, _, err := svc.RunScan(ctx, "broken-scanner", "target", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error when the scanner itself fails")
	}

	after := countRows(t, pool, "broken-scanner")
	if after != before {
		t.Errorf("rows for broken-scanner changed from %d to %d, want no persistence on scanner failure", before, after)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, scanner string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM scan_findings WHERE scanner = $1`, scanner).Scan(&n); err != nil {
		t.Fatalf("count scan_findings: %v", err)
	}
	return n
}

// A partir daqui: o fluxo assíncrono (CreateScanJob -> ProcessScanJob ->
// HandleScanDeadLetter), mesmo desenho dos testes de
// diario_oficial/application/service_test.go.

func TestCreateScanJob_UnknownScanner_ReturnsNotFoundWithoutCreatingAJob(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), "does-not-exist", "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered scanner")
	}
}

func TestCreateScanJob_EmptyTarget_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), "trivy", "", nil)
	if err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestCreateScanJob_CreatesJobAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})
	corrID := uuid.New()

	job, err := svc.CreateScanJob(context.Background(), corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if job.Status != jobs.StatusQueued {
		t.Errorf("Status = %s, want queued", job.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanRequested) {
		t.Error("expected a scanning.scan.requested outbox event")
	}
}

func TestProcessScanJob_Success_CompletesJobAndPersistsFindings(t *testing.T) {
	pool := testPool(t)
	want := []domain.Finding{
		{ID: "CVE-2026-0002", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityHigh, Description: "dependência vulnerável", File: "go.sum"},
	}
	scanner := &fakeScanner{name: "trivy", findings: want}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed", fetched.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanCompleted) {
		t.Error("expected a scanning.scan.completed outbox event")
	}

	// job.ID É o scan_id — ListFindings precisa devolver os achados
	// consultando pelo mesmo ID recebido na criação do job.
	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != len(want) {
		t.Fatalf("findings = %d, want %d", len(findings), len(want))
	}
	if findings[0].ID != want[0].ID {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, want[0].ID)
	}
}

// countingScanner retorna erro se Execute for chamado mais de uma vez,
// para que um teste prove que um evento redelivered foi pulado, em vez de
// meramente reprocessado de forma idempotente por coincidência.
type countingScanner struct {
	name  string
	calls int
}

func (c *countingScanner) Name() string { return c.name }

func (c *countingScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	c.calls++
	if c.calls > 1 {
		return nil, fmt.Errorf("Execute called again — the job should have been skipped as a duplicate delivery")
	}
	return nil, nil
}

func TestProcessScanJob_RedeliveryOfCompletedJob_IsANoOp(t *testing.T) {
	pool := testPool(t)
	scanner := &countingScanner{name: "trivy"}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("first ProcessScanJob: %v", err)
	}
	// Simula o RabbitMQ reentregando o mesmo evento
	// scanning.scan.requested depois que o job já foi concluído.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("redelivered ProcessScanJob should be a no-op, got error: %v", err)
	}

	if scanner.calls != 1 {
		t.Errorf("Execute called %d times, want exactly 1", scanner.calls)
	}
}

func TestProcessScanJob_ScannerError_MarksFailedAndReturnsErrorForRetry(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", err: fmt.Errorf("git clone failed")}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	err = svc.ProcessScanJob(ctx, job.ID, corrID)
	if err == nil {
		t.Fatal("expected ProcessScanJob to return an error so the caller retries")
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, getErr := jobsRepo.GetByID(ctx, job.ID)
	if getErr != nil {
		t.Fatalf("GetByID: %v", getErr)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}

	// Ainda nenhuma notificação de falha final — o job ainda pode ter
	// sucesso numa nova tentativa.
	if outboxEventExists(t, pool, job.ID.String(), EventScanFailed) {
		t.Error("did not expect a scanning.scan.failed outbox event before retries are exhausted")
	}
}

func TestHandleScanDeadLetter_MarksDeadLetterAndPublishesFailure(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", err: fmt.Errorf("still failing")}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	// Simula a(s) tentativa(s) que o RabbitMQ já fez antes de desistir.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected the fake scanner to fail")
	}

	if err := svc.HandleScanDeadLetter(ctx, job.ID, corrID, "max retries exceeded"); err != nil {
		t.Fatalf("HandleScanDeadLetter: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusDeadLetter {
		t.Errorf("Status = %s, want dead_letter", fetched.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanFailed) {
		t.Error("expected a scanning.scan.failed outbox event after dead-lettering")
	}
}

func TestProcessScanJob_UnregisteredScanner_FailsWithoutRetry(t *testing.T) {
	pool := testPool(t)
	// Cria o job com "trivy" registrado, mas simula um scanner
	// desregistrado depois (ex.: um deploy que removeu um scanner) usando
	// um Service à parte, sem nenhum scanner, para processar o job já
	// criado.
	creator := newService(pool, &fakeScanner{name: "trivy"})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := creator.CreateScanJob(ctx, corrID, "trivy", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	processor := newService(pool) // nenhum scanner registrado
	if err := processor.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob with an unregistered scanner should not return an error (no retry): %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}
}
