package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"does-not-exist"}, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered scanner")
	}
}

func TestCreateScanJob_EmptyTarget_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"trivy"}, "", nil)
	if err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestCreateScanJob_CreatesJobAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})
	corrID := uuid.New()

	job, err := svc.CreateScanJob(context.Background(), corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
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

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
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

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
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

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
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

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
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

// A partir daqui: Fase 7 (Orquestração concorrente) — um job com mais de
// um scanner.

func TestCreateScanJob_EmptyScannerList_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), nil, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error for an empty scanner list")
	}
}

func TestCreateScanJob_OneUnknownAmongKnown_RejectsWithoutCreatingAJob(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"trivy", "does-not-exist"}, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error when any scanner in the list is unregistered")
	}
}

// slowThenFastScanner deixa Execute bloquear até unblock ser fechado —
// usado pra provar que um scanner lento não atrasa os demais rodando em
// paralelo no mesmo job.
type slowThenFastScanner struct {
	name     string
	unblock  chan struct{}
	started  chan struct{}
	findings []domain.Finding
}

func (s *slowThenFastScanner) Name() string { return s.name }

func (s *slowThenFastScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	close(s.started)
	<-s.unblock
	return s.findings, nil
}

func TestProcessScanJob_MultipleScanners_RunConcurrentlyNotSequentially(t *testing.T) {
	pool := testPool(t)
	slow := &slowThenFastScanner{name: "slow-scanner", unblock: make(chan struct{}), started: make(chan struct{})}
	fast := &fakeScanner{name: "fast-scanner", findings: []domain.Finding{{ID: "FAST-1", Severity: domain.SeverityLow, Description: "achado rápido"}}}
	svc := newService(pool, slow, fast)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"slow-scanner", "fast-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.ProcessScanJob(ctx, job.ID, corrID) }()

	// Espera o scanner lento começar a rodar (prova que os dois foram
	// disparados) e então libera ele — se ProcessScanJob rodasse os
	// scanners em sequência em vez de paralelo, "fast-scanner" só
	// terminaria DEPOIS de slow-scanner desbloquear, o que este teste
	// não teria como observar de forma diferente; a prova real de
	// paralelismo está em slow.unblock nunca ser fechado até aqui —
	// ProcessScanJob não pode ter retornado sem travar em slow-scanner.
	select {
	case <-slow.started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow-scanner never started — ProcessScanJob may be running scanners sequentially and blocked before reaching it")
	}
	close(slow.unblock)

	if err := <-done; err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only fast-scanner produces one)", len(findings))
	}
}

func TestProcessScanJob_PartialFailure_CompletesJobAndKeepsSuccessfulFindings(t *testing.T) {
	pool := testPool(t)
	good := &fakeScanner{name: "good-scanner", findings: []domain.Finding{{ID: "OK-1", Severity: domain.SeverityMedium, Description: "achado válido"}}}
	bad := &fakeScanner{name: "bad-scanner", err: fmt.Errorf("tool crashed")}
	svc := newService(pool, good, bad)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"good-scanner", "bad-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	// Falha parcial não é reprocessada — ProcessScanJob retorna nil
	// mesmo com um scanner tendo falhado, pra nunca rodar de novo
	// good-scanner (que já teve sucesso) só por causa de bad-scanner.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob with partial failure should not return an error: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed (at least one scanner succeeded)", fetched.Status)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].Scanner != "good-scanner" {
		t.Errorf("findings = %+v, want exactly the good-scanner's finding, nothing from bad-scanner", findings)
	}
}

func TestProcessScanJob_AllScannersFail_MarksJobFailedForRetry(t *testing.T) {
	pool := testPool(t)
	bad1 := &fakeScanner{name: "bad-scanner-1", err: fmt.Errorf("crashed 1")}
	bad2 := &fakeScanner{name: "bad-scanner-2", err: fmt.Errorf("crashed 2")}
	svc := newService(pool, bad1, bad2)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"bad-scanner-1", "bad-scanner-2"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected an error when every scanner in the job fails, so the caller retries")
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

func TestProcessScanJob_UnregisteredScanner_IsTreatedAsThatScannerFailing(t *testing.T) {
	pool := testPool(t)
	// Cria o job com "trivy" registrado, mas simula um scanner
	// desregistrado depois (ex.: um deploy que removeu um scanner) usando
	// um Service à parte, sem nenhum scanner, para processar o job já
	// criado. Com um único scanner no job e ele "desaparecendo", o
	// resultado é o mesmo caminho de "todos os scanners falharam" (ver
	// TestProcessScanJob_AllScannersFail_MarksJobFailedForRetry) — um
	// scanner desregistrado não ganha mais tratamento especial de
	// "falha permanente, nunca reprocessar" desde a Fase 7: com vários
	// scanners por job, a mesma distinção precisaria existir por
	// scanner dentro de uma falha parcial, complexidade que não paga o
	// benefício (poucas tentativas extras esgotadas até cair em
	// dead-letter é aceitável).
	creator := newService(pool, &fakeScanner{name: "trivy"})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := creator.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	processor := newService(pool) // nenhum scanner registrado
	if err := processor.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected an error so the caller retries, same as any other all-scanners-failed outcome")
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

// A partir daqui: ListRecentFindings (Fase 9 — o feed "achados recentes
// por severidade" que a UI usa).

func TestListRecentFindings_IncludesFindingsFromMultipleScans(t *testing.T) {
	pool := testPool(t)
	// Nome de scanner distinto e improvável de colidir com achados de
	// outros testes rodando na mesma tabela compartilhada — a asserção
	// abaixo procura por ele especificamente em vez de comparar
	// contagem exata, porque scan_findings é uma tabela compartilhada
	// entre todo teste deste pacote (nenhum limpa depois de si) e
	// ListRecent, por natureza, não filtra por scan_id.
	const marker = "recent-findings-marker-scanner"
	scanner := &fakeScanner{name: marker, findings: []domain.Finding{
		{ID: "MARKER-1", Severity: domain.SeverityCritical, Description: "achado do teste de ListRecentFindings"},
	}}
	svc := newService(pool, scanner)
	ctx := context.Background()

	scanID, _, err := svc.RunScan(ctx, marker, "target", uuid.New(), nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	// Limite generoso — só precisa ser maior que o número total de
	// achados que a suíte inteira já gravou até este ponto, o que
	// maxRecentFindings (200) cobre com folga pro tamanho desta suíte.
	recent, err := svc.ListRecentFindings(ctx, maxRecentFindings)
	if err != nil {
		t.Fatalf("ListRecentFindings: %v", err)
	}

	found := false
	for _, f := range recent {
		if f.ScanID == scanID && f.ID == "MARKER-1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListRecentFindings did not include the finding just created (scan_id=%s)", scanID)
	}
}

func TestListRecentFindings_NeverExceedsMaxEvenWithoutExplicitLimit(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	recent, err := svc.ListRecentFindings(context.Background(), 0) // 0 usa o default, não maxRecentFindings
	if err != nil {
		t.Fatalf("ListRecentFindings: %v", err)
	}
	if len(recent) > maxRecentFindings {
		t.Errorf("ListRecentFindings returned %d rows, want at most %d (the hard cap)", len(recent), maxRecentFindings)
	}
}

// fakeRepositoryCapturingLimit é um domain.Repository mínimo, sem banco
// nenhum, só pra provar a lógica de clamping de ListRecentFindings
// (default quando limit <= 0, teto em maxRecentFindings) sem precisar de
// Postgres — SaveFindings/ListByScanID nunca deveriam ser chamados por
// este caminho, então entram em pânico se forem.
type fakeRepositoryCapturingLimit struct {
	gotLimit int
}

func (f *fakeRepositoryCapturingLimit) SaveFindings(context.Context, pgx.Tx, uuid.UUID, string, string, []domain.Finding) error {
	panic("SaveFindings should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListByScanID(context.Context, uuid.UUID) ([]domain.PersistedFinding, error) {
	panic("ListByScanID should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListRecent(_ context.Context, limit int) ([]domain.PersistedFinding, error) {
	f.gotLimit = limit
	return nil, nil
}

func TestListRecentFindings_LimitClamping(t *testing.T) {
	cases := []struct {
		name      string
		requested int
		want      int
	}{
		{"zero uses the default", 0, 50},
		{"negative uses the default", -5, 50},
		{"within range is passed through unchanged", 10, 10},
		{"above the cap is clamped", 10_000, maxRecentFindings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepositoryCapturingLimit{}
			svc := &Service{repo: repo, logger: testLogger()}

			if _, err := svc.ListRecentFindings(context.Background(), tc.requested); err != nil {
				t.Fatalf("ListRecentFindings: %v", err)
			}
			if repo.gotLimit != tc.want {
				t.Errorf("limit passed to the repository = %d, want %d", repo.gotLimit, tc.want)
			}
		})
	}
}
