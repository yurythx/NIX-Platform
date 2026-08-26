package application

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

type fakeScanner struct {
	name     string
	findings []domain.Finding
	err      error
	// block, quando não nil, faz Execute esperar o canal fechar antes de
	// retornar — só usado pelos testes de progresso EM ANDAMENTO (ver
	// TestProcessScanJob_ScannerRuns_ReflectRunningThenTerminalStatus),
	// pra observar de verdade um scanner com status "running" enquanto
	// outro já terminou, em vez de só inferir isso.
	block <-chan struct{}
}

func (f *fakeScanner) Name() string { return f.name }

func (f *fakeScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if f.block != nil {
		<-f.block
	}
	return f.findings, f.err
}

// fakeLocalScanner é um fakeScanner que também implementa
// domain.LocalScanner (e domain.LocalInventoryProvider) — usado pelos
// testes de Fase 10 (projeto criado por upload .zip), que nunca clonam
// nada, só escaneiam um diretório já extraído. gotDir grava o dir
// recebido por ExecuteLocal, prova de que um diretório de verdade
// (extraído do .zip) foi passado, não um alvo git vazio.
type fakeLocalScanner struct {
	fakeScanner
	gotDir   string
	packages []domain.Package
	// goModContent grava o conteúdo de "go.mod" lido DE DENTRO de
	// ExecuteLocal — precisa acontecer ali, não depois que ProcessScanJob
	// já retornou: o diretório de extração é temporário e some assim que
	// ProcessScanJob termina (mesmo ciclo de vida do clone git), então ler
	// depois sempre daria "no such file or directory", mesmo com a
	// extração tendo funcionado perfeitamente.
	goModContent string
}

func (f *fakeLocalScanner) ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error) {
	f.gotDir = dir
	if content, err := os.ReadFile(dir + "/go.mod"); err == nil {
		f.goModContent = string(content)
	}
	return f.findings, f.err
}

func (f *fakeLocalScanner) InventoryLocal(ctx context.Context, dir string) ([]domain.Package, error) {
	return f.packages, nil
}

var _ domain.LocalScanner = (*fakeLocalScanner)(nil)

var _ domain.LocalInventoryProvider = (*fakeLocalScanner)(nil)

// fakeProgressReportingScanner é um fakeScanner que também implementa
// domain.ProgressReportingScanner (ZapScanner é o único caso real hoje)
// — usado só pelo teste de sub-progresso abaixo, que precisa observar
// ProgressDetail preenchido ENQUANTO o scanner ainda está rodando, daí
// reusar o mesmo campo block de fakeScanner (mesmo padrão de
// TestProcessScanJob_ScannerRuns_ReflectRunningThenTerminalStatus).
type fakeProgressReportingScanner struct {
	fakeScanner
}

func (f *fakeProgressReportingScanner) ExecuteWithProgress(ctx context.Context, target string, report domain.ProgressFunc) ([]domain.Finding, error) {
	report("ataque ativo: 42%")
	if f.block != nil {
		<-f.block
	}
	return f.findings, f.err
}

var _ domain.ProgressReportingScanner = (*fakeProgressReportingScanner)(nil)

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
	return newServiceWithFlags(pool, nil, nil, scanners...)
}

// newServiceWithFlags é a variante completa de newService — usada só
// pelos testes de Fase 13 (filtro de ruído), que precisam de um
// configflags.Store de verdade pra exercitar noiseFilterEnabled.
func newServiceWithFlags(pool *pgxpool.Pool, flags configflags.Store, noiseFilterPatterns []string, scanners ...domain.CodeScanner) *Service {
	repo := infrastructure.NewPostgresRepository(pool)
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	// "" como baseDir do ZipExtractor: mesmo padrão de cloneShallow, cai
	// no diretório temporário padrão do SO — correto pra teste, onde não
	// existe volume compartilhado nenhum de verdade.
	zipExtractor := infrastructure.NewZipExtractor("", testLogger())
	return NewService(pool, repo, jobsRepo, outboxWriter, nil, zipExtractor, flags, noiseFilterPatterns, testLogger(), scanners...)
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

// fakeRepositoryCapturingLimit é um domain.Repository mínimo, sem banco
// nenhum, só pra provar a lógica de clamping de página/tamanho de página
// de ListRecentFindings (ver pagination.New) sem precisar de Postgres —
// SaveFindings/ListByScanID nunca deveriam ser chamados por este
// caminho, então entram em pânico se forem.
type fakeRepositoryCapturingLimit struct {
	gotOffset int
	gotLimit  int
}

func (f *fakeRepositoryCapturingLimit) SaveFindings(context.Context, pgx.Tx, uuid.UUID, string, string, []domain.Finding) error {
	panic("SaveFindings should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListByScanID(context.Context, uuid.UUID) ([]domain.PersistedFinding, error) {
	panic("ListByScanID should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListByScanIDs(context.Context, []uuid.UUID) ([]domain.PersistedFinding, error) {
	panic("ListByScanIDs should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListRecentPage(_ context.Context, offset, limit int) ([]domain.PersistedFinding, int64, error) {
	f.gotOffset = offset
	f.gotLimit = limit
	return nil, 0, nil
}

func (f *fakeRepositoryCapturingLimit) StartScannerRun(context.Context, uuid.UUID, string) error {
	panic("StartScannerRun should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) FinishScannerRun(context.Context, uuid.UUID, string, domain.ScannerRunStatus, int, string) error {
	panic("FinishScannerRun should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) UpdateScannerRunProgress(context.Context, uuid.UUID, string, string) error {
	panic("UpdateScannerRunProgress should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListScannerRuns(context.Context, uuid.UUID) ([]domain.ScannerRun, error) {
	panic("ListScannerRuns should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) CreateProject(context.Context, domain.Project) error {
	panic("CreateProject should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) GetProject(context.Context, uuid.UUID) (domain.Project, error) {
	panic("GetProject should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListProjects(context.Context, int) ([]domain.Project, error) {
	panic("ListProjects should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) SavePackages(context.Context, pgx.Tx, uuid.UUID, []domain.Package) error {
	panic("SavePackages should not be called by ListRecentFindings")
}

func (f *fakeRepositoryCapturingLimit) ListPackagesByScanID(context.Context, uuid.UUID) ([]domain.Package, error) {
	panic("ListPackagesByScanID should not be called by ListRecentFindings")
}

// buildTestZip monta um .zip em memória a partir de um mapa
// nome->conteúdo — mesmo helper de infrastructure/zip_extract_test.go,
// duplicado aqui porque os dois vivem em pacotes Go diferentes
// (application vs. infrastructure) e este teste não deveria importar
// infrastructure só por causa de um helper de teste.
func buildTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

// A partir daqui: Fase 12 — deduplicação de achados por fingerprint entre
// re-scans do MESMO projeto.

// A partir daqui: Fase 13 — filtro de ruído por caminho, gate por feature
// flag. fakeFlags (não o configflags.PostgresStore real): um Store real
// seria overkill pra decidir "habilitada" vs "desabilitada" neste teste,
// e sobretudo evita ligar uma flag GLOBAL na mesma instância de Postgres
// que a stack Docker ao vivo compartilha com TEST_DATABASE_URL — mesmo
// padrão já estabelecido em
// diario_oficial/transport/handlers_test.go's fakeFlags.
type fakeFlags struct{ enabled bool }

func (f fakeFlags) IsEnabled(_ context.Context, _ string, _ bool) (bool, error) {
	return f.enabled, nil
}

func (f fakeFlags) List(_ context.Context) ([]configflags.Flag, error) { return nil, nil }

func (f fakeFlags) Set(_ context.Context, key string, enabled bool, _ string) (configflags.Flag, error) {
	return configflags.Flag{Key: key, Enabled: enabled}, nil
}
