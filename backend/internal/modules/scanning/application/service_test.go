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
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// Estes testes rodam a lógica de aplicação completa (transação, gravação
// de achados, escrita no outbox) contra o Postgres real e migrado usado em
// todo este backend — pulados se TEST_DATABASE_URL não estiver definida.
// Nenhuma ferramenta de scanning real existe ainda (Fase 1 do roadmap de
// segurança): fakeScanner é o único CodeScanner disponível, controlado
// pelo próprio teste.

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
	outboxWriter := outbox.NewWriter("nix.test")
	return NewService(pool, repo, outboxWriter, nil, testLogger(), scanners...)
}

func TestRunScan_UnknownScanner_ReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.RunScan(context.Background(), "does-not-exist", "target", uuid.New(), nil)
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

	findings, err := svc.RunScan(ctx, "clean-scanner", "example.com", corrID, nil)
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

	got, err := svc.RunScan(ctx, "vuln-scanner", "backend/", corrID, nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %d, want %d", len(got), len(want))
	}

	var scanID uuid.UUID
	var count int
	err = pool.QueryRow(ctx, `SELECT scan_id, count(*) FROM scan_findings WHERE scanner = $1 GROUP BY scan_id ORDER BY scan_id DESC LIMIT 1`, "vuln-scanner").
		Scan(&scanID, &count)
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

	_, err := svc.RunScan(ctx, "broken-scanner", "target", uuid.New(), nil)
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
