package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	"github.com/yurythx/nix-platform/internal/modules/secops/domain"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

type fakeProvider struct {
	name string
	err  error
}

func (f *fakeProvider) Name() string                             { return f.name }
func (f *fakeProvider) TestConnection(ctx context.Context) error { return f.err }
func (f *fakeProvider) AnalyzeTarget(ctx context.Context, target string) (*domain.SecCheckResult, error) {
	return &domain.SecCheckResult{Success: true}, nil
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live secops integration test")
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

func newService(pool *pgxpool.Pool, provider *fakeProvider) *Service {
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	integrationsSvc := integrations.NewService(integrationsInfra.NewPostgresRepository(pool))
	providers := map[string]domain.SecurityProvider{"virustotal": provider}
	return NewService(pool, jobsRepo, outboxWriter, providers, integrationsSvc, nil, testLogger())
}

func resetIntegration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `UPDATE integrations SET status = 'unknown', last_error = NULL WHERE key = 'virustotal'`)
	if err != nil {
		t.Fatalf("reset integration baseline: %v", err)
	}
}

func TestCreateTestJob_RejectsUnknownProvider(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeProvider{name: "virustotal"})

	_, err := svc.CreateTestJob(context.Background(), "shodan", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered provider")
	}
}

func TestProcessJob_Success_CompletesAndUpdatesIntegration(t *testing.T) {
	pool := testPool(t)
	resetIntegration(t, pool)
	svc := newService(pool, &fakeProvider{name: "virustotal"})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, "virustotal", corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}

	if err := svc.ProcessJob(ctx, job.ID, "virustotal", corrID); err != nil {
		t.Fatalf("ProcessJob: %v", err)
	}

	repo := jobs.NewRepository(pool)
	fetched, err := repo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed", fetched.Status)
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM integrations WHERE key = 'virustotal'`).Scan(&status); err != nil {
		t.Fatalf("query integration status: %v", err)
	}
	if status != "online" {
		t.Errorf("integration status = %q, want online", status)
	}
}

func TestHandleDeadLetter_MarksOfflineAfterFailures(t *testing.T) {
	pool := testPool(t)
	resetIntegration(t, pool)
	svc := newService(pool, &fakeProvider{name: "virustotal", err: fmt.Errorf("timeout")})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, "virustotal", corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}
	if err := svc.ProcessJob(ctx, job.ID, "virustotal", corrID); err == nil {
		t.Fatal("expected the fake provider to fail")
	}

	if err := svc.HandleDeadLetter(ctx, job.ID, "virustotal", corrID, "max retries exceeded"); err != nil {
		t.Fatalf("HandleDeadLetter: %v", err)
	}

	repo := jobs.NewRepository(pool)
	fetched, err := repo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusDeadLetter {
		t.Errorf("Status = %s, want dead_letter", fetched.Status)
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM integrations WHERE key = 'virustotal'`).Scan(&status); err != nil {
		t.Fatalf("query integration status: %v", err)
	}
	if status != "offline" {
		t.Errorf("integration status = %q, want offline", status)
	}
}
