package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// Estes testes rodam a lógica de aplicação completa do módulo
// (transações, transições de status, escritas no outbox) contra o
// Postgres real e migrado usado em todo este backend — pulados se
// TEST_DATABASE_URL não estiver definida. Só a chamada externa ao Diário
// Oficial em si é falsa (fake), via domain.Client, para que o teste
// controle sucesso/falha de forma determinística.

type fakeClient struct {
	result *domain.CheckResult
	err    error
}

func (f *fakeClient) Check(ctx context.Context) (*domain.CheckResult, error) {
	return f.result, f.err
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live diario_oficial integration test")
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

func resetIntegration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `UPDATE integrations SET status = 'unknown', last_error = NULL WHERE key = 'diario-oficial'`)
	if err != nil {
		t.Fatalf("reset integration baseline: %v", err)
	}
}

func newService(pool *pgxpool.Pool, client domain.Client) *Service {
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	integrationsSvc := integrations.NewService(integrationsInfra.NewPostgresRepository(pool))
	return NewService(pool, jobsRepo, outboxWriter, client, integrationsSvc, nil, testLogger())
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

func TestCreateTestJob_CreatesJobAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeClient{})
	corrID := uuid.New()

	job, err := svc.CreateTestJob(context.Background(), corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}
	if job.Status != jobs.StatusQueued {
		t.Errorf("Status = %s, want queued", job.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventJobCreated) {
		t.Error("expected a diario_oficial.job.created outbox event")
	}
}

func TestProcessJob_Success_CompletesJobAndPublishesEvent(t *testing.T) {
	pool := testPool(t)
	resetIntegration(t, pool)
	svc := newService(pool, &fakeClient{result: &domain.CheckResult{StatusCode: 200, Summary: "ok"}})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}

	if err := svc.ProcessJob(ctx, job.ID, corrID); err != nil {
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
	if !outboxEventExists(t, pool, job.ID.String(), EventJobCompleted) {
		t.Error("expected a diario_oficial.job.completed outbox event")
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM integrations WHERE key = 'diario-oficial'`).Scan(&status); err != nil {
		t.Fatalf("query integration status: %v", err)
	}
	if status != "online" {
		t.Errorf("integration status = %q, want online", status)
	}
}

// countingClient retorna erro se Check for chamado mais de uma vez, para
// que um teste possa provar que um evento redelivered foi pulado, em vez
// de meramente reprocessado de forma idempotente por coincidência.
type countingClient struct {
	calls int
}

func (c *countingClient) Check(ctx context.Context) (*domain.CheckResult, error) {
	c.calls++
	if c.calls > 1 {
		return nil, fmt.Errorf("Check called again — the job should have been skipped as a duplicate delivery")
	}
	return &domain.CheckResult{StatusCode: 200, Summary: "ok"}, nil
}

func TestProcessJob_RedeliveryOfCompletedJob_IsANoOp(t *testing.T) {
	pool := testPool(t)
	resetIntegration(t, pool)
	client := &countingClient{}
	svc := newService(pool, client)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}

	if err := svc.ProcessJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("first ProcessJob: %v", err)
	}

	// Simula o RabbitMQ reentregando o mesmo evento
	// diario_oficial.job.created depois que o job já foi concluído.
	if err := svc.ProcessJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("redelivered ProcessJob should be a no-op, got error: %v", err)
	}

	if client.calls != 1 {
		t.Errorf("external Check called %d times, want exactly 1", client.calls)
	}

	repo := jobs.NewRepository(pool)
	fetched, err := repo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed (unchanged by the redelivery)", fetched.Status)
	}
}

func TestProcessJob_Failure_MarksFailedAndReturnsErrorForRetry(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeClient{err: fmt.Errorf("connection refused")})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}

	err = svc.ProcessJob(ctx, job.ID, corrID)
	if err == nil {
		t.Fatal("expected ProcessJob to return an error so the caller retries")
	}

	repo := jobs.NewRepository(pool)
	fetched, getErr := repo.GetByID(ctx, job.ID)
	if getErr != nil {
		t.Fatalf("GetByID: %v", getErr)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}

	// Ainda nenhuma notificação de conclusão/falha — o job ainda pode ter
	// sucesso numa nova tentativa.
	if outboxEventExists(t, pool, job.ID.String(), EventJobFailed) {
		t.Error("did not expect a job.failed outbox event before retries are exhausted")
	}
}

func TestHandleDeadLetter_MarksDeadLetterAndPublishesFailure(t *testing.T) {
	pool := testPool(t)
	resetIntegration(t, pool)
	svc := newService(pool, &fakeClient{err: fmt.Errorf("still down")})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateTestJob(ctx, corrID, nil)
	if err != nil {
		t.Fatalf("CreateTestJob: %v", err)
	}
	// Simula a(s) tentativa(s) que o RabbitMQ já fez antes de desistir.
	if err := svc.ProcessJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected the fake client to fail")
	}

	if err := svc.HandleDeadLetter(ctx, job.ID, corrID, "max retries exceeded"); err != nil {
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
	if !outboxEventExists(t, pool, job.ID.String(), EventJobFailed) {
		t.Error("expected a diario_oficial.job.failed outbox event after dead-lettering")
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM integrations WHERE key = 'diario-oficial'`).Scan(&status); err != nil {
		t.Fatalf("query integration status: %v", err)
	}
	if status != "offline" {
		t.Errorf("integration status = %q, want offline", status)
	}
}
