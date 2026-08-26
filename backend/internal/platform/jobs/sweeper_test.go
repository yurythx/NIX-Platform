// Testes de sweeper.go — rodam contra o Postgres real usado por todo
// este backend, pulando se TEST_DATABASE_URL não estiver definida (mesmo
// padrão de jobs_test.go).
package jobs

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// createStaleJob cria um job, o transiciona pra "processing" (mesmo
// caminho que um worker real usa), e então reescreve started_at
// diretamente pra simular quanto tempo atrás ele "começou" — sem isso,
// started_at sempre seria "agora" (MarkProcessing faz
// COALESCE(started_at, now())), impossível de testar staleness sem
// esperar de verdade.
func createStaleJob(t *testing.T, pool *pgxpool.Pool, jobType string, startedAgo time.Duration) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	repo := NewRepository(pool)

	job, err := New(jobType, uuid.New(), struct{}{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := repo.Create(ctx, tx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.MarkProcessing(ctx, tx, job.ID); err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE jobs SET started_at = now() - $2::interval WHERE id = $1`, job.ID, startedAgo.String()); err != nil {
		t.Fatalf("backdate started_at: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE id = $1`, job.ID)
	})
	return job.ID
}

func TestSweepOnce_CallsHandlerForStaleProcessingJob(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const jobType = "test.stale.sweep.hit"
	staleID := createStaleJob(t, pool, jobType, 2*time.Hour)

	var gotID, gotCorrID uuid.UUID
	var gotReason string
	calls := 0
	handlers := map[string]StaleJobHandler{
		jobType: func(_ context.Context, jobID, correlationID uuid.UUID, reason string) error {
			calls++
			gotID, gotCorrID, gotReason = jobID, correlationID, reason
			return nil
		},
	}

	sweepOnce(ctx, pool, handlers, time.Hour, testLogger())

	if calls != 1 {
		t.Fatalf("handler called %d times, want 1", calls)
	}
	if gotID != staleID {
		t.Errorf("handler jobID = %s, want %s", gotID, staleID)
	}
	if gotCorrID == uuid.Nil {
		t.Error("handler correlationID is zero, want the job's real correlation id")
	}
	if gotReason == "" || gotReason == "max retries exceeded" {
		t.Errorf("handler reason = %q, want a staleness-specific message (never the generic retry-exhaustion text)", gotReason)
	}

	// A varredura chama HandleDeadLetter-equivalente, que transiciona o
	// job pra dead_letter — confirma que o handler de verdade (não só o
	// fake acima) teria uma linha válida pra trabalhar em cima.
	repo := NewRepository(pool)
	fetched, err := repo.GetByID(ctx, staleID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != StatusProcessing {
		t.Errorf("status = %s, want processing (sweepOnce não muda status sozinho — quem muda é o StaleJobHandler registrado, que este teste fake não faz)", fetched.Status)
	}
}

func TestSweepOnce_IgnoresRecentProcessingJob(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const jobType = "test.stale.sweep.recent"
	createStaleJob(t, pool, jobType, 1*time.Minute) // "started" 1min ago — não deveria ser considerado órfão com staleAfter=1h

	calls := 0
	handlers := map[string]StaleJobHandler{
		jobType: func(context.Context, uuid.UUID, uuid.UUID, string) error {
			calls++
			return nil
		},
	}

	sweepOnce(ctx, pool, handlers, time.Hour, testLogger())

	if calls != 0 {
		t.Errorf("handler called %d times, want 0 (job ainda dentro da janela legítima de processamento)", calls)
	}
}

func TestSweepOnce_UnregisteredJobType_SkippedWithoutCrashing(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const jobType = "test.stale.sweep.no-handler"
	createStaleJob(t, pool, jobType, 2*time.Hour)

	// handlers vazio — nenhum tipo registrado. Não deveria dar panic nem
	// impedir outros jobs órfãos (não testados aqui) de serem varridos no
	// mesmo ciclo.
	sweepOnce(ctx, pool, map[string]StaleJobHandler{}, time.Hour, testLogger())
}

func TestSweepOnce_HandlerError_DoesNotCrashTheSweep(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const jobTypeA = "test.stale.sweep.errors"
	const jobTypeB = "test.stale.sweep.succeeds"
	createStaleJob(t, pool, jobTypeA, 2*time.Hour)
	createStaleJob(t, pool, jobTypeB, 2*time.Hour)

	bCalled := false
	handlers := map[string]StaleJobHandler{
		jobTypeA: func(context.Context, uuid.UUID, uuid.UUID, string) error {
			return context.DeadlineExceeded // erro qualquer, simulando um handler que falha
		},
		jobTypeB: func(context.Context, uuid.UUID, uuid.UUID, string) error {
			bCalled = true
			return nil
		},
	}

	sweepOnce(ctx, pool, handlers, time.Hour, testLogger())

	if !bCalled {
		t.Error("o handler do segundo tipo deveria ter rodado mesmo com o primeiro falhando (best-effort por job, não aborta o ciclo inteiro)")
	}
}
