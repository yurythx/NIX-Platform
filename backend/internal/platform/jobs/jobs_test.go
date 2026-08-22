package jobs

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live jobs integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestCanTransition(t *testing.T) {
	cases := []struct {
		from, to Status
		want     bool
	}{
		{StatusQueued, StatusProcessing, true},
		{StatusQueued, StatusCompleted, false},
		{StatusProcessing, StatusCompleted, true},
		{StatusProcessing, StatusFailed, true},
		{StatusProcessing, StatusQueued, false},
		{StatusFailed, StatusProcessing, true},
		{StatusFailed, StatusDeadLetter, true},
		{StatusCompleted, StatusProcessing, false},
		{StatusDeadLetter, StatusProcessing, false},
	}
	for _, tc := range cases {
		if got := CanTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("CanTransition(%s, %s) = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestRepository_FullLifecycle(t *testing.T) {
	pool := testPool(t)
	repo := NewRepository(pool)
	ctx := context.Background()

	job, err := New("test.job", uuid.New(), map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := repo.Create(ctx, tx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	fetched, err := repo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != StatusQueued {
		t.Errorf("Status = %s, want queued", fetched.Status)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := repo.MarkProcessing(ctx, tx, job.ID); err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if err := repo.MarkCompleted(ctx, tx, job.ID, map[string]int{"status_code": 200}); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	fetched, err = repo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != StatusCompleted {
		t.Errorf("Status = %s, want completed", fetched.Status)
	}
	if fetched.StartedAt == nil || fetched.FinishedAt == nil {
		t.Error("expected StartedAt and FinishedAt to be set")
	}
	if len(fetched.Result) == 0 {
		t.Error("expected a stored result")
	}
}

func TestRepository_RejectsInvalidTransition(t *testing.T) {
	pool := testPool(t)
	repo := NewRepository(pool)
	ctx := context.Background()

	job, err := New("test.job", uuid.New(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := repo.Create(ctx, tx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// queued -> completed is not a valid transition (must go through processing).
	err = repo.MarkCompleted(ctx, tx, job.ID, nil)
	_ = tx.Rollback(ctx)
	if err == nil {
		t.Fatal("expected MarkCompleted from queued to fail")
	}
}

func TestRepository_List_FiltersByType(t *testing.T) {
	pool := testPool(t)
	repo := NewRepository(pool)
	ctx := context.Background()

	uniqueType := "test.job." + uuid.NewString()[:8]
	for i := 0; i < 3; i++ {
		job, err := New(uniqueType, uuid.New(), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if err := repo.Create(ctx, tx, job); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	list, total, err := repo.List(ctx, pagination.New(1, 20, 100), uniqueType)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(list) != 3 {
		t.Errorf("len(list) = %d, want 3", len(list))
	}
	for _, j := range list {
		if j.Type != uniqueType {
			t.Errorf("job type = %q, want %q", j.Type, uniqueType)
		}
	}
}
