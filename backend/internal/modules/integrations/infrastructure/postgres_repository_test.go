package infrastructure

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/integrations/domain"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live integrations repository test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// These tests rely on the "virustotal" row seeded by migration 000006.

func TestPostgresRepository_List_IncludesSeeded(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresRepository(pool)

	list, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	found := false
	for _, i := range list {
		if i.Key == "virustotal" {
			found = true
		}
	}
	if !found {
		t.Error("expected the seeded virustotal integration to be present")
	}
}

func TestPostgresRepository_UpdateStatusTx_ReportsChange(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	// Reset to a known baseline so the test is order-independent.
	_, err := pool.Exec(ctx, `UPDATE integrations SET status = 'unknown', last_error = NULL WHERE key = 'virustotal'`)
	if err != nil {
		t.Fatalf("reset baseline: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	updated, changed, err := repo.UpdateStatusTx(ctx, tx, "virustotal", true, nil)
	if err != nil {
		t.Fatalf("UpdateStatusTx: %v", err)
	}
	if !changed {
		t.Error("expected status to change from unknown to online")
	}
	if updated.Status != domain.StatusOnline {
		t.Errorf("Status = %s, want online", updated.Status)
	}
	if updated.LastSuccessAt == nil {
		t.Error("expected LastSuccessAt to be set on success")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Same outcome again: status should NOT be reported as changed.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, changedAgain, err := repo.UpdateStatusTx(ctx, tx, "virustotal", true, nil)
	if err != nil {
		t.Fatalf("UpdateStatusTx (2nd): %v", err)
	}
	if changedAgain {
		t.Error("expected no status change when the outcome repeats")
	}
	_ = tx.Rollback(ctx)

	// Failure transitions online -> offline with an error recorded.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	errMsg := "connection timeout"
	updated, changed, err = repo.UpdateStatusTx(ctx, tx, "virustotal", false, &errMsg)
	if err != nil {
		t.Fatalf("UpdateStatusTx (failure): %v", err)
	}
	if !changed {
		t.Error("expected status to change from online to offline")
	}
	if updated.Status != domain.StatusOffline {
		t.Errorf("Status = %s, want offline", updated.Status)
	}
	if updated.LastError == nil || *updated.LastError != errMsg {
		t.Errorf("LastError = %v, want %q", updated.LastError, errMsg)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}
