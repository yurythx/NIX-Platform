package idempotency

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Estes testes rodam contra o PostgreSQL real usado no restante da suíte
// deste backend — pulados automaticamente se TEST_DATABASE_URL não
// estiver definida.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL não definida; pulando teste de integração do PostgresStore")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPostgresStore_ClaimNewKeySucceeds(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	existing, claimed, err := store.Claim(ctx, key, "hash-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !claimed {
		t.Fatalf("esperava claimed=true para uma chave nova, existing=%+v", existing)
	}
}

func TestPostgresStore_SecondClaimWhileProcessingIsRejected(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	if _, claimed, err := store.Claim(ctx, key, "hash-a"); err != nil || !claimed {
		t.Fatalf("primeiro Claim deveria suceder: claimed=%v err=%v", claimed, err)
	}

	existing, claimed, err := store.Claim(ctx, key, "hash-a")
	if err != nil {
		t.Fatalf("segundo Claim: %v", err)
	}
	if claimed {
		t.Fatal("esperava claimed=false — a chave já está 'processing'")
	}
	if existing.Status != StatusProcessing {
		t.Errorf("existing.Status = %q, want %q", existing.Status, StatusProcessing)
	}
	if existing.RequestHash != "hash-a" {
		t.Errorf("existing.RequestHash = %q, want %q", existing.RequestHash, "hash-a")
	}
}

func TestPostgresStore_CompleteThenReplayReturnsStoredResponse(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	if _, claimed, err := store.Claim(ctx, key, "hash-a"); err != nil || !claimed {
		t.Fatalf("Claim inicial deveria suceder: claimed=%v err=%v", claimed, err)
	}
	if err := store.Complete(ctx, key, 202, []byte(`{"job_id":"abc"}`), "application/json"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	existing, claimed, err := store.Claim(ctx, key, "hash-a")
	if err != nil {
		t.Fatalf("Claim após Complete: %v", err)
	}
	if claimed {
		t.Fatal("esperava claimed=false — a chave já está 'completed'")
	}
	if existing.Status != StatusCompleted {
		t.Errorf("existing.Status = %q, want %q", existing.Status, StatusCompleted)
	}
	if existing.ResponseStatus != 202 {
		t.Errorf("existing.ResponseStatus = %d, want 202", existing.ResponseStatus)
	}
	if string(existing.ResponseBody) != `{"job_id":"abc"}` {
		t.Errorf("existing.ResponseBody = %q", existing.ResponseBody)
	}
	if existing.ContentType != "application/json" {
		t.Errorf("existing.ContentType = %q, want application/json", existing.ContentType)
	}
}

func TestPostgresStore_FailedKeyCanBeReclaimedWithSameHash(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	if _, claimed, err := store.Claim(ctx, key, "hash-a"); err != nil || !claimed {
		t.Fatalf("Claim inicial deveria suceder: claimed=%v err=%v", claimed, err)
	}
	if err := store.Fail(ctx, key); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	// Mesmo hash: uma nova tentativa completa deve ser permitida — um
	// erro de servidor não pode travar a chave para sempre.
	_, claimed, err := store.Claim(ctx, key, "hash-a")
	if err != nil {
		t.Fatalf("Claim após Fail: %v", err)
	}
	if !claimed {
		t.Fatal("esperava claimed=true — uma chave 'failed' com o mesmo hash deve poder ser reivindicada de novo")
	}
}

func TestPostgresStore_FailedKeyWithDifferentHashIsNotSilentlyReclaimed(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	if _, claimed, err := store.Claim(ctx, key, "hash-a"); err != nil || !claimed {
		t.Fatalf("Claim inicial deveria suceder: claimed=%v err=%v", claimed, err)
	}
	if err := store.Fail(ctx, key); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	// Hash diferente: a chave está sendo reaproveitada para uma
	// requisição distinta — não deve ser silenciosamente reescrita.
	existing, claimed, err := store.Claim(ctx, key, "hash-b")
	if err != nil {
		t.Fatalf("Claim com hash diferente: %v", err)
	}
	if claimed {
		t.Fatal("esperava claimed=false — reusar uma chave 'failed' com hash diferente não deve ser reivindicado silenciosamente")
	}
	if existing.RequestHash != "hash-a" {
		t.Errorf("existing.RequestHash = %q, want o hash original %q", existing.RequestHash, "hash-a")
	}
}
