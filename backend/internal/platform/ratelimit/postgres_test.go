package ratelimit

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Estes testes rodam contra o PostgreSQL real usado no restante da suíte
// deste backend — pulados automaticamente se TEST_DATABASE_URL não
// estiver definida, então `go test ./...` continua passando sem
// infraestrutura.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL não definida; pulando teste de integração do rate limiter")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPostgresLimiter_AllowsWithinLimitThenRejects(t *testing.T) {
	pool := testPool(t)
	key := "test:" + uuid.NewString()
	limiter := NewPostgresLimiter(pool, 60, 3) // janela de 60s para não cruzar fronteira durante o teste
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, err := limiter.Allow(ctx, key)
		if err != nil {
			t.Fatalf("Allow (chamada %d): %v", i, err)
		}
		if !allowed {
			t.Fatalf("chamada %d: esperava permitido (dentro do limite de 3), mas foi negado", i)
		}
	}

	allowed, err := limiter.Allow(ctx, key)
	if err != nil {
		t.Fatalf("Allow (4ª chamada): %v", err)
	}
	if allowed {
		t.Error("esperava negado na 4ª chamada (limite de 3 já esgotado), mas foi permitido")
	}
}

func TestPostgresLimiter_DifferentKeysAreIndependent(t *testing.T) {
	pool := testPool(t)
	limiter := NewPostgresLimiter(pool, 60, 1)
	ctx := context.Background()

	keyA := "test:" + uuid.NewString()
	keyB := "test:" + uuid.NewString()

	allowedA, err := limiter.Allow(ctx, keyA)
	if err != nil || !allowedA {
		t.Fatalf("primeira chamada da chave A deveria ser permitida: allowed=%v err=%v", allowedA, err)
	}
	allowedB, err := limiter.Allow(ctx, keyB)
	if err != nil || !allowedB {
		t.Fatalf("primeira chamada da chave B deveria ser permitida (independente de A): allowed=%v err=%v", allowedB, err)
	}

	// A segunda chamada de A, com limite 1, já deve ser negada — mas B
	// não deve ser afetada por isso.
	allowedA2, err := limiter.Allow(ctx, keyA)
	if err != nil {
		t.Fatalf("Allow (A, 2ª chamada): %v", err)
	}
	if allowedA2 {
		t.Error("esperava a chave A negada na 2ª chamada (limite 1)")
	}
}

func TestPostgresLimiter_SharedAcrossInstances(t *testing.T) {
	pool := testPool(t)
	key := "test:" + uuid.NewString()
	ctx := context.Background()

	// Duas instâncias de PostgresLimiter apontando para o MESMO pool —
	// simula duas réplicas da API. O contador precisa ser compartilhado
	// entre elas, provando que o limite não vira N× o configurado com
	// múltiplas réplicas (o problema real que motivou esta implementação).
	replicaA := NewPostgresLimiter(pool, 60, 2)
	replicaB := NewPostgresLimiter(pool, 60, 2)

	allowed1, _ := replicaA.Allow(ctx, key)
	allowed2, _ := replicaB.Allow(ctx, key)
	allowed3, _ := replicaA.Allow(ctx, key)

	if !allowed1 || !allowed2 {
		t.Fatalf("as duas primeiras chamadas (limite=2) deveriam ser permitidas: %v, %v", allowed1, allowed2)
	}
	if allowed3 {
		t.Error("a 3ª chamada deveria ser negada — o limite é compartilhado entre as duas 'réplicas', não 2 por réplica")
	}
}
