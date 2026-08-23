package configflags

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

func TestPostgresStore_IsEnabled_UnknownKeyUsesDefault(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	key := "test:" + uuid.NewString()

	enabled, err := store.IsEnabled(context.Background(), key, true)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !enabled {
		t.Error("uma chave nunca registrada deveria usar o defaultValue (true)")
	}

	disabled, err := store.IsEnabled(context.Background(), key, false)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if disabled {
		t.Error("uma chave nunca registrada deveria usar o defaultValue (false)")
	}
}

func TestPostgresStore_SetThenIsEnabledReflectsChange(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	ctx := context.Background()
	key := "test:" + uuid.NewString()

	if _, err := store.Set(ctx, key, true, "admin-1"); err != nil {
		t.Fatalf("Set(true): %v", err)
	}
	enabled, err := store.IsEnabled(ctx, key, false)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !enabled {
		t.Fatal("esperava enabled=true logo após Set(true)")
	}

	if _, err := store.Set(ctx, key, false, "admin-1"); err != nil {
		t.Fatalf("Set(false): %v", err)
	}
	enabled, err = store.IsEnabled(ctx, key, true)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if enabled {
		t.Fatal("esperava enabled=false logo após Set(false) — sem cache, a mudança deve refletir imediatamente")
	}
}

func TestPostgresStore_ListIncludesSeededFlags(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)

	flags, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	seen := map[string]bool{}
	for _, f := range flags {
		seen[f.Key] = true
	}
	for _, want := range []string{"diario_oficial_scraping_enabled"} {
		if !seen[want] {
			t.Errorf("List() não incluiu a flag semeada %q", want)
		}
	}
}
