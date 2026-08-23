package infrastructure

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/users/domain"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live users repository test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPostgresRepository_UpsertIsIdempotentAndTracksCreation(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	suffix := uuid.NewString()
	subject := "test-sub-" + suffix
	username := "jdoe-" + suffix[:8]

	first, err := repo.UpsertByKeycloakSubject(ctx, &domain.User{
		KeycloakSubject: &subject, Username: username, Email: "jdoe-" + suffix[:8] + "@example.com",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !first.Created {
		t.Error("expected Created=true on first upsert")
	}

	updatedEmail := "jdoe-" + suffix[:8] + "-updated@example.com"
	second, err := repo.UpsertByKeycloakSubject(ctx, &domain.User{
		KeycloakSubject: &subject, Username: username, Email: updatedEmail,
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.Created {
		t.Error("expected Created=false on second upsert (same subject)")
	}
	if second.User.ID != first.User.ID {
		t.Error("expected the same user id across upserts")
	}
	if second.User.Email != updatedEmail {
		t.Errorf("Email = %q, want %q", second.User.Email, updatedEmail)
	}

	fetched, err := repo.GetByID(ctx, first.User.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Email != updatedEmail {
		t.Errorf("fetched Email = %q, want %q", fetched.Email, updatedEmail)
	}
}

func TestPostgresRepository_GetByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresRepository(pool)

	_, err := repo.GetByID(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error for a nonexistent user id")
	}
}
