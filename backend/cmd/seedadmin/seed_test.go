// Testes de seedAdmin — rodam contra o Postgres real usado por todo este
// backend, pulando se TEST_DATABASE_URL não estiver definida (mesmo
// padrão de todo outro pacote desta sessão).
package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live seedadmin test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestSeedAdmin_CreatesUserWithHashedRandomPassword(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	username := "seedadmin-test-" + uuid.New().String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	})

	password, err := seedAdmin(ctx, pool, username, "seedadmin-test@nix.local", "Seedadmin Test", "nix-admin,nix-user", "")
	if err != nil {
		t.Fatalf("seedAdmin: %v", err)
	}
	if password == "" {
		t.Fatal("expected a non-empty generated password")
	}

	var hash string
	var roles []string
	var active bool
	err = pool.QueryRow(ctx, `SELECT password_hash, roles, active FROM users WHERE username = $1`, username).
		Scan(&hash, &roles, &active)
	if err != nil {
		t.Fatalf("query created user: %v", err)
	}
	if !active {
		t.Error("expected the created user to be active")
	}
	if len(roles) != 2 || roles[0] != "nix-admin" || roles[1] != "nix-user" {
		t.Errorf("roles = %v, want [nix-admin nix-user]", roles)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Errorf("the stored hash does not match the returned password: %v", err)
	}
}

func TestSeedAdmin_SecondRun_ResetsPasswordAndLockout(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	username := "seedadmin-test-" + uuid.New().String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	})

	firstPassword, err := seedAdmin(ctx, pool, username, "seedadmin-test@nix.local", "Seedadmin Test", "nix-admin", "")
	if err != nil {
		t.Fatalf("seedAdmin (primeira vez): %v", err)
	}

	// Simula uma conta bloqueada por tentativas de senha errada — rodar de
	// novo deveria destravá-la, não só trocar a senha.
	if _, err := pool.Exec(ctx, `UPDATE users SET failed_login_attempts = 5, locked_until = now() + interval '15 minutes' WHERE username = $1`, username); err != nil {
		t.Fatalf("simulate lockout: %v", err)
	}

	secondPassword, err := seedAdmin(ctx, pool, username, "seedadmin-test@nix.local", "Seedadmin Test", "nix-admin", "")
	if err != nil {
		t.Fatalf("seedAdmin (segunda vez): %v", err)
	}
	if firstPassword == secondPassword {
		t.Error("a segunda execução deveria gerar uma senha NOVA, não repetir a primeira")
	}

	var failedAttempts int
	var lockedUntil *string
	err = pool.QueryRow(ctx, `SELECT failed_login_attempts, locked_until FROM users WHERE username = $1`, username).
		Scan(&failedAttempts, &lockedUntil)
	if err != nil {
		t.Fatalf("query user after second run: %v", err)
	}
	if failedAttempts != 0 || lockedUntil != nil {
		t.Errorf("failed_login_attempts=%d locked_until=%v, want 0/nil (segunda execução deveria destravar a conta)", failedAttempts, lockedUntil)
	}
}

// TestSeedAdmin_PasswordOverride_UsesGivenPasswordInsteadOfRandom cobre a
// flag --password (só automação — CI de E2E, ver
// .github/workflows/ci.yml, que precisa saber a senha de antemão pra
// digitar num formulário do Playwright).
func TestSeedAdmin_PasswordOverride_UsesGivenPasswordInsteadOfRandom(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	username := "seedadmin-test-" + uuid.New().String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	})

	const fixedPassword = "e2e-fixed-password-not-random"
	got, err := seedAdmin(ctx, pool, username, "seedadmin-test@nix.local", "Seedadmin Test", "nix-admin", fixedPassword)
	if err != nil {
		t.Fatalf("seedAdmin: %v", err)
	}
	if got != fixedPassword {
		t.Errorf("seedAdmin returned %q, want the override %q unchanged", got, fixedPassword)
	}

	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE username = $1`, username).Scan(&hash); err != nil {
		t.Fatalf("query created user: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(fixedPassword)); err != nil {
		t.Errorf("stored hash does not match the override password: %v", err)
	}
}

func TestSeedAdmin_RefusesToOverwriteKeycloakLinkedAccount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	username := "seedadmin-test-" + uuid.New().String()[:8]
	keycloakSubject := "kc-subject-" + uuid.New().String()

	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, keycloak_subject, username, email, display_name, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'SSO User', true, now(), now())
	`, uuid.New(), keycloakSubject, username, "sso-user@example.com")
	if err != nil {
		t.Fatalf("seed a Keycloak-linked user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	})

	_, err = seedAdmin(ctx, pool, username, "someone-else@nix.local", "Someone Else", "nix-admin", "")
	if err == nil {
		t.Fatal("expected seedAdmin to refuse overwriting a Keycloak-linked account, got no error")
	}
}
