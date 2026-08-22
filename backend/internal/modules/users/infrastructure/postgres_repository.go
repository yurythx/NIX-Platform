// Package infrastructure implements the users module's domain.Repository
// against PostgreSQL.
package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/users/domain"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

var _ domain.Repository = (*PostgresRepository)(nil)

func (r *PostgresRepository) UpsertByKeycloakSubject(ctx context.Context, u *domain.User) (domain.UpsertResult, error) {
	// `xmax = 0` is the standard Postgres idiom for "this row was just
	// inserted, not updated by the ON CONFLICT branch" — lets us know
	// whether to raise a user.created audit entry without a second query.
	const q = `
		INSERT INTO users (id, keycloak_subject, username, email, display_name, active, created_at, updated_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, true, now(), now(), now())
		ON CONFLICT (keycloak_subject) DO UPDATE
		SET username = EXCLUDED.username, email = EXCLUDED.email, last_seen_at = now(), updated_at = now()
		RETURNING id, keycloak_subject, username, email, display_name, active, created_at, updated_at, last_seen_at, (xmax = 0) AS inserted
	`
	var out domain.User
	var inserted bool
	err := r.pool.QueryRow(ctx, q, uuid.New(), u.KeycloakSubject, u.Username, u.Email, u.DisplayName).
		Scan(&out.ID, &out.KeycloakSubject, &out.Username, &out.Email, &out.DisplayName, &out.Active, &out.CreatedAt, &out.UpdatedAt, &out.LastSeenAt, &inserted)
	if err != nil {
		return domain.UpsertResult{}, fmt.Errorf("users: upsert: %w", err)
	}
	return domain.UpsertResult{User: &out, Created: inserted}, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	const q = `
		SELECT id, keycloak_subject, username, email, display_name, active, created_at, updated_at, last_seen_at
		FROM users WHERE id = $1
	`
	var u domain.User
	err := r.pool.QueryRow(ctx, q, id).
		Scan(&u.ID, &u.KeycloakSubject, &u.Username, &u.Email, &u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSeenAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.NotFound(fmt.Sprintf("user %s not found", id))
		}
		return nil, fmt.Errorf("users: get by id: %w", err)
	}
	return &u, nil
}

func (r *PostgresRepository) List(ctx context.Context, p pagination.Params) ([]*domain.User, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("users: count: %w", err)
	}

	const q = `
		SELECT id, keycloak_subject, username, email, display_name, active, created_at, updated_at, last_seen_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.pool.Query(ctx, q, p.Limit(), p.Offset())
	if err != nil {
		return nil, 0, fmt.Errorf("users: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.KeycloakSubject, &u.Username, &u.Email, &u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSeenAt); err != nil {
			return nil, 0, fmt.Errorf("users: scan: %w", err)
		}
		out = append(out, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("users: iterate: %w", err)
	}
	return out, total, nil
}
