// Package domain holds the users module's entity and repository contract.
// It imports nothing from HTTP, RabbitMQ, PostgreSQL, or Keycloak — those
// belong to transport/infrastructure.
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
)

// User is a NIX Platform account, mirrored from Keycloak on each
// authenticated request (Keycloak is the identity source of truth; this
// row holds only what the platform itself needs — §32).
type User struct {
	ID              uuid.UUID
	KeycloakSubject string
	Username        string
	Email           string
	DisplayName     string
	Active          bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastSeenAt      *time.Time
}

// UpsertResult reports whether Upsert created a new row, so callers can
// decide whether a user.created audit entry is warranted.
type UpsertResult struct {
	User    *User
	Created bool
}

// Repository persists User rows.
type Repository interface {
	// UpsertByKeycloakSubject creates the user if this is the first time
	// this Keycloak subject has been seen, or refreshes
	// username/email/last_seen_at otherwise.
	UpsertByKeycloakSubject(ctx context.Context, u *User) (UpsertResult, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	List(ctx context.Context, p pagination.Params) ([]*User, int64, error)
}
