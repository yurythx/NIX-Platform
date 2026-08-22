// Package domain holds the integrations module's entity and repository
// contract (§74).
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Status is an integration's last known health (§42/§74).
type Status string

const (
	StatusUnknown  Status = "unknown"
	StatusOnline   Status = "online"
	StatusOffline  Status = "offline"
	StatusDegraded Status = "degraded"
	StatusDisabled Status = "disabled"
)

// Integration is a configured external system the platform can check the
// status of and, for some types, trigger a test run against.
type Integration struct {
	ID            uuid.UUID
	Key           string
	Name          string
	Type          string
	Enabled       bool
	Status        Status
	LastCheckAt   *time.Time
	LastSuccessAt *time.Time
	LastError     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Repository persists Integration rows.
type Repository interface {
	List(ctx context.Context) ([]*Integration, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Integration, error)
	GetByKey(ctx context.Context, key string) (*Integration, error)

	// UpdateStatusTx records the outcome of a health/test check for the
	// integration identified by key, on the caller's transaction so it can
	// be committed atomically alongside an outbox event when the status
	// actually changed (§9's integration.status.changed routing key).
	UpdateStatusTx(ctx context.Context, tx pgx.Tx, key string, success bool, lastError *string) (updated *Integration, changed bool, err error)
}
