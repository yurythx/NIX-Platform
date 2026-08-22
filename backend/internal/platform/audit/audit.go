// Package audit writes the audit_logs trail (§49): login/logout,
// user.created/updated, integration.test, integration.config.changed,
// job.created/completed/failed. Callers are responsible for never putting
// a password, access/refresh token, client secret, or integration secret
// into Entry.Metadata — this package does not attempt to redact content it
// doesn't understand the shape of.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Well-known action names (§49). Callers may also use their own
// "<context>.<action>" strings for module-specific events not listed here.
const (
	ActionLogin                    = "login"
	ActionLogout                   = "logout"
	ActionUserCreated              = "user.created"
	ActionUserUpdated              = "user.updated"
	ActionIntegrationTest          = "integration.test"
	ActionIntegrationConfigChanged = "integration.config.changed"
	ActionJobCreated               = "job.created"
	ActionJobCompleted             = "job.completed"
	ActionJobFailed                = "job.failed"
)

// Entry is one audit record.
type Entry struct {
	UserID        *uuid.UUID
	Action        string
	ResourceType  string
	ResourceID    string
	Metadata      map[string]any
	CorrelationID *uuid.UUID
	IPAddress     string
}

// execer is satisfied by both *pgxpool.Pool and pgx.Tx, so Record can be
// used either standalone or atomically alongside other writes on an
// existing transaction.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Writer inserts audit_logs rows.
type Writer struct {
	db execer
}

// NewWriter builds a Writer over db, which may be a *pgxpool.Pool for
// standalone writes or a pgx.Tx to make the audit entry atomic with other
// changes in the same transaction.
func NewWriter(db execer) *Writer {
	return &Writer{db: db}
}

// Record inserts entry.
func (w *Writer) Record(ctx context.Context, entry Entry) error {
	metadata := entry.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	const q = `
		INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, metadata, correlation_id, ip_address, created_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, NULLIF($8, '')::inet, now())
	`
	_, err = w.db.Exec(ctx, q,
		uuid.New(), entry.UserID, entry.Action, entry.ResourceType, entry.ResourceID,
		metadataJSON, entry.CorrelationID, entry.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("audit: insert entry for action %s: %w", entry.Action, err)
	}
	return nil
}
