// Package outbox implements the Transactional Outbox pattern (§16): an
// event is written to the outbox_events table in the same PostgreSQL
// transaction as the business data it describes, so a partial failure
// (data committed but RabbitMQ unreachable, or vice versa) can never
// happen. A separate Publisher polls pending rows and forwards them to
// RabbitMQ, marking each published only after the broker confirms it.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yurythx/nix-platform/internal/domain/events"
)

// Writer inserts outbox rows. It takes no database handle itself —
// callers pass the pgx.Tx of the business transaction they're already in,
// so the outbox insert is atomic with whatever business data was just
// written on that same tx.
type Writer struct {
	source string // events.Event.Source for every event this writer builds, e.g. "nix.diario_oficial"
}

// NewWriter builds a Writer that stamps every event with source.
func NewWriter(source string) *Writer {
	return &Writer{source: source}
}

// Write builds the standard event envelope (§17) and inserts it into
// outbox_events within tx. It must be called before tx.Commit(); the event
// only becomes visible to the Publisher once the surrounding transaction
// commits.
func (w *Writer) Write(ctx context.Context, tx pgx.Tx, eventType, aggregateType, aggregateID string, correlationID uuid.UUID, payload any) error {
	event, err := events.New(eventType, w.source, correlationID, payload)
	if err != nil {
		return fmt.Errorf("outbox: build event envelope: %w", err)
	}

	envelope, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("outbox: marshal event envelope: %w", err)
	}

	const q = `
		INSERT INTO outbox_events (id, event_type, aggregate_type, aggregate_id, payload, status, attempts, created_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6)
	`
	if _, err := tx.Exec(ctx, q, event.ID, eventType, aggregateType, aggregateID, envelope, event.OccurredAt); err != nil {
		return fmt.Errorf("outbox: insert event %s: %w", eventType, err)
	}
	return nil
}
