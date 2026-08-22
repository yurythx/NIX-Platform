package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/domain/events"
)

// Publisher polls outbox_events for pending rows and forwards them to
// RabbitMQ via the injected events.EventPublisher, marking each row
// "published" only once the broker has confirmed it (§14/§16). It never
// imports the messaging package directly — only the domain interface — so
// it can be tested with a fake publisher.
type Publisher struct {
	pool           *pgxpool.Pool
	eventPublisher events.EventPublisher
	logger         *slog.Logger

	pollInterval time.Duration
	batchSize    int
	maxAttempts  int
}

// NewPublisher builds an outbox Publisher with sensible defaults: poll
// every 2s, up to 20 rows per batch, giving up (marking a row "failed"
// rather than retrying forever) after 10 failed publish attempts.
func NewPublisher(pool *pgxpool.Pool, eventPublisher events.EventPublisher, logger *slog.Logger) *Publisher {
	return &Publisher{
		pool:           pool,
		eventPublisher: eventPublisher,
		logger:         logger,
		pollInterval:   2 * time.Second,
		batchSize:      20,
		maxAttempts:    10,
	}
}

// Run polls until ctx is cancelled. It's meant to be registered as one of
// cmd/worker's background processors.
func (p *Publisher) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.publishPendingBatch(ctx); err != nil {
				p.logger.Error("outbox: publish pending batch failed", slog.Any("error", err))
			}
		}
	}
}

type outboxRow struct {
	id       uuid.UUID
	payload  []byte
	attempts int
}

// publishPendingBatch locks up to batchSize pending rows with SELECT ...
// FOR UPDATE SKIP LOCKED (safe for multiple worker replicas polling
// concurrently — each grabs a disjoint set of rows) and, for each,
// publishes and updates its status within the same transaction.
func (p *Publisher) publishPendingBatch(ctx context.Context) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("outbox: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	const selectQ = `
		SELECT id, payload, attempts
		FROM outbox_events
		WHERE status = 'pending'
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`
	rows, err := tx.Query(ctx, selectQ, p.batchSize)
	if err != nil {
		return fmt.Errorf("outbox: select pending: %w", err)
	}

	var pending []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.id, &r.payload, &r.attempts); err != nil {
			rows.Close()
			return fmt.Errorf("outbox: scan pending row: %w", err)
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("outbox: iterate pending rows: %w", err)
	}

	for _, row := range pending {
		p.publishRow(ctx, tx, row)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("outbox: commit batch: %w", err)
	}
	return nil
}

func (p *Publisher) publishRow(ctx context.Context, tx pgx.Tx, row outboxRow) {
	var event events.Event
	if err := json.Unmarshal(row.payload, &event); err != nil {
		p.logger.Error("outbox: undecodable envelope, marking failed", slog.String("outbox_id", row.id.String()), slog.Any("error", err))
		p.markFailed(ctx, tx, row.id, "undecodable envelope: "+err.Error())
		return
	}

	if err := p.eventPublisher.Publish(ctx, event); err != nil {
		attempts := row.attempts + 1
		if attempts >= p.maxAttempts {
			p.logger.Error("outbox: exceeded max publish attempts, marking failed",
				slog.String("outbox_id", row.id.String()), slog.String("event_type", event.Type), slog.Any("error", err))
			p.markFailed(ctx, tx, row.id, err.Error())
			return
		}
		p.logger.Warn("outbox: publish attempt failed, will retry next poll",
			slog.String("outbox_id", row.id.String()), slog.String("event_type", event.Type), slog.Int("attempts", attempts), slog.Any("error", err))
		p.markAttemptFailed(ctx, tx, row.id, attempts, err.Error())
		return
	}

	p.markPublished(ctx, tx, row.id)
}

func (p *Publisher) markPublished(ctx context.Context, tx pgx.Tx, id uuid.UUID) {
	const q = `UPDATE outbox_events SET status = 'published', published_at = now() WHERE id = $1`
	if _, err := tx.Exec(ctx, q, id); err != nil {
		p.logger.Error("outbox: failed to mark row published", slog.String("outbox_id", id.String()), slog.Any("error", err))
	}
}

func (p *Publisher) markAttemptFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID, attempts int, lastError string) {
	const q = `UPDATE outbox_events SET attempts = $2, last_error = $3 WHERE id = $1`
	if _, err := tx.Exec(ctx, q, id, attempts, lastError); err != nil {
		p.logger.Error("outbox: failed to record attempt", slog.String("outbox_id", id.String()), slog.Any("error", err))
	}
}

func (p *Publisher) markFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID, lastError string) {
	const q = `UPDATE outbox_events SET status = 'failed', attempts = attempts + 1, last_error = $2 WHERE id = $1`
	if _, err := tx.Exec(ctx, q, id, lastError); err != nil {
		p.logger.Error("outbox: failed to mark row failed", slog.String("outbox_id", id.String()), slog.Any("error", err))
	}
}
