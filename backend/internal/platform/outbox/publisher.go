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

// Publisher faz polling de outbox_events buscando linhas pendentes e as
// encaminha ao RabbitMQ via o events.EventPublisher injetado, marcando
// cada linha como "published" somente depois que o broker a confirma
// (§14/§16). Nunca importa o pacote messaging diretamente — só a
// interface de domínio — o que permite testá-lo com um publisher falso
// (fake), sem precisar de um RabbitMQ real no teste.
type Publisher struct {
	pool           *pgxpool.Pool
	eventPublisher events.EventPublisher
	logger         *slog.Logger

	pollInterval time.Duration
	batchSize    int
	maxAttempts  int
}

// NewPublisher constrói um Publisher de outbox com padrões razoáveis:
// faz polling a cada 2s, até 20 linhas por lote, desistindo (marcando uma
// linha como "failed" em vez de tentar para sempre) depois de 10
// tentativas de publicação falhas.
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

// Run faz polling até ctx ser cancelado. Pensado para ser registrado como
// um dos processadores em segundo plano do cmd/worker.
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

// publishPendingBatch trava até batchSize linhas pendentes com SELECT ...
// FOR UPDATE SKIP LOCKED (seguro para múltiplas réplicas do worker fazendo
// polling ao mesmo tempo — cada uma pega um conjunto disjunto de linhas,
// sem duas réplicas processarem a mesma linha) e, para cada uma, publica
// e atualiza seu status dentro da mesma transação.
func (p *Publisher) publishPendingBatch(ctx context.Context) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("outbox: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // vira no-op depois de um commit bem-sucedido

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

// publishRow tenta publicar uma única linha do outbox e ajusta seu status
// de acordo com o resultado: envelope ilegível vai direto para "failed"
// (nunca teria sucesso numa nova tentativa); falha de publicação soma uma
// tentativa e, se ainda não estourou maxAttempts, fica "pending" para a
// próxima rodada de polling tentar de novo; sucesso marca "published".
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
