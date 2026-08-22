package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// Repository persiste as linhas de Job. Todo método que altera dado recebe
// um pgx.Tx, para que quem chama consiga manter a atualização do job e seu
// evento de outbox na mesma transação (§16, padrão Transactional Outbox);
// GetByID/List leem direto pelo pool, já que nunca precisam de atomicidade
// transacional com mais nada.
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create insere um novo job no estado "queued".
func (r *Repository) Create(ctx context.Context, tx pgx.Tx, j *Job) error {
	const q = `
		INSERT INTO jobs (id, type, status, attempts, payload, correlation_id, created_at)
		VALUES ($1, $2, $3, 0, $4, $5, $6)
	`
	_, err := tx.Exec(ctx, q, j.ID, j.Type, j.Status, j.Payload, j.CorrelationID, j.CreatedAt)
	if err != nil {
		return fmt.Errorf("jobs: insert: %w", err)
	}
	return nil
}

// transition aplica uma mudança de status depois de validá-la contra
// CanTransition, incrementando attempts e ajustando os timestamps de
// início/fim conforme o caso.
func (r *Repository) transition(ctx context.Context, tx pgx.Tx, id uuid.UUID, to Status, result any, jobErr *string) error {
	// SELECT ... FOR UPDATE trava a linha até o fim da transação, para que
	// duas goroutines/consumers concorrentes processando o mesmo job (ex.:
	// uma redelivery do RabbitMQ chegando enquanto o processamento
	// original ainda está em andamento) não apliquem transições
	// conflitantes lendo o mesmo status "velho" ao mesmo tempo.
	locked, err := r.getForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if !CanTransition(locked.Status, to) {
		return fmt.Errorf("jobs: invalid transition %s -> %s for job %s", locked.Status, to, id)
	}

	var resultJSON []byte
	if result != nil {
		resultJSON, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("jobs: marshal result: %w", err)
		}
	}

	switch to {
	case StatusProcessing:
		const q = `UPDATE jobs SET status = $2, attempts = attempts + 1, started_at = COALESCE(started_at, now()) WHERE id = $1`
		_, err = tx.Exec(ctx, q, id, to)
	case StatusCompleted:
		const q = `UPDATE jobs SET status = $2, result = $3, finished_at = now() WHERE id = $1`
		_, err = tx.Exec(ctx, q, id, to, resultJSON)
	case StatusFailed, StatusDeadLetter:
		const q = `UPDATE jobs SET status = $2, error = $3, finished_at = now() WHERE id = $1`
		_, err = tx.Exec(ctx, q, id, to, jobErr)
	default:
		return fmt.Errorf("jobs: unsupported target status %s", to)
	}
	if err != nil {
		return fmt.Errorf("jobs: update status to %s: %w", to, err)
	}

	// §53: registra toda tentativa que chega a um status que vale a pena
	// contar — concluído, uma tentativa falha (que ainda pode ser
	// reprocessada) ou a desistência final em dead-letter. A duração é a
	// idade desde a criação, então a observação de uma tentativa falha se
	// lê como "quanto tempo esse job já existia quando esta tentativa
	// terminou", não o tempo de execução da tentativa em si.
	switch to {
	case StatusCompleted, StatusFailed, StatusDeadLetter:
		metrics.JobsProcessedTotal.WithLabelValues(locked.Type, string(to)).Inc()
		metrics.JobsDuration.WithLabelValues(locked.Type).Observe(time.Since(locked.CreatedAt).Seconds())
	}

	return nil
}

type lockedJob struct {
	Status    Status
	Type      string
	CreatedAt time.Time
}

func (r *Repository) getForUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedJob, error) {
	var j lockedJob
	err := tx.QueryRow(ctx, `SELECT status, type, created_at FROM jobs WHERE id = $1 FOR UPDATE`, id).
		Scan(&j.Status, &j.Type, &j.CreatedAt)
	if err != nil {
		return lockedJob{}, fmt.Errorf("jobs: lock job %s: %w", id, err)
	}
	return j, nil
}

// MarkProcessing transiciona um job para "processing" — chamado pelo
// worker no início do processamento de cada entrega/redelivery.
func (r *Repository) MarkProcessing(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	return r.transition(ctx, tx, id, StatusProcessing, nil, nil)
}

// MarkCompleted transiciona um job para "completed" e grava o resultado.
func (r *Repository) MarkCompleted(ctx context.Context, tx pgx.Tx, id uuid.UUID, result any) error {
	return r.transition(ctx, tx, id, StatusCompleted, result, nil)
}

// MarkFailed transiciona um job para "failed" e registra o erro — usado
// quando a tentativa atual falhou mas ainda pode ser reprocessada
// (retry ainda dentro do limite configurado).
func (r *Repository) MarkFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID, errMsg string) error {
	return r.transition(ctx, tx, id, StatusFailed, nil, &errMsg)
}

// MarkDeadLetter transiciona um job para "dead_letter" — chamado quando o
// RabbitMQ já esgotou sua própria política de retry para a mensagem que
// impulsiona este job (RABBITMQ_MAX_RETRIES excedido). É um estado final:
// a partir daqui, alguém precisa investigar manualmente a fila de dead
// letter.
func (r *Repository) MarkDeadLetter(ctx context.Context, tx pgx.Tx, id uuid.UUID, errMsg string) error {
	return r.transition(ctx, tx, id, StatusDeadLetter, nil, &errMsg)
}

// GetByID busca um único job.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Job, error) {
	const q = `
		SELECT id, type, status, attempts, payload, result, error, correlation_id, created_at, started_at, finished_at
		FROM jobs WHERE id = $1
	`
	row := r.pool.QueryRow(ctx, q, id)
	j, err := scanJob(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.NotFound(fmt.Sprintf("job %s not found", id))
		}
		return nil, fmt.Errorf("jobs: get by id: %w", err)
	}
	return j, nil
}

// List retorna uma página de jobs ordenados do mais recente para o mais
// antigo, opcionalmente filtrada por tipo.
func (r *Repository) List(ctx context.Context, p pagination.Params, jobType string) ([]*Job, int64, error) {
	var total int64
	countQ := `SELECT count(*) FROM jobs WHERE ($1 = '' OR type = $1)`
	if err := r.pool.QueryRow(ctx, countQ, jobType).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("jobs: count: %w", err)
	}

	const q = `
		SELECT id, type, status, attempts, payload, result, error, correlation_id, created_at, started_at, finished_at
		FROM jobs
		WHERE ($1 = '' OR type = $1)
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.pool.Query(ctx, q, jobType, p.Limit(), p.Offset())
	if err != nil {
		return nil, 0, fmt.Errorf("jobs: list: %w", err)
	}
	defer rows.Close()

	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("jobs: scan: %w", err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("jobs: iterate: %w", err)
	}
	return out, total, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.Type, &j.Status, &j.Attempts, &j.Payload, &j.Result, &j.Error, &j.CorrelationID, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &j, nil
}
