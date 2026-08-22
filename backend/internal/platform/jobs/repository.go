package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
)

// Repository persists Job rows. Every mutating method takes a pgx.Tx so
// callers can keep the job update and its outbox event in the same
// transaction (§16); GetByID/List read through the pool directly since
// they never need transactional atomicity with anything else.
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create inserts a new job in the "queued" state.
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

// transition applies a status change after validating it against
// CanTransition, incrementing attempts and setting started/finished
// timestamps as appropriate.
func (r *Repository) transition(ctx context.Context, tx pgx.Tx, id uuid.UUID, to Status, result any, jobErr *string) error {
	current, err := r.getForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if !CanTransition(current, to) {
		return fmt.Errorf("jobs: invalid transition %s -> %s for job %s", current, to, id)
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
	return nil
}

func (r *Repository) getForUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Status, error) {
	var status Status
	err := tx.QueryRow(ctx, `SELECT status FROM jobs WHERE id = $1 FOR UPDATE`, id).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("jobs: lock job %s: %w", id, err)
	}
	return status, nil
}

// MarkProcessing transitions a job to "processing".
func (r *Repository) MarkProcessing(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	return r.transition(ctx, tx, id, StatusProcessing, nil, nil)
}

// MarkCompleted transitions a job to "completed" and stores its result.
func (r *Repository) MarkCompleted(ctx context.Context, tx pgx.Tx, id uuid.UUID, result any) error {
	return r.transition(ctx, tx, id, StatusCompleted, result, nil)
}

// MarkFailed transitions a job to "failed" and records the error.
func (r *Repository) MarkFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID, errMsg string) error {
	return r.transition(ctx, tx, id, StatusFailed, nil, &errMsg)
}

// MarkDeadLetter transitions a job to "dead_letter" — called once RabbitMQ
// has exhausted its own retry policy for the message driving this job.
func (r *Repository) MarkDeadLetter(ctx context.Context, tx pgx.Tx, id uuid.UUID, errMsg string) error {
	return r.transition(ctx, tx, id, StatusDeadLetter, nil, &errMsg)
}

// GetByID fetches a single job.
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

// List returns a page of jobs ordered by most recent first, optionally
// filtered by type.
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
