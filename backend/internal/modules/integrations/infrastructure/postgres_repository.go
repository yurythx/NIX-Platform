// Package infrastructure implementa o domain.Repository do módulo
// integrations contra o PostgreSQL.
package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/integrations/domain"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

var _ domain.Repository = (*PostgresRepository)(nil)

const selectColumns = `id, key, name, type, enabled, status, last_check_at, last_success_at, last_error, created_at, updated_at`

func (r *PostgresRepository) List(ctx context.Context) ([]*domain.Integration, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+selectColumns+` FROM integrations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("integrations: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.Integration
	for rows.Next() {
		i, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("integrations: scan: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Integration, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+selectColumns+` FROM integrations WHERE id = $1`, id)
	i, err := scan(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.NotFound(fmt.Sprintf("integration %s not found", id))
		}
		return nil, fmt.Errorf("integrations: get by id: %w", err)
	}
	return i, nil
}

func (r *PostgresRepository) GetByKey(ctx context.Context, key string) (*domain.Integration, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+selectColumns+` FROM integrations WHERE key = $1`, key)
	i, err := scan(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.NotFound(fmt.Sprintf("integration %q not found", key))
		}
		return nil, fmt.Errorf("integrations: get by key: %w", err)
	}
	return i, nil
}

func (r *PostgresRepository) UpdateStatusTx(ctx context.Context, tx pgx.Tx, key string, success bool, lastError *string) (*domain.Integration, bool, error) {
	// Trava a linha antes de ler o status anterior para comparar com o
	// novo de forma segura sob concorrência — dois testes da mesma
	// integração rodando ao mesmo tempo (ex.: um usuário clicando "testar"
	// duas vezes seguidas) não podem os dois achar que "mudou de status"
	// comparando contra um valor já obsoleto.
	var previousStatus domain.Status
	err := tx.QueryRow(ctx, `SELECT status FROM integrations WHERE key = $1 FOR UPDATE`, key).Scan(&previousStatus)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, false, apperrors.NotFound(fmt.Sprintf("integration %q not found", key))
		}
		return nil, false, fmt.Errorf("integrations: lock %q: %w", key, err)
	}

	newStatus := domain.StatusOffline
	if success {
		newStatus = domain.StatusOnline
	}

	const q = `
		UPDATE integrations
		SET status = $2,
		    last_check_at = now(),
		    last_success_at = CASE WHEN $3 THEN now() ELSE last_success_at END,
		    last_error = $4,
		    updated_at = now()
		WHERE key = $1
		RETURNING ` + selectColumns
	row := tx.QueryRow(ctx, q, key, newStatus, success, lastError)
	updated, err := scan(row)
	if err != nil {
		return nil, false, fmt.Errorf("integrations: update status for %q: %w", key, err)
	}

	return updated, previousStatus != newStatus, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(row scanner) (*domain.Integration, error) {
	var i domain.Integration
	err := row.Scan(&i.ID, &i.Key, &i.Name, &i.Type, &i.Enabled, &i.Status, &i.LastCheckAt, &i.LastSuccessAt, &i.LastError, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &i, nil
}
