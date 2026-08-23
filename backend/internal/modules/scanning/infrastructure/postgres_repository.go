// Package infrastructure implementa o domain.Repository do módulo scanning
// contra o PostgreSQL.
package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

var _ domain.Repository = (*PostgresRepository)(nil)

// SaveFindings grava todo achado de uma execução de scan numa única viagem
// ao banco via pgx.Batch, dentro da transação de quem chama — nunca abre
// sua própria transação, porque o achado tem que ficar atômico com o
// evento de outbox gravado pelo Service na mesma transação (ver
// application.Service.RunScan). Uma lista vazia de achados (scan limpo, sem
// nenhum problema encontrado) é um resultado legítimo, não um erro — não
// grava nada e retorna nil.
func (r *PostgresRepository) SaveFindings(ctx context.Context, tx pgx.Tx, scanID uuid.UUID, scanner, target string, findings []domain.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	const q = `
		INSERT INTO scan_findings (scan_id, scanner, target, owasp_category, severity, description, file, line)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	batch := &pgx.Batch{}
	for _, f := range findings {
		batch.Queue(q, scanID, scanner, target, f.OWASPCategory, f.Severity, f.Description, f.File, f.Line)
	}

	results := tx.SendBatch(ctx, batch)
	defer results.Close()

	for range findings {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("scanning: insert finding: %w", err)
		}
	}
	return results.Close()
}
