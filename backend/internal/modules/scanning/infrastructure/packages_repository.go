package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// SavePackages grava o inventário (Fase 11 — Syft) de uma execução de
// scan — mesmo padrão de SaveFindings (pgx.Batch, dentro da transação de
// quem chama, nunca abre a própria). Uma lista vazia não é erro.
func (r *PostgresRepository) SavePackages(ctx context.Context, tx pgx.Tx, scanID uuid.UUID, packages []domain.Package) error {
	if len(packages) == 0 {
		return nil
	}

	const q = `
		INSERT INTO scan_packages (scan_id, name, version, type, license)
		VALUES ($1, $2, $3, $4, $5)
	`
	batch := &pgx.Batch{}
	for _, p := range packages {
		batch.Queue(q, scanID, p.Name, p.Version, p.Type, p.License)
	}

	results := tx.SendBatch(ctx, batch)
	defer results.Close()

	for range packages {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("scanning: insert package: %w", err)
		}
	}
	return results.Close()
}

// ListPackagesByScanID retorna o inventário de uma execução, em ordem
// alfabética de nome — não há "gravidade" pra ordenar por, ao contrário
// de scan_findings.
func (r *PostgresRepository) ListPackagesByScanID(ctx context.Context, scanID uuid.UUID) ([]domain.Package, error) {
	const q = `SELECT name, version, type, license FROM scan_packages WHERE scan_id = $1 ORDER BY name`
	rows, err := r.pool.Query(ctx, q, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list packages for scan %s: %w", scanID, err)
	}
	defer rows.Close()

	out := make([]domain.Package, 0)
	for rows.Next() {
		var p domain.Package
		if err := rows.Scan(&p.Name, &p.Version, &p.Type, &p.License); err != nil {
			return nil, fmt.Errorf("scanning: scan package row: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
