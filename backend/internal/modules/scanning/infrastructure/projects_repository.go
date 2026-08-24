package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// CreateProject grava um domain.Project novo — ver domain.Repository.
func (r *PostgresRepository) CreateProject(ctx context.Context, p domain.Project) error {
	const q = `
		INSERT INTO scanning_projects (id, name, source_type, target, upload_zip, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	if _, err := r.pool.Exec(ctx, q, p.ID, p.Name, p.SourceType, p.Target, p.UploadZip, p.CreatedAt); err != nil {
		return fmt.Errorf("scanning: create project: %w", err)
	}
	return nil
}

// GetProject busca um projeto por ID — ver domain.Repository.
func (r *PostgresRepository) GetProject(ctx context.Context, id uuid.UUID) (domain.Project, error) {
	const q = `SELECT id, name, source_type, target, upload_zip, created_at FROM scanning_projects WHERE id = $1`
	row := r.pool.QueryRow(ctx, q, id)
	p, err := scanProject(row)
	if err != nil {
		return domain.Project{}, apperrors.NotFound(fmt.Sprintf("project %s not found", id))
	}
	return p, nil
}

// ListProjects retorna os projetos mais recentes primeiro — ver
// domain.Repository.
func (r *PostgresRepository) ListProjects(ctx context.Context, limit int) ([]domain.Project, error) {
	const q = `
		SELECT id, name, source_type, target, upload_zip, created_at
		FROM scanning_projects
		ORDER BY created_at DESC
		LIMIT $1
	`
	rows, err := r.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list projects: %w", err)
	}
	defer rows.Close()

	out := make([]domain.Project, 0)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning: scan project row: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type projectScanner interface {
	Scan(dest ...any) error
}

func scanProject(row projectScanner) (domain.Project, error) {
	var p domain.Project
	var sourceType string
	if err := row.Scan(&p.ID, &p.Name, &sourceType, &p.Target, &p.UploadZip, &p.CreatedAt); err != nil {
		return domain.Project{}, err
	}
	p.SourceType = domain.ProjectSourceType(sourceType)
	return p, nil
}
