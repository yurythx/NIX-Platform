package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// UpsertTriage grava (ou substitui) a decisão de triagem de um
// fingerprint dentro de um projeto — ver domain.TriageRepository.
// ON CONFLICT em vez de UPDATE-ou-INSERT separados: o caso comum (trocar
// de decisão) e o raro (primeira triagem deste fingerprint) usam a mesma
// viagem ao banco.
func (r *PostgresRepository) UpsertTriage(ctx context.Context, t domain.Triage) error {
	const q = `
		INSERT INTO scanning_finding_triage (project_id, fingerprint, status, reason, actor_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (project_id, fingerprint) DO UPDATE
			SET status = EXCLUDED.status,
			    reason = EXCLUDED.reason,
			    actor_user_id = EXCLUDED.actor_user_id,
			    updated_at = now()
	`
	if _, err := r.pool.Exec(ctx, q, t.ProjectID, t.Fingerprint, t.Status, t.Reason, t.ActorUserID); err != nil {
		return fmt.Errorf("scanning: upsert triage for project %s fingerprint %s: %w", t.ProjectID, t.Fingerprint, err)
	}
	return nil
}

// DeleteTriage "reabre" um achado — ver domain.TriageRepository. Apagar
// uma linha que já não existe não é erro (o mesmo DELETE que reabre um
// achado já triado também serve pra um clique duplo/idempotente do
// frontend em um achado já aberto).
func (r *PostgresRepository) DeleteTriage(ctx context.Context, projectID uuid.UUID, fingerprint string) error {
	const q = `DELETE FROM scanning_finding_triage WHERE project_id = $1 AND fingerprint = $2`
	if _, err := r.pool.Exec(ctx, q, projectID, fingerprint); err != nil {
		return fmt.Errorf("scanning: delete triage for project %s fingerprint %s: %w", projectID, fingerprint, err)
	}
	return nil
}

// ListTriageByProject retorna toda triagem de um projeto, indexada por
// fingerprint — ver domain.TriageRepository. Um mapa vazio (projeto sem
// nenhum achado triado ainda) não é erro.
func (r *PostgresRepository) ListTriageByProject(ctx context.Context, projectID uuid.UUID) (map[string]domain.Triage, error) {
	const q = `
		SELECT project_id, fingerprint, status, reason, actor_user_id, created_at, updated_at
		FROM scanning_finding_triage
		WHERE project_id = $1
	`
	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list triage for project %s: %w", projectID, err)
	}
	defer rows.Close()

	out := make(map[string]domain.Triage)
	for rows.Next() {
		var t domain.Triage
		var status string
		if err := rows.Scan(&t.ProjectID, &t.Fingerprint, &status, &t.Reason, &t.ActorUserID, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning: scan triage row: %w", err)
		}
		t.Status = domain.TriageStatus(status)
		out[t.Fingerprint] = t
	}
	return out, rows.Err()
}

var _ domain.TriageRepository = (*PostgresRepository)(nil)
