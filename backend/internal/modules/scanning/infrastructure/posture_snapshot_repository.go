package infrastructure

import (
	"context"
	"fmt"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// SaveSnapshot grava (ou substitui, se já existia um snapshot pra esta
// mesma data) o resumo do dia — ver domain.PostureRepository. s.Date é
// truncado pro dia (::date no SQL) — quem chama (application.Service.
// SnapshotSecurityPosture) sempre passa time.Now(), com hora/minuto/
// segundo, mas snapshot_date é DATE puro (migration 000025); o cast
// aqui evita que quem chama precise se lembrar de truncar antes.
func (r *PostgresRepository) SaveSnapshot(ctx context.Context, s domain.PostureSnapshot) error {
	const q = `
		INSERT INTO scanning_posture_snapshots
			(snapshot_date, open_critical, open_high, open_medium, open_low, triaged_count, projects_scanned, created_at, updated_at)
		VALUES ($1::date, $2, $3, $4, $5, $6, $7, now(), now())
		ON CONFLICT (snapshot_date) DO UPDATE
			SET open_critical = EXCLUDED.open_critical,
			    open_high = EXCLUDED.open_high,
			    open_medium = EXCLUDED.open_medium,
			    open_low = EXCLUDED.open_low,
			    triaged_count = EXCLUDED.triaged_count,
			    projects_scanned = EXCLUDED.projects_scanned,
			    updated_at = now()
	`
	if _, err := r.pool.Exec(ctx, q,
		s.Date, s.OpenCritical, s.OpenHigh, s.OpenMedium, s.OpenLow, s.TriagedCount, s.ProjectsScanned,
	); err != nil {
		return fmt.Errorf("scanning: save posture snapshot for %s: %w", s.Date.Format("2006-01-02"), err)
	}
	return nil
}

// ListSnapshots retorna os últimos `days` dias de snapshot, data mais
// antiga primeiro — ver domain.PostureRepository.
func (r *PostgresRepository) ListSnapshots(ctx context.Context, days int) ([]domain.PostureSnapshot, error) {
	// make_interval(days => $1), não ($1 || ' days')::interval: o
	// operador || força o planejador de tipo do pgx a tentar codificar
	// $1 (um int do Go) como texto — falha em tempo de execução ("cannot
	// find encode plan") antes mesmo da query rodar. make_interval
	// aceita o inteiro direto, mesmo padrão já usado em
	// internal/platform/idempotency/postgres.go's Cleanup.
	const q = `
		SELECT snapshot_date, open_critical, open_high, open_medium, open_low, triaged_count, projects_scanned
		FROM scanning_posture_snapshots
		WHERE snapshot_date >= (CURRENT_DATE - make_interval(days => $1))
		ORDER BY snapshot_date ASC
	`
	rows, err := r.pool.Query(ctx, q, days)
	if err != nil {
		return nil, fmt.Errorf("scanning: list posture snapshots: %w", err)
	}
	defer rows.Close()

	var out []domain.PostureSnapshot
	for rows.Next() {
		var s domain.PostureSnapshot
		if err := rows.Scan(&s.Date, &s.OpenCritical, &s.OpenHigh, &s.OpenMedium, &s.OpenLow, &s.TriagedCount, &s.ProjectsScanned); err != nil {
			return nil, fmt.Errorf("scanning: scan posture snapshot row: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

var _ domain.PostureRepository = (*PostgresRepository)(nil)
