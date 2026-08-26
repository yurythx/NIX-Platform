package infrastructure

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
)

// PostgresRepository implementa domain.Repository (monitoramento do
// Diário Oficial) contra o PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

var _ domain.Repository = (*PostgresRepository)(nil)

func (r *PostgresRepository) CreateMonitoredTerm(ctx context.Context, term domain.MonitoredTerm) error {
	const q = `
		INSERT INTO diario_oficial_monitored_terms
			(id, label, oab_number, oab_uf, process_number, free_text, active, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.pool.Exec(ctx, q,
		term.ID, term.Label, nullableText(term.OABNumber), nullableText(term.OABState),
		nullableText(term.ProcessNumber), nullableText(term.FreeText), term.Active, term.CreatedBy,
		term.CreatedAt, term.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("diario_oficial: create monitored term: %w", err)
	}
	return nil
}

func (r *PostgresRepository) ListMonitoredTerms(ctx context.Context, onlyActive bool) ([]domain.MonitoredTerm, error) {
	q := `
		SELECT id, label, oab_number, oab_uf, process_number, free_text, active, created_by, last_synced_at, created_at, updated_at
		FROM diario_oficial_monitored_terms
	`
	if onlyActive {
		q += " WHERE active"
	}
	q += " ORDER BY created_at DESC"

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: list monitored terms: %w", err)
	}
	defer rows.Close()

	var out []domain.MonitoredTerm
	for rows.Next() {
		term, err := scanMonitoredTerm(rows)
		if err != nil {
			return nil, fmt.Errorf("diario_oficial: scan monitored term row: %w", err)
		}
		out = append(out, term)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("diario_oficial: monitored term rows: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) GetMonitoredTerm(ctx context.Context, id uuid.UUID) (*domain.MonitoredTerm, error) {
	const q = `
		SELECT id, label, oab_number, oab_uf, process_number, free_text, active, created_by, last_synced_at, created_at, updated_at
		FROM diario_oficial_monitored_terms
		WHERE id = $1
	`
	term, err := scanMonitoredTerm(r.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, apperrors.NotFound(fmt.Sprintf("monitored term %s not found", id))
	}
	return &term, nil
}

func (r *PostgresRepository) DeleteMonitoredTerm(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM diario_oficial_monitored_terms WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("diario_oficial: delete monitored term: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.NotFound(fmt.Sprintf("monitored term %s not found", id))
	}
	return nil
}

func (r *PostgresRepository) UpdateLastSyncedAt(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) error {
	const q = `UPDATE diario_oficial_monitored_terms SET last_synced_at = $2, updated_at = $2 WHERE id = $1`
	if _, err := tx.Exec(ctx, q, id, at); err != nil {
		return fmt.Errorf("diario_oficial: update last synced at: %w", err)
	}
	return nil
}

// UpsertPublication grava pub se external_id ainda não existe — ver
// domain.Repository.UpsertPublication. `RETURNING id` + a checagem de
// linhas afetadas é como distinguimos "inseriu" de "já existia": um
// ON CONFLICT DO NOTHING não devolve linha nenhuma quando não insere
// nada, então uma segunda consulta (só no caso de conflito) busca o id
// já existente.
func (r *PostgresRepository) UpsertPublication(ctx context.Context, tx pgx.Tx, pub domain.Publication) (uuid.UUID, bool, error) {
	const insertQ = `
		INSERT INTO diario_oficial_publications
			(id, external_id, tribunal, orgao, tipo_comunicacao, texto, process_number, process_number_masked, availability_date, link, raw_payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (external_id) DO NOTHING
		RETURNING id
	`
	var storedID uuid.UUID
	err := tx.QueryRow(ctx, insertQ,
		pub.ID, pub.ExternalID, pub.Tribunal, pub.Orgao, pub.TipoComunicacao, pub.Texto,
		pub.ProcessNumber, pub.ProcessNumberMasked, pub.AvailabilityDate, pub.Link, pub.RawPayload, pub.CreatedAt,
	).Scan(&storedID)
	if err == nil {
		return storedID, true, nil
	}
	if err != pgx.ErrNoRows {
		return uuid.Nil, false, fmt.Errorf("diario_oficial: upsert publication: %w", err)
	}

	// ON CONFLICT DO NOTHING não retornou linha — já existia. Busca o id
	// já existente pelo external_id, a chave natural de deduplicação.
	const selectQ = `SELECT id FROM diario_oficial_publications WHERE external_id = $1`
	if err := tx.QueryRow(ctx, selectQ, pub.ExternalID).Scan(&storedID); err != nil {
		return uuid.Nil, false, fmt.Errorf("diario_oficial: load existing publication by external_id: %w", err)
	}
	return storedID, false, nil
}

func (r *PostgresRepository) CreateMatch(ctx context.Context, tx pgx.Tx, publicationID, monitoredTermID uuid.UUID) (bool, error) {
	const q = `
		INSERT INTO diario_oficial_publication_matches (id, publication_id, monitored_term_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (publication_id, monitored_term_id) DO NOTHING
	`
	tag, err := tx.Exec(ctx, q, uuid.New(), publicationID, monitoredTermID)
	if err != nil {
		return false, fmt.Errorf("diario_oficial: create match: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

const matchedPublicationColumns = `
	p.id, p.external_id, p.tribunal, p.orgao, p.tipo_comunicacao, p.texto,
	p.process_number, p.process_number_masked, p.availability_date, p.link, p.raw_payload, p.created_at,
	m.monitored_term_id, t.label, m.matched_at
`

func (r *PostgresRepository) ListPublicationsForTerm(ctx context.Context, termID uuid.UUID, params pagination.Params) ([]domain.MatchedPublication, int64, error) {
	q := fmt.Sprintf(`
		SELECT %s, count(*) OVER()
		FROM diario_oficial_publication_matches m
		JOIN diario_oficial_publications p ON p.id = m.publication_id
		JOIN diario_oficial_monitored_terms t ON t.id = m.monitored_term_id
		WHERE m.monitored_term_id = $1
		ORDER BY m.matched_at DESC
		OFFSET $2 LIMIT $3
	`, matchedPublicationColumns)
	return r.queryMatchedPublicationsPage(ctx, q, []any{termID, params.Offset(), params.Limit()},
		`SELECT count(*) FROM diario_oficial_publication_matches WHERE monitored_term_id = $1`, []any{termID})
}

func (r *PostgresRepository) ListRecentMatches(ctx context.Context, params pagination.Params) ([]domain.MatchedPublication, int64, error) {
	q := fmt.Sprintf(`
		SELECT %s, count(*) OVER()
		FROM diario_oficial_publication_matches m
		JOIN diario_oficial_publications p ON p.id = m.publication_id
		JOIN diario_oficial_monitored_terms t ON t.id = m.monitored_term_id
		ORDER BY m.matched_at DESC
		OFFSET $1 LIMIT $2
	`, matchedPublicationColumns)
	return r.queryMatchedPublicationsPage(ctx, q, []any{params.Offset(), params.Limit()},
		`SELECT count(*) FROM diario_oficial_publication_matches`, nil)
}

// queryMatchedPublicationsPage compartilha o scan de linha e o fallback
// de contagem pra página vazia entre ListPublicationsForTerm (escopado a
// um termo) e ListRecentMatches (todo termo) — mesmo raciocínio de
// scanning.PostgresRepository.ListRecentPage's `count(*) OVER()` +
// fallback: a window function só aparece numa linha se a página tiver
// ALGUMA linha, então uma página vazia (offset além do total) precisa de
// uma segunda consulta só pra saber o total de verdade.
func (r *PostgresRepository) queryMatchedPublicationsPage(ctx context.Context, q string, args []any, emptyCountQ string, emptyCountArgs []any) ([]domain.MatchedPublication, int64, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("diario_oficial: list matched publications: %w", err)
	}
	defer rows.Close()

	var out []domain.MatchedPublication
	var total int64
	for rows.Next() {
		var mp domain.MatchedPublication
		if err := rows.Scan(
			&mp.ID, &mp.ExternalID, &mp.Tribunal, &mp.Orgao, &mp.TipoComunicacao, &mp.Texto,
			&mp.ProcessNumber, &mp.ProcessNumberMasked, &mp.AvailabilityDate, &mp.Link, &mp.RawPayload, &mp.CreatedAt,
			&mp.MonitoredTermID, &mp.MonitoredTermLabel, &mp.MatchedAt, &total,
		); err != nil {
			return nil, 0, fmt.Errorf("diario_oficial: scan matched publication row: %w", err)
		}
		out = append(out, mp)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("diario_oficial: matched publication rows: %w", err)
	}
	if len(out) == 0 {
		if err := r.pool.QueryRow(ctx, emptyCountQ, emptyCountArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("diario_oficial: count matched publications for empty page: %w", err)
		}
	}
	return out, total, nil
}

// rowScanner abstrai pgx.Row/pgx.Rows — ambos têm Scan(...) error, o que
// scanMonitoredTerm precisa pra servir tanto GetMonitoredTerm (uma linha)
// quanto ListMonitoredTerms (várias).
type rowScanner interface {
	Scan(dest ...any) error
}

func scanMonitoredTerm(row rowScanner) (domain.MonitoredTerm, error) {
	var t domain.MonitoredTerm
	var oabNumber, oabState, processNumber, freeText *string
	if err := row.Scan(&t.ID, &t.Label, &oabNumber, &oabState, &processNumber, &freeText, &t.Active, &t.CreatedBy, &t.LastSyncedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return domain.MonitoredTerm{}, err
	}
	t.OABNumber = stringOrEmpty(oabNumber)
	t.OABState = stringOrEmpty(oabState)
	t.ProcessNumber = stringOrEmpty(processNumber)
	t.FreeText = stringOrEmpty(freeText)
	return t, nil
}

func nullableText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
