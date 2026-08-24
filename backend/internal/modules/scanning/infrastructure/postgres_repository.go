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
		INSERT INTO scan_findings (scan_id, scanner, target, finding_id, owasp_category, severity, description, file, line, snippet, fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	batch := &pgx.Batch{}
	for _, f := range findings {
		// Fingerprint calculado aqui, na hora de gravar — não pelo
		// CodeScanner (ver domain.Fingerprint): identifica o "mesmo"
		// achado entre re-scans do mesmo alvo/projeto (Fase 10).
		fingerprint := domain.Fingerprint(scanner, f.ID, f.File, f.Line)
		batch.Queue(q, scanID, scanner, target, f.ID, f.OWASPCategory, f.Severity, f.Description, f.File, f.Line, f.Snippet, fingerprint)
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

// findingColumns é a lista de colunas compartilhada por ListByScanID e
// ListRecent — as duas leem a mesma forma de linha, só o WHERE/LIMIT muda.
const findingColumns = `id, scan_id, scanner, target, finding_id, owasp_category, severity, description, file, line, snippet, fingerprint, created_at`

// findingSeverityOrder ordena da mais grave pra menos grave — compartilhado
// pelas duas queries abaixo.
const findingSeverityOrder = `
	CASE severity
		WHEN 'CRITICAL' THEN 0
		WHEN 'HIGH' THEN 1
		WHEN 'MEDIUM' THEN 2
		WHEN 'LOW' THEN 3
	END,
	created_at DESC
`

// ListByScanID retorna todo achado de scanID, mais grave/recente primeiro.
// Lê direto pelo pool (nunca precisa de atomicidade transacional com mais
// nada, ao contrário de SaveFindings).
func (r *PostgresRepository) ListByScanID(ctx context.Context, scanID uuid.UUID) ([]domain.PersistedFinding, error) {
	q := fmt.Sprintf(`SELECT %s FROM scan_findings WHERE scan_id = $1 ORDER BY %s`, findingColumns, findingSeverityOrder)
	rows, err := r.pool.Query(ctx, q, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings for scan %s: %w", scanID, err)
	}
	defer rows.Close()
	return scanFindingRows(rows)
}

// ListByScanIDs retorna todo achado de QUALQUER um dos scanIDs (Fase 12 —
// histórico de achados de um projeto) — sem ordenação por severidade
// aqui, quem chama (application.Service.ListProjectFindingsHistory)
// agrupa por Fingerprint em memória e decide sua própria ordem pro
// resultado final.
func (r *PostgresRepository) ListByScanIDs(ctx context.Context, scanIDs []uuid.UUID) ([]domain.PersistedFinding, error) {
	if len(scanIDs) == 0 {
		return nil, nil
	}
	q := fmt.Sprintf(`SELECT %s FROM scan_findings WHERE scan_id = ANY($1)`, findingColumns)
	rows, err := r.pool.Query(ctx, q, scanIDs)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings for %d scans: %w", len(scanIDs), err)
	}
	defer rows.Close()
	return scanFindingRows(rows)
}

// ListRecent retorna os achados mais graves/recentes entre TODAS as
// execuções de scan, até limit linhas — o feed que a Fase 9 (UI) usa.
func (r *PostgresRepository) ListRecent(ctx context.Context, limit int) ([]domain.PersistedFinding, error) {
	q := fmt.Sprintf(`SELECT %s FROM scan_findings ORDER BY %s LIMIT $1`, findingColumns, findingSeverityOrder)
	rows, err := r.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list recent findings: %w", err)
	}
	defer rows.Close()
	return scanFindingRows(rows)
}

func scanFindingRows(rows pgx.Rows) ([]domain.PersistedFinding, error) {
	var out []domain.PersistedFinding
	for rows.Next() {
		var f domain.PersistedFinding
		var severity string
		if err := rows.Scan(&f.RecordID, &f.ScanID, &f.Scanner, &f.Target, &f.ID, &f.OWASPCategory, &severity, &f.Description, &f.File, &f.Line, &f.Snippet, &f.FindingFingerprint, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning: scan finding row: %w", err)
		}
		f.Severity = domain.Severity(severity)
		out = append(out, f)
	}
	return out, rows.Err()
}
