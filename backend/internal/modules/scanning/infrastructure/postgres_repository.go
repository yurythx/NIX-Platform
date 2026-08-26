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

// ListRecentPage retorna uma página de achados, mais grave/recente
// primeiro, mais o total de linhas na tabela inteira (sem paginação) —
// ver domain.Repository. count(*) OVER() calcula o total na MESMA
// query (uma window function sobre o resultado já filtrado/ordenado,
// antes do OFFSET/LIMIT recortar a página) — uma segunda viagem
// separada ao banco só pra contar seria mais simples de ler, mas
// dobraria o custo de toda chamada a este método, que a Fase 9 (UI) já
// faz a cada carregamento de /seguranca.
func (r *PostgresRepository) ListRecentPage(ctx context.Context, offset, limit int) ([]domain.PersistedFinding, int64, error) {
	q := fmt.Sprintf(`SELECT %s, count(*) OVER() FROM scan_findings ORDER BY %s OFFSET $1 LIMIT $2`, findingColumns, findingSeverityOrder)
	rows, err := r.pool.Query(ctx, q, offset, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("scanning: list recent findings page: %w", err)
	}
	defer rows.Close()

	var out []domain.PersistedFinding
	var total int64
	for rows.Next() {
		var f domain.PersistedFinding
		var severity string
		if err := rows.Scan(&f.RecordID, &f.ScanID, &f.Scanner, &f.Target, &f.ID, &f.OWASPCategory, &severity, &f.Description, &f.File, &f.Line, &f.Snippet, &f.FindingFingerprint, &f.CreatedAt, &total); err != nil {
			return nil, 0, fmt.Errorf("scanning: scan finding page row: %w", err)
		}
		f.Severity = domain.Severity(severity)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("scanning: scan finding page rows: %w", err)
	}
	// count(*) OVER() só aparece numa linha se a página tiver ALGUMA
	// linha — uma página vazia (offset além do total, ex.: página 99 de
	// uma tabela com 3 achados) nunca escreve `total`, então ficaria 0
	// mesmo que a tabela tenha achados — errado (o cliente perguntaria
	// "página 99 de quantas ao todo?" e receberia "0 ao todo", quando na
	// verdade só essa página específica está vazia). Uma segunda consulta,
	// só pro caso raro de uma página sem nenhuma linha, corrige isso sem
	// pagar o custo dessa consulta extra no caminho comum (página com
	// conteúdo).
	if len(out) == 0 {
		if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM scan_findings`).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("scanning: count findings for empty page: %w", err)
		}
	}
	return out, total, nil
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
