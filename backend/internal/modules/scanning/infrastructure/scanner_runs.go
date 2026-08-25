package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// StartScannerRun grava (ou reinicia, numa redelivery do mesmo job) a
// linha de progresso de scanner dentro de jobID — ver
// domain.Repository.StartScannerRun. Upsert, não insert simples: a chave
// primária é (job_id, scanner), então uma segunda tentativa do mesmo
// scanner no mesmo job (retry depois de MarkFailed) reaproveita a linha
// existente em vez de colidir, sempre voltando pro estado "running"
// (finished_at/findings_count/error voltam a NULL — a tentativa anterior
// não faz mais sentido mostrar como progresso desta).
func (r *PostgresRepository) StartScannerRun(ctx context.Context, jobID uuid.UUID, scanner string) error {
	const q = `
		INSERT INTO scanning_scanner_runs (job_id, scanner, status, started_at, finished_at, findings_count, error)
		VALUES ($1, $2, 'running', now(), NULL, NULL, NULL)
		ON CONFLICT (job_id, scanner) DO UPDATE
			SET status = 'running', started_at = now(), finished_at = NULL, findings_count = NULL, error = NULL
	`
	if _, err := r.pool.Exec(ctx, q, jobID, scanner); err != nil {
		return fmt.Errorf("scanning: start scanner run: %w", err)
	}
	return nil
}

// FinishScannerRun registra o desfecho de UM scanner — ver
// domain.Repository.FinishScannerRun.
func (r *PostgresRepository) FinishScannerRun(ctx context.Context, jobID uuid.UUID, scanner string, status domain.ScannerRunStatus, findingsCount int, errMsg string) error {
	const q = `
		UPDATE scanning_scanner_runs
		SET status = $3, finished_at = now(), findings_count = $4, error = NULLIF($5, ''), progress_detail = NULL
		WHERE job_id = $1 AND scanner = $2
	`
	// findings_count só faz sentido pra quem teve sucesso — NULL nos
	// demais casos, em vez de um 0 que poderia ser confundido com "achou
	// zero problemas" numa falha. progress_detail volta a NULL: um
	// scanner concluído não precisa mais de sub-progresso (ver
	// domain.ScannerRun.ProgressDetail).
	var fc *int
	if status == domain.ScannerRunSucceeded {
		fc = &findingsCount
	}
	if _, err := r.pool.Exec(ctx, q, jobID, scanner, status, fc, errMsg); err != nil {
		return fmt.Errorf("scanning: finish scanner run: %w", err)
	}
	return nil
}

// UpdateScannerRunProgress grava o sub-progresso de UM scanner ainda
// rodando — ver domain.Repository.UpdateScannerRunProgress. Não filtra
// por status = 'running' na cláusula WHERE: se FinishScannerRun já
// correu (corrida rara entre a última chamada do reporter e o retorno de
// Execute), este UPDATE só reescreve um progress_detail que
// FinishScannerRun acabou de zerar — inofensivo, a próxima leitura de
// ListScannerRuns já reflete o job terminado, não este valor solto.
func (r *PostgresRepository) UpdateScannerRunProgress(ctx context.Context, jobID uuid.UUID, scanner, detail string) error {
	const q = `
		UPDATE scanning_scanner_runs
		SET progress_detail = NULLIF($3, '')
		WHERE job_id = $1 AND scanner = $2
	`
	if _, err := r.pool.Exec(ctx, q, jobID, scanner, detail); err != nil {
		return fmt.Errorf("scanning: update scanner run progress: %w", err)
	}
	return nil
}

// ListScannerRuns retorna o progresso de todo scanner de jobID — ver
// domain.Repository.ListScannerRuns.
func (r *PostgresRepository) ListScannerRuns(ctx context.Context, jobID uuid.UUID) ([]domain.ScannerRun, error) {
	const q = `
		SELECT scanner, status, started_at, finished_at, findings_count, COALESCE(error, ''), COALESCE(progress_detail, '')
		FROM scanning_scanner_runs
		WHERE job_id = $1
		ORDER BY started_at ASC
	`
	rows, err := r.pool.Query(ctx, q, jobID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list scanner runs for job %s: %w", jobID, err)
	}
	defer rows.Close()

	var out []domain.ScannerRun
	for rows.Next() {
		var run domain.ScannerRun
		var status string
		if err := rows.Scan(&run.Scanner, &status, &run.StartedAt, &run.FinishedAt, &run.FindingsCount, &run.Error, &run.ProgressDetail); err != nil {
			return nil, fmt.Errorf("scanning: scan scanner run row: %w", err)
		}
		run.Status = domain.ScannerRunStatus(status)
		out = append(out, run)
	}
	return out, rows.Err()
}
