// Arquivo scan_orchestration.go: a mecânica de rodar N scanners em
// paralelo contra o mesmo alvo (runConcurrently[Local]), acompanhar
// o progresso de cada um (markScannerRunning/Finished,
// reportScannerProgress) e reconciliar os resultados em outcomes
// (scannerOutcome, split/summarize/encode/decodeFailures) —
// consumida por ProcessScanJob/HandleScanDeadLetter, os dois
// pontos de entrada que o worker chama pra processar um job de
// scan. Extraído de scans.go (ver nota lá) — mesmo pacote
// application, mesmo *Service.
package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
)

// scannerOutcome é o resultado da execução de um scanner contra um alvo —
// exatamente um erro OU achados/pacotes (nunca erro junto com um dos dois),
// usado tanto pelo caminho síncrono (RunScan, sempre uma lista de um)
// quanto pelo assíncrono (ProcessScanJob via runConcurrently, uma lista de
// N). packages só é populado por um scanner que também implementa
// domain.InventoryProvider (Fase 11 — hoje só Syft); a maioria dos
// scanners nunca preenche este campo.
type scannerOutcome struct {
	scanner  string
	findings []domain.Finding
	packages []domain.Package
	err      error
}

// runConcurrently executa cada scanner em scannerNames contra target em
// paralelo (Fase 7 do roadmap — Orquestração concorrente), retornando o
// resultado de cada um na mesma ordem de scannerNames.
//
// O roadmap descreve isto como "goroutines + errgroup" — usa goroutines
// puras + sync.WaitGroup aqui, deliberadamente sem o pacote errgroup: o
// comportamento padrão de errgroup.Group.WithContext cancela o ctx do
// grupo inteiro assim que o primeiro Go() retorna erro, exatamente o
// oposto do que esta fase pede ("cancelando um scanner que trava sem
// derrubar os outros"). Evitar errgroup.WithContext aqui não é
// cosmético: é o que garante essa independência. Cada scanner já limita
// seu próprio tempo de execução por dentro (CloneTimeout do git,
// SonarQubeAnalysisTimeout, ZapScanTimeout, ...) — não precisa de mais um
// nível de timeout aqui, só isolamento: a falha ou lentidão de um nunca
// afeta os demais, porque cada goroutine roda de forma completamente
// independente e nenhuma jamais cancela o contexto de outra.
// jobID vira o progresso individual de cada scanner (StartScannerRun/
// FinishScannerRun, ver markScannerRunning/markScannerFinished abaixo) —
// o que GetScanStatus expõe pra dar visibilidade em tempo real de qual
// scanner está rodando agora e qual já terminou, pedido explícito do
// usuário ("um painel visual dos testes rodando... quero saber qual
// teste está rodando, quanto falta pra acabar"), sem o qual um job
// "processing" era uma caixa preta do início ao fim.
func (s *Service) runConcurrently(ctx context.Context, jobID uuid.UUID, scannerNames []string, target string) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	var wg sync.WaitGroup
	for i, name := range scannerNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			scanner, ok := s.scanners[name]
			if !ok {
				// Defensivo: CreateScanJob já validou isto na criação do
				// job, mas um scanner poderia ter sido desregistrado
				// entre a criação e o processamento (ex.: um deploy). Não
				// é uma falha transitória do próprio scanner, mas ainda
				// assim é só a falha DESTE scanner — os demais continuam.
				err := fmt.Errorf("scanner %q not registered", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerRunning(ctx, jobID, name)
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			s.markScannerRunning(ctx, jobID, name)
			findings, err := s.executeScanner(ctx, jobID, name, scanner, target)
			packages := inventoryFor(ctx, scanner, target, &err)
			outcomes[i] = scannerOutcome{scanner: name, findings: findings, packages: packages, err: err}
			s.markScannerFinished(ctx, jobID, name, findings, err)
		}(i, name)
	}
	wg.Wait()
	return outcomes
}

// inventoryFor chama Inventory (Fase 11 — Syft) se, e só se, scanner
// também implementar domain.InventoryProvider (type assertion — o mesmo
// scanner pode participar do fluxo de achados, do de inventário, ou dos
// dois, ver docs/roadmap-secops-orchestrator.md). Pulado quando *err já
// aponta uma falha (ex.: Execute já falhou) — não faz sentido tentar
// inventariar um alvo que o próprio Execute não conseguiu processar. Um
// erro de Inventory sobrescreve *err: para um scanner cujo Execute é um
// no-op (Syft, que não produz achados), Inventory é a única chamada real
// que pode falhar de verdade, então o erro dela precisa ser o que o
// chamador (runConcurrently/RunScan) trata como a falha do scanner.
func inventoryFor(ctx context.Context, scanner domain.CodeScanner, target string, err *error) []domain.Package {
	if *err != nil {
		return nil
	}
	inv, ok := scanner.(domain.InventoryProvider)
	if !ok {
		return nil
	}
	packages, invErr := inv.Inventory(ctx, target)
	if invErr != nil {
		*err = invErr
		return nil
	}
	return packages
}

// runConcurrentlyLocal é o par de runConcurrently pro caso de um projeto
// criado por upload (Fase 10): em vez de scanner.Execute(ctx, target)
// (que clonaria um alvo git), chama scanner.(domain.LocalScanner).
// ExecuteLocal(ctx, dir) contra um diretório JÁ extraído — dir precisa
// vir de ZipExtractor.ExtractZip, chamado uma vez só por quem chama esta
// função (ProcessScanJob), não aqui: todo scanner deste job compartilha o
// MESMO diretório, então a extração acontece uma única vez pro job
// inteiro, nunca uma vez por scanner.
//
// Um scanner sem LocalScanner chegando aqui seria um bug de wiring —
// createScanJob já rejeita isso na CRIAÇÃO do job (ver "unsupported"
// acima) — mas o mesmo cenário defensivo de runConcurrently (scanner
// desregistrado entre a criação e o processamento) se aplica igual aqui,
// por isso a checagem continua, nunca um type assertion que entra em
// pânico.
func (s *Service) runConcurrentlyLocal(ctx context.Context, jobID uuid.UUID, scannerNames []string, dir string) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	var wg sync.WaitGroup
	for i, name := range scannerNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			scanner, ok := s.scanners[name]
			if !ok {
				err := fmt.Errorf("scanner %q not registered", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerRunning(ctx, jobID, name)
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			s.markScannerRunning(ctx, jobID, name)
			local, ok := scanner.(domain.LocalScanner)
			if !ok {
				err := fmt.Errorf("scanner %q does not support scanning a local directory (upload-based project)", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			findings, err := local.ExecuteLocal(ctx, dir)
			packages := inventoryForLocal(ctx, scanner, dir, &err)
			outcomes[i] = scannerOutcome{scanner: name, findings: findings, packages: packages, err: err}
			s.markScannerFinished(ctx, jobID, name, findings, err)
		}(i, name)
	}
	wg.Wait()
	return outcomes
}

// inventoryForLocal é o par local de inventoryFor — mesma lógica, só que
// via domain.LocalInventoryProvider.InventoryLocal em vez de
// InventoryProvider.Inventory.
func inventoryForLocal(ctx context.Context, scanner domain.CodeScanner, dir string, err *error) []domain.Package {
	if *err != nil {
		return nil
	}
	inv, ok := scanner.(domain.LocalInventoryProvider)
	if !ok {
		return nil
	}
	packages, invErr := inv.InventoryLocal(ctx, dir)
	if invErr != nil {
		*err = invErr
		return nil
	}
	return packages
}

// failAllScanners marca todo scanner de scannerNames como falho com o
// MESMO err — usado só quando algo impede QUALQUER scanner de sequer
// começar (Fase 10: falha ao extrair o .zip do projeto, ou o projeto
// sumiu entre a criação do job e o processamento) — sem isto, nenhuma
// linha apareceria em scanning_scanner_runs pra explicar por que o job
// falhou, e o painel de progresso ficaria vazio em vez de mostrar CADA
// scanner pedido com o motivo real.
func (s *Service) failAllScanners(ctx context.Context, jobID uuid.UUID, scannerNames []string, err error) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	for i, name := range scannerNames {
		s.markScannerRunning(ctx, jobID, name)
		s.markScannerFinished(ctx, jobID, name, nil, err)
		outcomes[i] = scannerOutcome{scanner: name, err: err}
	}
	return outcomes
}

// markScannerRunning/markScannerFinished são escritas best-effort de
// progresso (ver domain.Repository.StartScannerRun/FinishScannerRun): uma
// falha aqui só vira um log — nunca derruba o scan em si, porque o
// progresso é observabilidade, não parte da garantia transacional de
// achados/eventos que persistCompletion tem.
func (s *Service) markScannerRunning(ctx context.Context, jobID uuid.UUID, name string) {
	if err := s.repo.StartScannerRun(ctx, jobID, name); err != nil {
		s.logger.Warn("scanning: failed to record scanner start (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", err))
	}
}

func (s *Service) markScannerFinished(ctx context.Context, jobID uuid.UUID, name string, findings []domain.Finding, err error) {
	status := domain.ScannerRunSucceeded
	errMsg := ""
	if err != nil {
		status = domain.ScannerRunFailed
		errMsg = err.Error()
	}
	if writeErr := s.repo.FinishScannerRun(ctx, jobID, name, status, len(findings), errMsg); writeErr != nil {
		s.logger.Warn("scanning: failed to record scanner finish (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", writeErr))
	}
}

// reportScannerProgress grava o sub-progresso de UM scanner ainda
// rodando (ver domain.ProgressReportingScanner) — mesma escrita
// best-effort de markScannerRunning/markScannerFinished, chamada
// potencialmente muitas vezes por scan (ZapScanner chama a cada 5s
// enquanto spider/scan ativo não terminam), então o log de falha aqui é
// Debug, não Warn: um Warn por tentativa acabaria inundando o log de um
// scan de 20 minutos sem trazer nada de novo depois da primeira falha.
func (s *Service) reportScannerProgress(ctx context.Context, jobID uuid.UUID, name, detail string) {
	if err := s.repo.UpdateScannerRunProgress(ctx, jobID, name, detail); err != nil {
		s.logger.Debug("scanning: failed to record scanner progress (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", err))
	}
}

// executeScanner chama Execute — ou, quando scanner também implementa
// domain.ProgressReportingScanner (hoje: só ZapScanner), ExecuteWithProgress
// com um reporter que grava em scanning_scanner_runs.progress_detail.
// Extraído de runConcurrently pra manter a checagem de sub-progresso num
// único lugar, nunca duplicada — runConcurrentlyLocal nunca chama isto:
// nenhum scanner que implementa LocalScanner (Trivy/Gitleaks/Semgrep/
// Syft) hoje também implementa ProgressReportingScanner, e ZAP nunca
// implementa LocalScanner (ataca uma URL viva, nunca um diretório).
func (s *Service) executeScanner(ctx context.Context, jobID uuid.UUID, name string, scanner domain.CodeScanner, target string) ([]domain.Finding, error) {
	reporting, ok := scanner.(domain.ProgressReportingScanner)
	if !ok {
		return scanner.Execute(ctx, target)
	}
	return reporting.ExecuteWithProgress(ctx, target, func(detail string) {
		s.reportScannerProgress(ctx, jobID, name, detail)
	})
}

func splitOutcomes(outcomes []scannerOutcome) (succeeded, failed []scannerOutcome) {
	for _, o := range outcomes {
		if o.err != nil {
			failed = append(failed, o)
		} else {
			succeeded = append(succeeded, o)
		}
	}
	return succeeded, failed
}

func outcomeNames(outcomes []scannerOutcome) []string {
	names := make([]string, len(outcomes))
	for i, o := range outcomes {
		names[i] = o.scanner
	}
	return names
}

func summarizeFailures(failed []scannerOutcome) string {
	parts := make([]string, len(failed))
	for i, o := range failed {
		parts[i] = fmt.Sprintf("%s: %v", o.scanner, o.err)
	}
	return strings.Join(parts, "; ")
}

// newScannerFailure extrai de scannerOutcome.err a mesma classificação de
// erro (Code) que a camada HTTP já usa pra decidir status code —
// reaproveitada aqui pra que quem consultar o resultado de um job (ver
// GetScanStatus) saiba o TIPO do erro sem fazer parsing de string livre.
// Um erro que não veio de apperrors não deveria acontecer nos
// CodeScanner de hoje (todos devolvem *apperrors.Error nas suas falhas
// conhecidas), mas defensivo contra um bug futuro que devolva um erro
// "cru" — cai em CodeInternal em vez de entrar em pânico ou perder a
// mensagem.
func newScannerFailure(o scannerOutcome) domain.ScannerFailure {
	if appErr, ok := apperrors.As(o.err); ok {
		return domain.ScannerFailure{Scanner: o.scanner, Code: string(appErr.Code), Message: appErr.Message}
	}
	return domain.ScannerFailure{Scanner: o.scanner, Code: string(apperrors.CodeInternal), Message: o.err.Error()}
}

func scannerFailures(outcomes []scannerOutcome) []domain.ScannerFailure {
	out := make([]domain.ScannerFailure, len(outcomes))
	for i, o := range outcomes {
		out[i] = newScannerFailure(o)
	}
	return out
}

// encodeFailures serializa as falhas de scanner de failed para o texto
// gravado em jobs.error (TEXT genérico, compartilhado com todo outro
// tipo de job desta plataforma) — JSON, não texto livre, pra que
// GetScanStatus consiga decodificar de volta em []domain.ScannerFailure
// sem parsing de string. summarizeFailures (texto livre, pensado pra
// leitura em log) continua existindo separadamente só pras mensagens de
// log desta package — os dois formatos servem públicos diferentes.
func encodeFailures(failed []scannerOutcome) string {
	data, err := json.Marshal(scannerFailures(failed))
	if err != nil {
		// Defensivo: json.Marshal de um []domain.ScannerFailure (só
		// campos string) não deveria falhar nunca — preferimos um
		// texto degradado, ainda útil em log, a perder jobs.error
		// inteiro por causa de um erro de serialização.
		return summarizeFailures(failed)
	}
	return string(data)
}

// ProcessScanJob implementa a execução do lado do worker (mesmo desenho
// de diario_oficial.Service.ProcessJob, incluindo a mesma idempotência
// contra redelivery do RabbitMQ: um job em estado terminal vira um no-op
// em vez de ser reprocessado). O scan_id usado em EventScanCompleted é o
// próprio jobID — não um uuid.New() separado — para que o cliente HTTP
// consiga consultar ListFindings com o mesmo ID recebido de
// CreateScanJob.
//
// Todo scanner do payload roda em paralelo (runConcurrently, Fase 7).
// Falha parcial (alguns scanners tiveram sucesso, outros não) marca o job
// como concluído, não como falho — reprocessar o job inteiro numa
// redelivery re-executaria também os scanners que JÁ tiveram sucesso,
// arriscando achados duplicados gravados sob o mesmo scan_id; o(s)
// scanner(s) que falhou(aram) fica(m) registrado(s) no resultado do job e
// nos metadados de auditoria, não silenciosamente perdido(s). Só quando
// TODOS os scanners falham o job inteiro é marcado como falho, pra ser
// reprocessado (mesma semântica de retry de antes desta fase).
func (s *Service) ProcessScanJob(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("scanning: load job %s: %w", jobID, err)
	}
	if current.Status == jobs.StatusCompleted || current.Status == jobs.StatusDeadLetter {
		s.logger.Info("scanning: duplicate delivery of an already-finished job, skipping",
			slog.String("job_id", jobID.String()), slog.String("status", string(current.Status)))
		return nil
	}

	var payload scanJobPayload
	if err := json.Unmarshal(current.Payload, &payload); err != nil {
		return fmt.Errorf("scanning: decode job %s payload: %w", jobID, err)
	}

	// MarkProcessing sozinho, na SUA PRÓPRIA transação, ANTES de
	// runConcurrently — antes desta mudança, o job ficava "queued" (não
	// "processing") pelo tempo INTEIRO que os scanners rodavam, porque
	// MarkProcessing só era chamado dentro da mesma transação que
	// MarkCompleted/MarkFailed, DEPOIS de runConcurrently já ter
	// terminado. Um painel de progresso consultando GetScanStatus via
	// polling via via um job "queued" o tempo todo mesmo com scanners
	// visivelmente "running" em ScannerRuns — confuso pro pedido do
	// usuário de saber "qual teste está rodando". CanTransition permite
	// tanto queued->processing (primeira tentativa) quanto
	// failed->processing (retry depois de MarkFailed), então isto nunca
	// rejeita uma transição válida.
	if err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		return s.jobsRepo.MarkProcessing(ctx, tx, jobID)
	}); err != nil {
		return fmt.Errorf("scanning: mark job %s processing: %w", jobID, err)
	}

	// Fase 10 — projeto criado por upload .zip: ProjectID preenchido (ver
	// scanJobPayload.ProjectID) faz este job re-buscar o domain.Project
	// pra saber o SourceType de verdade — um projeto GIT segue o caminho
	// de sempre abaixo (clona payload.Target normalmente, runConcurrently
	// sem nenhuma mudança de comportamento); um projeto UPLOAD não tem
	// alvo git nenhum pra clonar, então extrai o .zip do projeto pro
	// volume compartilhado e escaneia esse diretório (runConcurrentlyLocal)
	// em vez de clonar. payload.Target já vem certo dos dois jeitos desde
	// createScanJob/CreateProjectScanJob (o alvo git, ou o rótulo
	// sintético "upload:<projeto>" — ver uploadTarget) — persistCompletion
	// abaixo usa esse mesmo valor sempre, nunca recomputado aqui.
	var outcomes []scannerOutcome
	if payload.ProjectID != nil {
		project, err := s.repo.GetProject(ctx, *payload.ProjectID)
		if err != nil {
			outcomes = s.failAllScanners(ctx, jobID, payload.Scanners, fmt.Errorf("scanning: load project %s: %w", *payload.ProjectID, err))
		} else if project.SourceType == domain.ProjectSourceUpload {
			dir, cleanup, extractErr := s.zipExtractor.ExtractZip(project.UploadZip)
			if extractErr != nil {
				outcomes = s.failAllScanners(ctx, jobID, payload.Scanners, extractErr)
			} else {
				defer cleanup()
				outcomes = s.runConcurrentlyLocal(ctx, jobID, payload.Scanners, dir)
			}
		} else {
			outcomes = s.runConcurrently(ctx, jobID, payload.Scanners, payload.Target)
		}
	} else {
		outcomes = s.runConcurrently(ctx, jobID, payload.Scanners, payload.Target)
	}
	succeeded, failed := splitOutcomes(outcomes)

	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if len(succeeded) == 0 {
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, encodeFailures(failed))
		}
		return s.jobsRepo.MarkCompleted(ctx, tx, jobID, struct {
			SucceededScanners []string                `json:"succeeded_scanners"`
			FailedScanners    []domain.ScannerFailure `json:"failed_scanners,omitempty"`
		}{SucceededScanners: outcomeNames(succeeded), FailedScanners: scannerFailures(failed)})
	})
	if txErr != nil {
		return fmt.Errorf("scanning: record processing outcome: %w", txErr)
	}

	if len(succeeded) == 0 {
		s.logger.Warn("scanning: all scanners failed, will retry",
			slog.String("job_id", jobID.String()), slog.String("errors", summarizeFailures(failed)))
		return fmt.Errorf("scanning: all scanners failed: %s", summarizeFailures(failed))
	}

	if err := s.persistCompletion(ctx, jobID, payload.Target, correlationID, outcomes); err != nil {
		return err
	}

	if len(failed) > 0 {
		s.logger.Warn("scanning: job completed with partial failure",
			slog.String("job_id", jobID.String()), slog.Any("succeeded", outcomeNames(succeeded)),
			slog.String("failed", summarizeFailures(failed)))
	}

	if s.audit != nil {
		totalFindings := 0
		for _, o := range succeeded {
			totalFindings += len(o.findings)
		}
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata: map[string]any{
				"scanners":        outcomeNames(succeeded),
				"failed_scanners": outcomeNames(failed),
				"target":          payload.Target,
				"findings_count":  totalFindings,
			},
		})
	}
	return nil
}

// HandleScanDeadLetter é chamado quando o RabbitMQ já esgotou
// RABBITMQ_MAX_RETRIES para a mensagem deste job: o desfecho terminal, tal
// qual diario_oficial.Service.HandleDeadLetter — antes disso, toda falha
// era tratada como "ainda pode ter sucesso numa nova tentativa" (ver
// ProcessScanJob) e não publicava EventScanFailed.
//
// O motivo gravado como jobs.error não é mais um texto genérico fixo
// ("max retries exceeded"): isso descartava silenciosamente o motivo de
// verdade (qual scanner falhou, com que tipo de erro e mensagem) que
// ProcessScanJob já tinha gravado na ÚLTIMA tentativa via MarkFailed —
// bug real, encontrado enquanto o usuário investigava por que um disparo
// de scan "deu errado" e só via "max retries exceeded" no resultado
// final, sem nenhuma pista do motivo. Em vez de sobrescrever, carrega o
// job atual e reaproveita seu jobs.error (já no formato JSON de
// []domain.ScannerFailure produzido por encodeFailures) verbatim — só
// cai no texto genérico se, por algum motivo defensivo (job nunca passou
// por MarkFailed antes de ser dado como esgotado), não houver nada
// gravado ainda.
func (s *Service) HandleScanDeadLetter(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("scanning: load job %s for dead letter: %w", jobID, err)
	}
	reason := "max retries exceeded"
	if current.Error != nil && *current.Error != "" {
		reason = *current.Error
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkDeadLetter(ctx, tx, jobID, reason); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventScanFailed, "job", jobID.String(), correlationID, jobRefPayload{JobID: jobID})
	})
	if err != nil {
		return fmt.Errorf("scanning: handle dead letter: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionScanFailed,
			ResourceType:  "job",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"reason": reason},
		})
	}
	return nil
}
