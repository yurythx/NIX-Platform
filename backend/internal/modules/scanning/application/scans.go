// Arquivo scans.go: entidade Scan em si — RunScan (síncrono),
// CreateScanJob/CreateProjectScanJob (assíncrono, dispara o job),
// e as consultas de status (GetScanStatus/ListRecentScans/
// ListProjectScans). A mecânica de RODAR vários scanners em
// paralelo e reconciliar os resultados fica em
// scan_orchestration.go — arquivo separado porque scans.go sozinho
// (o resultado de já ter sido extraído de service.go, ver nota lá)
// tinha voltado a passar de 900 linhas, duas responsabilidades bem
// distintas coabitando: "o que é um scan" vs. "como de fato rodar
// um". Mesmo pacote application, mesmo *Service, nenhuma mudança
// de comportamento.
package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
)

// RunScan executa o CodeScanner chamado scannerName contra target,
// persiste os achados e o evento EventScanCompleted atomicamente, e
// retorna os achados encontrados. Bloqueia até o scanner terminar — para
// um scanner potencialmente lento chamado a partir de HTTP, prefira
// CreateScanJob (que também roda vários scanners em paralelo, ver
// ProcessScanJob; RunScan continua limitado a um só, já que quem chama
// direto — testes, uma futura execução agendada — controla exatamente
// qual scanner quer, sem precisar do desenho de job/orquestração).
// requestedBy é opcional (nil para execuções sem um usuário autenticado
// por trás). scanID retornado é o mesmo usado para consultar depois via
// ListFindings — RunScan gera um novo a cada chamada, já que (ao
// contrário de CreateScanJob/ProcessScanJob) não há nenhum jobID
// pré-existente para reaproveitar.
func (s *Service) RunScan(ctx context.Context, scannerName, target string, correlationID uuid.UUID, requestedBy *uuid.UUID) (scanID uuid.UUID, findings []domain.Finding, err error) {
	scanner, ok := s.scanners[scannerName]
	if !ok {
		return uuid.Nil, nil, apperrors.NotFound(fmt.Sprintf("scanner %q not registered", scannerName))
	}

	findings, err = scanner.Execute(ctx, target)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("scanning: execute %q against %q: %w", scannerName, target, err)
	}
	packages := inventoryFor(ctx, scanner, target, &err)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("scanning: inventory %q against %q: %w", scannerName, target, err)
	}

	scanID = uuid.New()
	outcome := scannerOutcome{scanner: scannerName, findings: findings, packages: packages}
	if err := s.persistCompletion(ctx, scanID, target, correlationID, []scannerOutcome{outcome}); err != nil {
		return uuid.Nil, nil, err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    scanID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanners": []string{scannerName}, "target": target, "findings_count": len(findings)},
		})
	}

	return scanID, findings, nil
}

// persistCompletion grava os achados de todo scanner bem-sucedido em
// outcomes (os que falharam são pulados — sem achado nenhum pra gravar) +
// o evento EventScanCompleted, tudo numa única transação — o miolo
// compartilhado entre RunScan e ProcessScanJob, para as duas nunca
// divergirem em como um scan concluído é registrado. Não é chamado se
// TODOS os scanners de outcomes falharam (ver ProcessScanJob) — gravar um
// EventScanCompleted sem nenhum sucesso seria enganoso.
func (s *Service) persistCompletion(ctx context.Context, scanID uuid.UUID, target string, correlationID uuid.UUID, outcomes []scannerOutcome) error {
	var succeededNames []string
	totalFindings := 0

	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		for _, o := range outcomes {
			if o.err != nil {
				continue
			}
			if err := s.repo.SaveFindings(ctx, tx, scanID, o.scanner, target, o.findings); err != nil {
				return err
			}
			// SavePackages (Fase 11 — Syft): mesma atomicidade de
			// SaveFindings, dentro da mesma transação — um scan concluído
			// nunca fica com achados gravados e inventário perdido, ou
			// vice-versa. Um outcome sem pacotes (todo scanner exceto
			// Syft) é um no-op (ver packages_repository.go).
			if err := s.repo.SavePackages(ctx, tx, scanID, o.packages); err != nil {
				return err
			}
			succeededNames = append(succeededNames, o.scanner)
			totalFindings += len(o.findings)
		}
		payload := scanCompletedPayload{ScanID: scanID, Scanners: succeededNames, Target: target, FindingsCount: totalFindings}
		return s.outboxWriter.Write(ctx, tx, EventScanCompleted, "scan", scanID.String(), correlationID, payload)
	})
	if err != nil {
		return fmt.Errorf("scanning: persist scan %s: %w", scanID, err)
	}

	s.logger.Info("scanning: scan completed",
		slog.String("scan_id", scanID.String()), slog.Any("scanners", succeededNames),
		slog.String("target", target), slog.Int("findings", totalFindings))
	return nil
}

// ScanStatus é a projeção de um job de scan pensada pra consumo HTTP (ver
// GetScanStatus/transport.GetScanStatus) — o mesmo Status/Attempts/
// timestamps que jobs.Job já guarda, mais os campos específicos de
// scanning (scanners pedidos, quais tiveram sucesso, o detalhe
// estruturado de quem falhou e por quê) decodificados de dentro de
// Payload/Result/Error — só esta package sabe o formato scanning-specific
// desses três campos genéricos.
//
// Existe porque, antes desta mudança, um scan que falhava (parcial ou
// totalmente) não tinha NENHUMA superfície HTTP pra consultar o motivo:
// só aparecia no log do worker. FailedScanners é o que responde
// diretamente ao pedido do usuário de saber "qual ferramenta achou o
// erro" (Scanner) "com descrição de que tipo de erro" (Code, Message) —
// "como corrigir" fica por conta de quem exibe isso (ver
// transport.remediationHint), não deste tipo: uma sugestão de correção é
// texto de apresentação, não um dado que faça sentido persistir junto do
// job.
type ScanStatus struct {
	JobID  uuid.UUID
	Status string
	Target string
	// ProjectID (Fase 10) — nil pra um scan avulso, preenchido quando
	// este job foi disparado a partir de um domain.Project (ver
	// scanJobPayload.ProjectID). ListProjectScans filtra por este campo.
	ProjectID         *uuid.UUID
	RequestedScanners []string
	SucceededScanners []string
	FailedScanners    []domain.ScannerFailure
	// ScannerRuns dá o progresso de CADA scanner individualmente — ao
	// contrário de Status (o job como um todo), funciona mesmo enquanto
	// o job ainda está "processing": é o que permite um painel mostrar
	// qual scanner está rodando agora e quanto falta, em vez de só
	// "processing" sem mais detalhe até tudo terminar de uma vez.
	ScannerRuns []domain.ScannerRun
	Attempts    int
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// GetScanStatus consulta o estado atual de um job de scan — quem chama
// tipicamente é a UI logo depois de disparar um scan (CreateScanJob),
// fazendo polling até o status virar terminal (completed/failed/
// dead_letter), pra saber se precisa mostrar os achados, um aviso de
// falha parcial, ou o motivo de uma falha total.
func (s *Service) GetScanStatus(ctx context.Context, jobID uuid.UUID) (*ScanStatus, error) {
	job, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("scanning: get scan status %s: %w", jobID, err)
	}
	return s.projectScanStatus(ctx, job)
}

// projectScanStatus é o miolo compartilhado entre GetScanStatus (um job
// já carregado por ID) e ListRecentScans (uma página inteira de jobs) —
// as duas nunca divergem em como um *jobs.Job vira um *ScanStatus.
func (s *Service) projectScanStatus(ctx context.Context, job *jobs.Job) (*ScanStatus, error) {
	jobID := job.ID
	var payload scanJobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("scanning: decode job %s payload: %w", jobID, err)
	}
	requestedScanners := payload.Scanners
	if len(requestedScanners) == 0 && payload.LegacyScanner != "" {
		requestedScanners = []string{payload.LegacyScanner}
	}

	status := &ScanStatus{
		JobID:             job.ID,
		Status:            string(job.Status),
		Target:            payload.Target,
		ProjectID:         payload.ProjectID,
		RequestedScanners: requestedScanners,
		Attempts:          job.Attempts,
		CreatedAt:         job.CreatedAt,
		StartedAt:         job.StartedAt,
		FinishedAt:        job.FinishedAt,
	}

	switch job.Status {
	case jobs.StatusCompleted:
		var result struct {
			SucceededScanners []string                `json:"succeeded_scanners"`
			FailedScanners    []domain.ScannerFailure `json:"failed_scanners,omitempty"`
		}
		if len(job.Result) > 0 {
			if err := json.Unmarshal(job.Result, &result); err != nil {
				// Compatibilidade com jobs concluídos ANTES desta fase:
				// failed_scanners costumava ser só uma lista de nomes
				// (strings), não domain.ScannerFailure estruturado — cai
				// pra esse formato antigo em vez de quebrar a consulta
				// inteira por causa de um job velho (confirmado contra um
				// job de verdade deste ambiente, b2a39c9c..., completado
				// antes desta mudança). A tentativa acima pode ter
				// deixado result.FailedScanners parcialmente preenchido
				// com valores zero antes de falhar (um detalhe de como
				// encoding/json decodifica um array elemento por
				// elemento) — por isso ATRIBUI abaixo, nunca append,
				// pra nunca herdar esse lixo parcial.
				var legacy struct {
					SucceededScanners []string `json:"succeeded_scanners"`
					FailedScanners    []string `json:"failed_scanners,omitempty"`
				}
				if legacyErr := json.Unmarshal(job.Result, &legacy); legacyErr != nil {
					return nil, fmt.Errorf("scanning: decode job %s result: %w", jobID, err)
				}
				failed := make([]domain.ScannerFailure, len(legacy.FailedScanners))
				for i, name := range legacy.FailedScanners {
					failed[i] = domain.ScannerFailure{Scanner: name}
				}
				result.SucceededScanners = legacy.SucceededScanners
				result.FailedScanners = failed
			}
		}
		status.SucceededScanners = result.SucceededScanners
		status.FailedScanners = result.FailedScanners
		if len(status.SucceededScanners) == 0 && len(status.FailedScanners) == 0 && len(requestedScanners) > 0 {
			// jobs.result de jobs completados ANTES até do formato
			// legado acima (nem succeeded_scanners nem failed_scanners
			// gravados — só findings_count, confirmado contra jobs de
			// verdade deste ambiente) não tem como saber QUAL scanner
			// teve sucesso a partir do que foi persistido. Mas
			// status==completed já implica que pelo menos um teve, e
			// nenhuma falha foi registrada — a inferência mais honesta
			// é que todo scanner pedido teve sucesso, não deixar a
			// lista vazia (que a UI leria como "nenhum scanner rodou",
			// falso pra um job concluído de verdade).
			status.SucceededScanners = requestedScanners
		}
	case jobs.StatusFailed, jobs.StatusDeadLetter:
		if job.Error != nil && *job.Error != "" {
			status.FailedScanners = decodeFailures(*job.Error)
		}
	}

	// Best-effort: funciona pra QUALQUER status (inclusive "processing",
	// o caso que realmente importa pro painel de progresso) — uma falha
	// aqui não derruba a resposta inteira, já que ScannerRuns é
	// informação suplementar, não o resultado principal do job.
	if runs, err := s.repo.ListScannerRuns(ctx, jobID); err != nil {
		s.logger.Warn("scanning: failed to load scanner progress (best-effort, status still returned)",
			slog.String("job_id", jobID.String()), slog.Any("error", err))
	} else {
		status.ScannerRuns = runs
	}

	return status, nil
}

// maxRecentScans é o teto de ListRecentScans — mesmo espírito de
// maxRecentFindings logo abaixo (uma consulta "generosa demais" ainda é
// atendida, só que com o teto em vez do valor pedido).
const maxRecentScans = 100

// ListRecentScans retorna os jobs de scan mais recentes, mais novo
// primeiro — o que /seguranca usa pra listar "resultados separados por
// scan" (cada job/execução como sua própria entrada, em vez de um feed
// só de achados misturando todo scan junto). Reaproveita o mesmo
// projeção de GetScanStatus pra cada job da página, então as duas
// consultas nunca divergem em formato.
func (s *Service) ListRecentScans(ctx context.Context, limit int) ([]*ScanStatus, error) {
	if limit <= 0 || limit > maxRecentScans {
		limit = maxRecentScans
	}

	jobList, _, err := s.jobsRepo.List(ctx, pagination.New(1, limit, maxRecentScans), JobType)
	if err != nil {
		return nil, fmt.Errorf("scanning: list recent scans: %w", err)
	}

	out := make([]*ScanStatus, 0, len(jobList))
	for _, job := range jobList {
		status, err := s.projectScanStatus(ctx, job)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

// ListProjectScans retorna as execuções mais recentes de UM projeto, mais
// nova primeiro (Fase 10) — filtra dentro de ListRecentScans (mesma
// consulta, mesmo teto maxRecentScans) por ScanStatus.ProjectID, em vez de
// uma consulta nova no banco: scanJobPayload.ProjectID vive dentro do
// JSONB do payload de jobs.Job, não numa coluna própria (o volume de
// scans desta plataforma nunca justificou um índice dedicado só pra
// isto). Uma lista vazia (projeto nunca escaneado) não é erro.
func (s *Service) ListProjectScans(ctx context.Context, projectID uuid.UUID) ([]*ScanStatus, error) {
	scans, err := s.ListRecentScans(ctx, maxRecentScans)
	if err != nil {
		return nil, err
	}
	out := make([]*ScanStatus, 0)
	for _, sc := range scans {
		if sc.ProjectID != nil && *sc.ProjectID == projectID {
			out = append(out, sc)
		}
	}
	return out, nil
}

// decodeFailures decodifica o texto de jobs.error de volta em
// []domain.ScannerFailure — o formato que encodeFailures grava desde
// esta fase. Tolerante a texto que NÃO está nesse formato (o fallback
// defensivo de HandleScanDeadLetter grava só "max retries exceeded" em
// texto puro quando não há nenhum jobs.error anterior; um jobs.error
// gravado antes desta mudança também não seria JSON): em vez de devolver
// erro e quebrar GetScanStatus pra um job assim, devolve uma única
// entrada sintética com o texto bruto na Message — sempre alguma
// informação em vez de um erro de decodificação visível pro cliente
// HTTP.
func decodeFailures(raw string) []domain.ScannerFailure {
	var failures []domain.ScannerFailure
	if err := json.Unmarshal([]byte(raw), &failures); err != nil {
		return []domain.ScannerFailure{{Message: raw}}
	}
	return failures
}

// CreateScanJob implementa o "Commit" do fluxo assíncrono avulso (sem
// projeto por trás) — mesmo desenho de diario_oficial.Service.
// CreateTestJob. Ver createScanJob pro que as duas variantes (esta e
// CreateProjectScanJob) compartilham.
func (s *Service) CreateScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, target string, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if target == "" {
		return nil, apperrors.Validation("target is required")
	}
	return s.createScanJob(ctx, correlationID, scannerNames, target, nil, requestedBy)
}

// CreateProjectScanJob dispara um scan a partir de um domain.Project já
// existente (Fase 10) — "Rodar de novo" no frontend, sem pedir a URL/o
// .zip de novo. Resolve target a partir do projeto: um projeto GIT usa
// project.Target (o job resultante fica indistinguível de um scan avulso
// pro resto do pipeline, exceto por carregar ProjectID pro histórico); um
// projeto UPLOAD deixa Target vazio de propósito — é esse sinal que
// ProcessScanJob usa pra extrair o .zip em vez de clonar (ver
// runConcurrentlyLocal).
func (s *Service) CreateProjectScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, projectID uuid.UUID, requestedBy *uuid.UUID) (*jobs.Job, error) {
	project, err := s.repo.GetProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	target := project.Target
	if project.SourceType == domain.ProjectSourceUpload {
		// Nunca fica vazio, nem enquanto o job ainda está "queued": sem
		// isto, GetScanStatus/ListScans mostrariam Target="" pra um scan
		// de upload até ele terminar (só ProcessScanJob saberia o nome
		// "upload:<projeto>" de verdade) — computado aqui, na criação,
		// pra aparecer certo desde o primeiro instante.
		target = uploadTarget(project.Name)
	}
	return s.createScanJob(ctx, correlationID, scannerNames, target, &project, requestedBy)
}

// uploadTarget é o "alvo" sintético gravado pra um scan de projeto
// UPLOAD — nunca um alvo git de verdade, só um rótulo consistente
// (scan_findings.target, ScanStatus.Target, jobs.payload.target) que
// identifica de qual projeto esse scan veio, já que não existe URL
// nenhuma pra mostrar.
func uploadTarget(projectName string) string {
	return "upload:" + projectName
}

// createScanJob é o miolo compartilhado por CreateScanJob (avulso) e
// CreateProjectScanJob (Fase 10): valida que todo nome em scannerNames
// está registrado (e, pra um projeto UPLOAD, que cada um também
// implementa domain.LocalScanner — SonarQube/ZAP são rejeitados aqui,
// nunca silenciosamente ignorados nem descobertos como falha só depois
// que o worker já tentou), cria o job e seu evento de outbox disparador
// atomicamente, e retorna — quem chama (o transport) responde 202. O ID
// do job também é o scan_id usado depois em ListFindings, para que o
// cliente HTTP consiga consultar os achados de TODOS os scanners pedidos
// com o mesmo ID que recebeu na criação.
func (s *Service) createScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, target string, project *domain.Project, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if len(scannerNames) == 0 {
		return nil, apperrors.Validation("at least one scanner is required")
	}

	isUpload := project != nil && project.SourceType == domain.ProjectSourceUpload

	var unknown, unsupported []string
	for _, name := range scannerNames {
		scanner, ok := s.scanners[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if isUpload {
			if _, ok := scanner.(domain.LocalScanner); !ok {
				unsupported = append(unsupported, name)
			}
		}
	}
	if len(unknown) > 0 {
		return nil, apperrors.NotFound(fmt.Sprintf("scanner(s) not registered: %s", strings.Join(unknown, ", ")))
	}
	if len(unsupported) > 0 {
		return nil, apperrors.Validation(fmt.Sprintf(
			"scanner(s) not supported for an upload-based project (need a git clone or a live URL): %s",
			strings.Join(unsupported, ", ")))
	}

	payload := scanJobPayload{Scanners: scannerNames, Target: target}
	if project != nil {
		payload.ProjectID = &project.ID
	}

	job, err := jobs.New(JobType, correlationID, payload)
	if err != nil {
		return nil, fmt.Errorf("scanning: build job: %w", err)
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.Create(ctx, tx, job); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventScanRequested, "job", job.ID.String(), correlationID, jobRefPayload{JobID: job.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("scanning: create scan job: %w", err)
	}

	if s.audit != nil {
		metadata := map[string]any{"scanners": scannerNames, "target": target}
		if project != nil {
			metadata["project_id"] = project.ID.String()
		}
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanRequested,
			ResourceType:  "job",
			ResourceID:    job.ID.String(),
			CorrelationID: &correlationID,
			Metadata:      metadata,
		})
	}

	return job, nil
}
