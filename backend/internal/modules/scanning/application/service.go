// Package application implementa os casos de uso do módulo scanning:
// rodar um CodeScanner registrado contra um alvo e persistir os achados,
// tanto de forma síncrona (RunScan) quanto assíncrona via o padrão
// job+outbox+worker (CreateScanJob/ProcessScanJob/HandleScanDeadLetter) já
// estabelecido por diario_oficial.Service.
//
// Fase 1 do roadmap de segurança (docs/roadmap-secops-orchestrator.md) só
// construiu a fundação síncrona — sem nenhum scanner real registrado e sem
// nenhum endpoint HTTP amarrado a isto, o padrão assíncrono teria sido
// infraestrutura morta. A fase seguinte introduziu o primeiro scanner real
// (scanning/infrastructure.TrivyScanner: clona um repositório via git e
// escaneia dependências/Dockerfiles) — uma operação de segundos a minutos,
// disparada por um endpoint HTTP de verdade — e é isso que agora justifica
// o par CreateScanJob/ProcessScanJob: a requisição HTTP retorna 202
// imediatamente, e o clone+scan em si roda no worker, sem bloquear a
// requisição original. RunScan continua existindo, síncrono, como o modo
// de chamar um scanner diretamente sem depender de fila nenhuma — útil
// para testes e para uma futura execução agendada que já roda no worker.
package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

const (
	// JobType identifica todo job assíncrono deste módulo em jobs.Job.Type
	// — um único tipo cobre qualquer scanner registrado (o scanner de fato
	// executado vive no payload do job, não no tipo), então adicionar um
	// scanner novo nunca exige um JobType novo.
	JobType = "scanning.scan"

	// EventScanRequested dispara ProcessScanJob no worker — o mesmo papel
	// que diario_oficial.job.created tem para aquele módulo.
	EventScanRequested = "scanning.scan.requested"

	// EventScanCompleted é publicado toda vez que um scan termina com
	// sucesso, com ou sem achados — tanto pelo caminho síncrono (RunScan)
	// quanto pelo assíncrono (ProcessScanJob). Quem consumir este evento
	// (hoje: só o WebSocket de notificação) decide se achados
	// CRITICAL/HIGH merecem alguma reação adicional.
	EventScanCompleted = "scanning.scan.completed"

	// EventScanFailed é publicado só quando o RabbitMQ já esgotou os
	// retries de um job de scan (ver HandleScanDeadLetter) — o mesmo
	// desenho de diario_oficial.job.failed: uma falha isolada, que ainda
	// pode ter sucesso numa nova tentativa, nunca gera este evento.
	EventScanFailed = "scanning.scan.failed"
)

// scanCompletedPayload é o corpo do evento EventScanCompleted — só o
// necessário para localizar a execução, não os achados inteiros (esses
// vivem em scan_findings, consultáveis por scan_id via ListFindings).
type scanCompletedPayload struct {
	ScanID        uuid.UUID `json:"scan_id"`
	Scanner       string    `json:"scanner"`
	Target        string    `json:"target"`
	FindingsCount int       `json:"findings_count"`
}

// scanJobPayload é o corpo persistido em jobs.Job.Payload para um job de
// scan — o scanner e o alvo que ProcessScanJob precisa pra saber o que
// executar quando o worker pegar o evento EventScanRequested.
type scanJobPayload struct {
	Scanner string `json:"scanner"`
	Target  string `json:"target"`
}

// jobRefPayload é o corpo do evento EventScanRequested/EventScanFailed —
// só o bastante pra quem consumir localizar o job de novo (o resto do
// estado vive na tabela jobs), mesmo desenho de
// diario_oficial/application/service.go's jobPayload.
type jobRefPayload struct {
	JobID uuid.UUID `json:"job_id"`
}

// Service orquestra execuções de scan. scanners mapeia o nome de cada
// CodeScanner registrado (Strategy Pattern) ao seu Name() — o mesmo
// desenho de registro em mapa que o restante da plataforma já usa (ex.:
// lib/integrations/registry.ts no frontend), para que adicionar um
// scanner novo signifique registrar mais uma entrada, nunca alterar
// RunScan/ProcessScanJob.
type Service struct {
	db           *pgxpool.Pool
	repo         domain.Repository
	jobsRepo     *jobs.Repository
	outboxWriter *outbox.Writer
	audit        *audit.Writer
	scanners     map[string]domain.CodeScanner
	logger       *slog.Logger
}

// NewService constrói o Service a partir da lista de scanners disponíveis.
// Registrar dois scanners com o mesmo Name() é um erro de programação (bug
// de wiring, não uma condição de runtime a ser tolerada) e por isso
// entra em pânico imediatamente na inicialização, em vez de silenciosamente
// descartar um dos dois.
func NewService(
	db *pgxpool.Pool,
	repo domain.Repository,
	jobsRepo *jobs.Repository,
	outboxWriter *outbox.Writer,
	auditWriter *audit.Writer,
	logger *slog.Logger,
	scanners ...domain.CodeScanner,
) *Service {
	byName := make(map[string]domain.CodeScanner, len(scanners))
	for _, s := range scanners {
		if _, exists := byName[s.Name()]; exists {
			panic(fmt.Sprintf("scanning: duplicate scanner registered: %q", s.Name()))
		}
		byName[s.Name()] = s
	}
	return &Service{
		db:           db,
		repo:         repo,
		jobsRepo:     jobsRepo,
		outboxWriter: outboxWriter,
		audit:        auditWriter,
		scanners:     byName,
		logger:       logger,
	}
}

// RunScan executa o CodeScanner chamado scannerName contra target,
// persiste os achados e o evento EventScanCompleted atomicamente, e
// retorna os achados encontrados. Bloqueia até o scanner terminar — para
// um scanner potencialmente lento chamado a partir de HTTP, prefira
// CreateScanJob. requestedBy é opcional (nil para execuções sem um
// usuário autenticado por trás). scanID retornado é o mesmo usado para
// consultar depois via ListFindings — RunScan gera um novo a cada
// chamada, já que (ao contrário de CreateScanJob/ProcessScanJob) não há
// nenhum jobID pré-existente para reaproveitar.
func (s *Service) RunScan(ctx context.Context, scannerName, target string, correlationID uuid.UUID, requestedBy *uuid.UUID) (scanID uuid.UUID, findings []domain.Finding, err error) {
	scanner, ok := s.scanners[scannerName]
	if !ok {
		return uuid.Nil, nil, apperrors.NotFound(fmt.Sprintf("scanner %q not registered", scannerName))
	}

	findings, err = scanner.Execute(ctx, target)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("scanning: execute %q against %q: %w", scannerName, target, err)
	}

	scanID = uuid.New()
	if err := s.persistCompletion(ctx, scanID, scannerName, target, correlationID, findings); err != nil {
		return uuid.Nil, nil, err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    scanID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanner": scannerName, "target": target, "findings_count": len(findings)},
		})
	}

	return scanID, findings, nil
}

// persistCompletion grava os achados de scanID + o evento
// EventScanCompleted numa única transação, e loga o resultado — o miolo
// compartilhado entre RunScan e ProcessScanJob, para as duas nunca
// divergirem em como um scan concluído é registrado.
func (s *Service) persistCompletion(ctx context.Context, scanID uuid.UUID, scannerName, target string, correlationID uuid.UUID, findings []domain.Finding) error {
	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.repo.SaveFindings(ctx, tx, scanID, scannerName, target, findings); err != nil {
			return err
		}
		payload := scanCompletedPayload{ScanID: scanID, Scanner: scannerName, Target: target, FindingsCount: len(findings)}
		return s.outboxWriter.Write(ctx, tx, EventScanCompleted, "scan", scanID.String(), correlationID, payload)
	})
	if err != nil {
		return fmt.Errorf("scanning: persist scan %s: %w", scanID, err)
	}

	s.logger.Info("scanning: scan completed",
		slog.String("scan_id", scanID.String()), slog.String("scanner", scannerName),
		slog.String("target", target), slog.Int("findings", len(findings)))
	return nil
}

// ListFindings retorna todo achado de uma execução de scan, mais
// severo/recente primeiro.
func (s *Service) ListFindings(ctx context.Context, scanID uuid.UUID) ([]domain.PersistedFinding, error) {
	findings, err := s.repo.ListByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings for scan %s: %w", scanID, err)
	}
	return findings, nil
}

// CreateScanJob implementa o "Commit" do fluxo assíncrono (mesmo desenho
// de diario_oficial.Service.CreateTestJob): valida que scannerName está
// registrado, cria o job e seu evento de outbox disparador atomicamente,
// e retorna — quem chama (o transport) responde 202. O ID do job também é
// o scan_id usado depois em ListFindings, para que o cliente HTTP consiga
// consultar os achados com o mesmo ID que recebeu na criação, sem
// precisar de um passo extra pra descobrir o scan_id.
func (s *Service) CreateScanJob(ctx context.Context, correlationID uuid.UUID, scannerName, target string, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if _, ok := s.scanners[scannerName]; !ok {
		return nil, apperrors.NotFound(fmt.Sprintf("scanner %q not registered", scannerName))
	}
	if target == "" {
		return nil, apperrors.Validation("target is required")
	}

	job, err := jobs.New(JobType, correlationID, scanJobPayload{Scanner: scannerName, Target: target})
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
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanRequested,
			ResourceType:  "job",
			ResourceID:    job.ID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanner": scannerName, "target": target},
		})
	}

	return job, nil
}

// ProcessScanJob implementa a execução do lado do worker (mesmo desenho
// de diario_oficial.Service.ProcessJob, incluindo a mesma idempotência
// contra redelivery do RabbitMQ: um job em estado terminal vira um no-op
// em vez de ser reprocessado). O scan_id usado em EventScanCompleted é o
// próprio jobID — não um uuid.New() separado — para que o cliente HTTP
// consiga consultar ListFindings com o mesmo ID recebido de
// CreateScanJob.
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

	scanner, ok := s.scanners[payload.Scanner]
	if !ok {
		// Não é uma falha transitória (o registro de scanners não muda
		// entre uma tentativa e a próxima dentro do mesmo deploy) — marca
		// como falho definitivamente em vez de deixar o RabbitMQ
		// reentregar até esgotar os retries à toa.
		txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
			if err := s.jobsRepo.MarkProcessing(ctx, tx, jobID); err != nil {
				return err
			}
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, fmt.Sprintf("scanner %q not registered", payload.Scanner))
		})
		if txErr != nil {
			return fmt.Errorf("scanning: record unregistered scanner outcome: %w", txErr)
		}
		s.logger.Error("scanning: job references an unregistered scanner", slog.String("job_id", jobID.String()), slog.String("scanner", payload.Scanner))
		return nil
	}

	findings, execErr := scanner.Execute(ctx, payload.Target)

	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkProcessing(ctx, tx, jobID); err != nil {
			return err
		}
		if execErr != nil {
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, execErr.Error())
		}
		return s.jobsRepo.MarkCompleted(ctx, tx, jobID, struct {
			FindingsCount int `json:"findings_count"`
		}{FindingsCount: len(findings)})
	})
	if txErr != nil {
		return fmt.Errorf("scanning: record processing outcome: %w", txErr)
	}

	if execErr != nil {
		s.logger.Warn("scanning: scan failed, will retry", slog.String("job_id", jobID.String()), slog.Any("error", execErr))
		return execErr
	}

	if err := s.persistCompletion(ctx, jobID, payload.Scanner, payload.Target, correlationID, findings); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanner": payload.Scanner, "target": payload.Target, "findings_count": len(findings)},
		})
	}
	return nil
}

// HandleScanDeadLetter é chamado quando o RabbitMQ já esgotou
// RABBITMQ_MAX_RETRIES para a mensagem deste job: o desfecho terminal, tal
// qual diario_oficial.Service.HandleDeadLetter — antes disso, toda falha
// era tratada como "ainda pode ter sucesso numa nova tentativa" (ver
// ProcessScanJob) e não publicava EventScanFailed.
func (s *Service) HandleScanDeadLetter(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID, reason string) error {
	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
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
