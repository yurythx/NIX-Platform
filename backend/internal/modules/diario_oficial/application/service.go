// Package application implementa os casos de uso do módulo diario_oficial
// (§22/§34/§35): CreateDiarioOficialJob (o fluxo disparado via HTTP) e
// ProcessJob/HandleDeadLetter (a execução do lado do worker).
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"

	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
)

const (
	JobType = "diario_oficial.test"

	EventJobCreated   = "diario_oficial.job.created"
	EventJobCompleted = "diario_oficial.job.completed"
	EventJobFailed    = "diario_oficial.job.failed"

	EventIntegrationStatusChanged = "integration.status.changed"

	integrationKey = "diario-oficial"
)

// jobPayload é o corpo de todo evento do ciclo de vida de um job do
// diario_oficial — só o necessário para os consumers do worker/DLQ
// localizarem o job de novo (o resto do estado vive na tabela jobs, não
// no evento).
type jobPayload struct {
	JobID uuid.UUID `json:"job_id"`
}

type Service struct {
	db           *pgxpool.Pool
	jobsRepo     *jobs.Repository
	outboxWriter *outbox.Writer
	client       domain.Client
	integrations *integrations.Service
	audit        *audit.Writer
	logger       *slog.Logger
}

func NewService(
	db *pgxpool.Pool,
	jobsRepo *jobs.Repository,
	outboxWriter *outbox.Writer,
	client domain.Client,
	integrationsSvc *integrations.Service,
	auditWriter *audit.Writer,
	logger *slog.Logger,
) *Service {
	return &Service{
		db:           db,
		jobsRepo:     jobsRepo,
		outboxWriter: outboxWriter,
		client:       client,
		integrations: integrationsSvc,
		audit:        auditWriter,
		logger:       logger,
	}
}

// CreateTestJob implementa o fluxo do §34/§72 até o "Commit": cria o job e
// seu evento de outbox disparador atomicamente, e então retorna — quem
// chama (o transport) é responsável pela resposta 202. Nunca chama o
// sistema externo do Diário Oficial diretamente — essa é a
// responsabilidade do worker, acionado de forma assíncrona pelo evento
// que acabou de ser gravado no outbox.
func (s *Service) CreateTestJob(ctx context.Context, correlationID uuid.UUID, requestedBy *uuid.UUID) (*jobs.Job, error) {
	job, err := jobs.New(JobType, correlationID, struct{}{})
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: build job: %w", err)
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.Create(ctx, tx, job); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventJobCreated, "job", job.ID.String(), correlationID, jobPayload{JobID: job.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: create test job: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionJobCreated,
			ResourceType:  "job",
			ResourceID:    job.ID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"job_type": JobType},
		})
	}

	return job, nil
}

// ProcessJob implementa a execução do lado do worker (§35). Em caso de
// falha, registra o resultado da tentativa e retorna o erro para que quem
// chama (o consumer de mensageria) tente de novo conforme §12 —
// deliberadamente NÃO publica ainda uma notificação job.failed, já que o
// job ainda pode ter sucesso numa nova tentativa. Só HandleDeadLetter,
// chamado quando o RabbitMQ desiste, faz isso.
//
// Idempotência (§18): a entrega "pelo menos uma vez" (at-least-once) do
// RabbitMQ significa que o mesmo evento diario_oficial.job.created pode
// chegar mais de uma vez (uma redelivery competindo com um ack, um
// republish de retry cruzando com o original, ...). Se este job já
// alcançou um estado terminal, rodar a verificação de novo seria na
// melhor das hipóteses redundante e, como MarkProcessing/MarkCompleted
// impõem transições de status válidas, na pior das hipóteses daria erro —
// por isso jobs em estado terminal viram um no-op aqui, em vez de serem
// reprocessados.
func (s *Service) ProcessJob(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("diario_oficial: load job %s: %w", jobID, err)
	}
	if current.Status == jobs.StatusCompleted || current.Status == jobs.StatusDeadLetter {
		s.logger.Info("diario_oficial: duplicate delivery of an already-finished job, skipping",
			slog.String("job_id", jobID.String()), slog.String("status", string(current.Status)))
		return nil
	}

	checkResult, checkErr := s.client.Check(ctx)

	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkProcessing(ctx, tx, jobID); err != nil {
			return err
		}

		if checkErr != nil {
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, checkErr.Error())
		}
		return s.jobsRepo.MarkCompleted(ctx, tx, jobID, checkResult)
	})
	if txErr != nil {
		return fmt.Errorf("diario_oficial: record processing outcome: %w", txErr)
	}

	if checkErr != nil {
		s.logger.Warn("diario_oficial: check failed, will retry", slog.String("job_id", jobID.String()), slog.Any("error", checkErr))
		return checkErr
	}

	// Sucesso: publica job.completed e atualiza o status da integração
	// numa única transação — a mesma garantia usada na criação do job
	// (§16), para que "o job terminou" e "o status da integração
	// mudou" nunca fiquem inconsistentes entre si.
	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.outboxWriter.Write(ctx, tx, EventJobCompleted, "job", jobID.String(), correlationID, jobPayload{JobID: jobID}); err != nil {
			return err
		}
		updated, changed, err := s.integrations.RecordCheckResult(ctx, tx, integrationKey, true, "")
		if err != nil {
			return err
		}
		if changed {
			return s.outboxWriter.Write(ctx, tx, EventIntegrationStatusChanged, "integration", integrationKey, correlationID, integrationStatusPayload(updated.Key, string(updated.Status)))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("diario_oficial: publish completion: %w", err)
	}
	return nil
}

// HandleDeadLetter é chamado quando o RabbitMQ já esgotou
// RABBITMQ_MAX_RETRIES para a mensagem deste job: é o desfecho terminal,
// então é aqui que o job transiciona para dead_letter e a notificação
// job.failed voltada para o usuário é finalmente publicada — antes disso,
// toda falha era tratada como "ainda pode ter sucesso numa nova
// tentativa" (ver ProcessJob) e não gerava notificação nenhuma.
func (s *Service) HandleDeadLetter(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID, reason string) error {
	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkDeadLetter(ctx, tx, jobID, reason); err != nil {
			return err
		}
		if err := s.outboxWriter.Write(ctx, tx, EventJobFailed, "job", jobID.String(), correlationID, jobPayload{JobID: jobID}); err != nil {
			return err
		}
		updated, changed, err := s.integrations.RecordCheckResult(ctx, tx, integrationKey, false, reason)
		if err != nil {
			return err
		}
		if changed {
			return s.outboxWriter.Write(ctx, tx, EventIntegrationStatusChanged, "integration", integrationKey, correlationID, integrationStatusPayload(updated.Key, string(updated.Status)))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("diario_oficial: handle dead letter: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionJobFailed,
			ResourceType:  "job",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"reason": reason},
		})
	}
	return nil
}

func integrationStatusPayload(key, status string) any {
	return struct {
		Key    string `json:"key"`
		Status string `json:"status"`
	}{Key: key, Status: status}
}
