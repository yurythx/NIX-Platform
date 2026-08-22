// Package application implements the diario_oficial module's use cases
// (§22/§34/§35): CreateDiarioOficialJob (the HTTP-triggered flow) and
// ProcessJob/HandleDeadLetter (the worker-side execution).
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

// jobPayload is the body of every diario_oficial job-lifecycle event —
// just enough for the worker/DLQ consumers to look the job back up.
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

// CreateTestJob implements the §34/§72 flow up through "Commit": it
// creates the job and its triggering outbox event atomically, then
// returns — the caller (transport) is responsible for the 202 response.
// It never calls the external Diário Oficial system itself.
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

// ProcessJob implements the worker-side execution (§35). On failure it
// records the attempt's outcome and returns the error so the caller (the
// messaging consumer) retries per §12 — it deliberately does NOT publish a
// job.failed notification yet, since the job may still succeed on retry.
// Only HandleDeadLetter, called once RabbitMQ gives up, does that.
func (s *Service) ProcessJob(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
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

	// Success: publish job.completed and update integration status in one
	// transaction — same guarantee as job creation (§16).
	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
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

// HandleDeadLetter is called once RabbitMQ has exhausted RABBITMQ_MAX_RETRIES
// for this job's message: it's the terminal outcome, so this is where the
// job transitions to dead_letter and the user-facing job.failed
// notification is finally published.
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
