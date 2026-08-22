// Package application implements the secops module's use cases: creating
// an async "test this provider's connection" job (§34-style flow reused
// for any SecurityProvider) and processing it on the worker side.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	"github.com/yurythx/nix-platform/internal/modules/secops/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

const (
	JobType = "integration.test"

	EventTestRequested            = "integration.test.requested"
	EventTestCompleted            = "integration.test.completed"
	EventIntegrationStatusChanged = "integration.status.changed"
)

type jobInput struct {
	ProviderKey string `json:"provider_key"`
}

type eventPayload struct {
	JobID       uuid.UUID `json:"job_id"`
	ProviderKey string    `json:"provider_key"`
}

// Service is generic over every registered SecurityProvider — adding a
// new one (Shodan, AbuseIPDB, ...) means registering it in the providers
// map, never touching this file (§36/§76).
type Service struct {
	db           *pgxpool.Pool
	jobsRepo     *jobs.Repository
	outboxWriter *outbox.Writer
	providers    map[string]domain.SecurityProvider
	integrations *integrations.Service
	audit        *audit.Writer
	logger       *slog.Logger
}

func NewService(
	db *pgxpool.Pool,
	jobsRepo *jobs.Repository,
	outboxWriter *outbox.Writer,
	providers map[string]domain.SecurityProvider,
	integrationsSvc *integrations.Service,
	auditWriter *audit.Writer,
	logger *slog.Logger,
) *Service {
	return &Service{
		db:           db,
		jobsRepo:     jobsRepo,
		outboxWriter: outboxWriter,
		providers:    providers,
		integrations: integrationsSvc,
		audit:        auditWriter,
		logger:       logger,
	}
}

// CreateTestJob validates the requested provider exists, then creates the
// job and its triggering outbox event atomically (§34).
func (s *Service) CreateTestJob(ctx context.Context, providerKey string, correlationID uuid.UUID, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if _, ok := s.providers[providerKey]; !ok {
		return nil, apperrors.BadRequest(fmt.Sprintf("unknown security provider %q", providerKey))
	}

	job, err := jobs.New(JobType, correlationID, jobInput{ProviderKey: providerKey})
	if err != nil {
		return nil, fmt.Errorf("secops: build job: %w", err)
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.Create(ctx, tx, job); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventTestRequested, "job", job.ID.String(), correlationID, eventPayload{JobID: job.ID, ProviderKey: providerKey})
	})
	if err != nil {
		return nil, fmt.Errorf("secops: create test job: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionJobCreated,
			ResourceType:  "job",
			ResourceID:    job.ID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"job_type": JobType, "provider": providerKey},
		})
	}

	return job, nil
}

// ProcessJob runs the provider's connectivity test (§35). Like
// diario_oficial, a failure is recorded but returned as an error so the
// messaging consumer retries — only HandleDeadLetter publishes the
// user-facing failure notification.
//
// Idempotency (§18): see the identical guard in diario_oficial's
// ProcessJob — a redelivered event for an already-terminal job is a
// no-op rather than an error-triggering reprocess attempt.
func (s *Service) ProcessJob(ctx context.Context, jobID uuid.UUID, providerKey string, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("secops: load job %s: %w", jobID, err)
	}
	if current.Status == jobs.StatusCompleted || current.Status == jobs.StatusDeadLetter {
		s.logger.Info("secops: duplicate delivery of an already-finished job, skipping",
			slog.String("job_id", jobID.String()), slog.String("status", string(current.Status)))
		return nil
	}

	provider, ok := s.providers[providerKey]
	if !ok {
		return fmt.Errorf("secops: unknown provider %q for job %s", providerKey, jobID)
	}

	checkErr := provider.TestConnection(ctx)

	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkProcessing(ctx, tx, jobID); err != nil {
			return err
		}
		if checkErr != nil {
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, checkErr.Error())
		}
		return s.jobsRepo.MarkCompleted(ctx, tx, jobID, map[string]string{"provider": providerKey, "result": "connected"})
	})
	if txErr != nil {
		return fmt.Errorf("secops: record processing outcome: %w", txErr)
	}

	if checkErr != nil {
		s.logger.Warn("secops: provider check failed, will retry", slog.String("job_id", jobID.String()), slog.String("provider", providerKey), slog.Any("error", checkErr))
		return checkErr
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.outboxWriter.Write(ctx, tx, EventTestCompleted, "job", jobID.String(), correlationID, eventPayload{JobID: jobID, ProviderKey: providerKey}); err != nil {
			return err
		}
		updated, changed, err := s.integrations.RecordCheckResult(ctx, tx, providerKey, true, "")
		if err != nil {
			return err
		}
		if changed {
			return s.outboxWriter.Write(ctx, tx, EventIntegrationStatusChanged, "integration", providerKey, correlationID, statusPayload(updated.Key, string(updated.Status)))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("secops: publish completion: %w", err)
	}
	return nil
}

// HandleDeadLetter is the terminal outcome once RabbitMQ gives up on a
// provider test job.
func (s *Service) HandleDeadLetter(ctx context.Context, jobID uuid.UUID, providerKey string, correlationID uuid.UUID, reason string) error {
	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkDeadLetter(ctx, tx, jobID, reason); err != nil {
			return err
		}
		updated, changed, err := s.integrations.RecordCheckResult(ctx, tx, providerKey, false, reason)
		if err != nil {
			return err
		}
		if changed {
			if err := s.outboxWriter.Write(ctx, tx, EventIntegrationStatusChanged, "integration", providerKey, correlationID, statusPayload(updated.Key, string(updated.Status))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("secops: handle dead letter: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionJobFailed,
			ResourceType:  "job",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"provider": providerKey, "reason": reason},
		})
	}
	return nil
}

func statusPayload(key, status string) any {
	return struct {
		Key    string `json:"key"`
		Status string `json:"status"`
	}{Key: key, Status: status}
}
