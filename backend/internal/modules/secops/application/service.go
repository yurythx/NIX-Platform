// Package application implementa os casos de uso do módulo secops: criar
// um job assíncrono de "testar a conexão deste provedor" (o mesmo estilo
// de fluxo do §34, reaproveitado para qualquer SecurityProvider) e
// processá-lo do lado do worker.
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
	"github.com/yurythx/nix-platform/internal/platform/configflags"
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

// Service é genérico sobre todo SecurityProvider registrado — adicionar
// um novo (Shodan, AbuseIPDB, ...) significa registrá-lo no mapa
// providers, nunca tocar neste arquivo (§36/§76). É esse desacoplamento
// que permite plugar um provedor novo sem reescrever o fluxo de job
// assíncrono.
type Service struct {
	db           *pgxpool.Pool
	jobsRepo     *jobs.Repository
	outboxWriter *outbox.Writer
	providers    map[string]domain.SecurityProvider
	integrations *integrations.Service
	audit        *audit.Writer
	flags        configflags.Store
	logger       *slog.Logger
}

// NewService constrói o Service. flags pode ser nil — nesse caso a
// checagem de feature flag em CreateTestJob é pulada e o teste é sempre
// permitido, o que mantém testes de aplicação que não se importam com
// feature flags simples de escrever (ver service_test.go).
func NewService(
	db *pgxpool.Pool,
	jobsRepo *jobs.Repository,
	outboxWriter *outbox.Writer,
	providers map[string]domain.SecurityProvider,
	integrationsSvc *integrations.Service,
	auditWriter *audit.Writer,
	flags configflags.Store,
	logger *slog.Logger,
) *Service {
	return &Service{
		db:           db,
		jobsRepo:     jobsRepo,
		outboxWriter: outboxWriter,
		providers:    providers,
		integrations: integrationsSvc,
		audit:        auditWriter,
		flags:        flags,
		logger:       logger,
	}
}

// featureFlagKey deriva a chave de feature flag de um provedor a partir
// do seu providerKey — "secops_<provider>_enabled" — para que um novo
// provedor (Shodan, AbuseIPDB, ...) já nasça com seu próprio interruptor
// sem precisar de nenhuma mudança de código aqui, só uma linha na
// migration/no admin de feature flags (§36/§76).
func featureFlagKey(providerKey string) string {
	return "secops_" + providerKey + "_enabled"
}

// CreateTestJob valida que o provedor requisitado existe e que sua
// feature flag está habilitada, e então cria o job e seu evento de
// outbox disparador atomicamente (§34).
func (s *Service) CreateTestJob(ctx context.Context, providerKey string, correlationID uuid.UUID, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if _, ok := s.providers[providerKey]; !ok {
		return nil, apperrors.BadRequest(fmt.Sprintf("unknown security provider %q", providerKey))
	}

	if s.flags != nil {
		flagKey := featureFlagKey(providerKey)
		enabled, err := s.flags.IsEnabled(ctx, flagKey, true)
		if err != nil {
			return nil, fmt.Errorf("secops: check feature flag: %w", err)
		}
		if !enabled {
			return nil, apperrors.FeatureDisabled(fmt.Sprintf("the %q feature is currently disabled", flagKey))
		}
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

// ProcessJob roda o teste de conectividade do provedor (§35). Assim como
// em diario_oficial, uma falha é registrada mas retornada como erro para
// que o consumer de mensageria tente de novo — só HandleDeadLetter publica
// a notificação de falha voltada para o usuário.
//
// Idempotência (§18): ver a mesma proteção em diario_oficial.ProcessJob —
// um evento redelivered para um job já em estado terminal vira um no-op
// em vez de uma tentativa de reprocessamento que geraria erro.
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

// HandleDeadLetter é o desfecho terminal quando o RabbitMQ desiste de um
// job de teste de provedor.
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
