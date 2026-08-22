// Package worker adapta o serviço de aplicação do módulo secops para o
// formato genérico events.MessageHandler da plataforma.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/modules/secops/application"
)

type jobPayload struct {
	JobID       string `json:"job_id"`
	ProviderKey string `json:"provider_key"`
}

// JobCreatedHandler processa eventos integration.test.requested —
// consumidos de nix.integration.worker. Esta fila é compartilhada por todo
// provedor SecOps (§36), e o despacho para o provedor certo é feito aqui
// através do provider_key do payload — não existe uma fila por provedor.
func JobCreatedHandler(svc *application.Service) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("secops worker: decode payload: %w", err)
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			return fmt.Errorf("secops worker: invalid job_id: %w", err)
		}
		return svc.ProcessJob(ctx, jobID, payload.ProviderKey, event.CorrelationID)
	}
}

// DeadLetterHandler processa mensagens que o RabbitMQ já desistiu de
// tentar de novo — consumidas de nix.integration.dlq.
func DeadLetterHandler(svc *application.Service, logger *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			logger.Error("secops dlq: undecodable payload, dropping", slog.Any("error", err))
			return nil
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			logger.Error("secops dlq: invalid job_id, dropping", slog.Any("error", err))
			return nil
		}

		if err := svc.HandleDeadLetter(ctx, jobID, payload.ProviderKey, event.CorrelationID, "max retries exceeded"); err != nil {
			logger.Error("secops dlq: failed to record dead letter outcome", slog.String("job_id", payload.JobID), slog.Any("error", err))
		}
		return nil
	}
}
