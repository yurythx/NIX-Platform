// Package worker adapts the secops module's application service to the
// platform's generic events.MessageHandler shape.
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

// JobCreatedHandler processes integration.test.requested events —
// consumed from nix.integration.worker. This queue is shared by every
// SecOps provider (§36), dispatched here by the payload's provider_key.
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

// DeadLetterHandler processes messages RabbitMQ has given up retrying —
// consumed from nix.integration.dlq.
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
