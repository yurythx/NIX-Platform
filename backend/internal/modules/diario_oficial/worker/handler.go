// Package worker adapts the diario_oficial module's application service
// to the platform's generic events.MessageHandler shape, for the two
// queues this module owns: the job trigger and its dead-letter sink.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
)

type jobPayload struct {
	JobID string `json:"job_id"`
}

// JobCreatedHandler processes diario_oficial.job.created events —
// consumed from nix.diario_oficial.worker.
func JobCreatedHandler(svc *application.Service) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("diario_oficial worker: decode payload: %w", err)
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			return fmt.Errorf("diario_oficial worker: invalid job_id: %w", err)
		}
		return svc.ProcessJob(ctx, jobID, event.CorrelationID)
	}
}

// DeadLetterHandler processes messages RabbitMQ has given up retrying —
// consumed from nix.diario_oficial.dlq. It's the terminal outcome for a
// job, so failures here are logged loudly but always acked: there is
// nowhere further for the message to go.
func DeadLetterHandler(svc *application.Service, logger *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			logger.Error("diario_oficial dlq: undecodable payload, dropping", slog.Any("error", err))
			return nil
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			logger.Error("diario_oficial dlq: invalid job_id, dropping", slog.Any("error", err))
			return nil
		}

		if err := svc.HandleDeadLetter(ctx, jobID, event.CorrelationID, "max retries exceeded"); err != nil {
			logger.Error("diario_oficial dlq: failed to record dead letter outcome", slog.String("job_id", payload.JobID), slog.Any("error", err))
			return nil
		}
		return nil
	}
}
