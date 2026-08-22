// Package worker adapta o serviço de aplicação do módulo diario_oficial
// para o formato genérico events.MessageHandler da plataforma, para as
// duas filas que este módulo possui: o gatilho do job e seu sink de dead
// letter.
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

// JobCreatedHandler processa eventos diario_oficial.job.created —
// consumidos de nix.diario_oficial.worker. Um erro retornado aqui aciona
// o retry com backoff do consumer (ver internal/platform/messaging); só
// depois de esgotados os retries é que a mensagem cai na DLQ e chega ao
// DeadLetterHandler abaixo.
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

// DeadLetterHandler processa mensagens que o RabbitMQ já desistiu de
// tentar de novo — consumidas de nix.diario_oficial.dlq. É o desfecho
// terminal para um job, então falhas aqui são logadas de forma bem visível
// mas sempre confirmadas (ack): não há mais para onde a mensagem ir, então
// retornar erro e reprocessá-la de novo não ajudaria em nada.
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
