// Package worker adapta o serviço de aplicação do módulo scanning para o
// formato genérico events.MessageHandler da plataforma, para as duas
// filas que este módulo possui: o gatilho do job e seu sink de dead
// letter — mesmo desenho de diario_oficial/worker/handler.go.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
)

type jobPayload struct {
	JobID string `json:"job_id"`
}

// ScanRequestedHandler processa eventos scanning.scan.requested —
// consumidos de nix.scanning.worker. Um erro retornado aqui aciona o
// retry com backoff do consumer (ver internal/platform/messaging); só
// depois de esgotados os retries é que a mensagem cai na DLQ e chega ao
// DeadLetterHandler abaixo.
func ScanRequestedHandler(svc *application.Service) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("scanning worker: decode payload: %w", err)
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			return fmt.Errorf("scanning worker: invalid job_id: %w", err)
		}
		return svc.ProcessScanJob(ctx, jobID, event.CorrelationID)
	}
}

// DeadLetterHandler processa mensagens que o RabbitMQ já desistiu de
// tentar de novo — consumidas de nix.scanning.dlq. É o desfecho terminal
// para um job, então falhas aqui são logadas de forma bem visível mas
// sempre confirmadas (ack): não há mais para onde a mensagem ir.
func DeadLetterHandler(svc *application.Service, logger *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		var payload jobPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			logger.Error("scanning dlq: undecodable payload, dropping", slog.Any("error", err))
			return nil
		}
		jobID, err := uuid.Parse(payload.JobID)
		if err != nil {
			logger.Error("scanning dlq: invalid job_id, dropping", slog.Any("error", err))
			return nil
		}

		if err := svc.HandleScanDeadLetter(ctx, jobID, event.CorrelationID, "max retries exceeded"); err != nil {
			logger.Error("scanning dlq: failed to record dead letter outcome", slog.String("job_id", payload.JobID), slog.Any("error", err))
			return nil
		}
		return nil
	}
}
