// Package events define o envelope de evento usado em toda a plataforma e
// as abstrações de mensageria das quais as camadas de domínio/aplicação
// dependem. O transporte concreto (RabbitMQ) vive em
// internal/platform/messaging e implementa estas interfaces — o domínio
// nunca importa um cliente AMQP diretamente (§25), o que permite trocar de
// broker sem tocar em regra de negócio.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EnvelopeVersion é a versão atual do schema do envelope de evento.
const EnvelopeVersion = 1

// Event é o envelope padrão que toda mensagem publicada/consumida carrega.
// Type também serve como routing key do RabbitMQ e precisa seguir a
// convenção "<contexto>.<entidade>.<ação>", ex.:
// "diario_oficial.job.completed".
type Event struct {
	ID            uuid.UUID       `json:"id"`
	Type          string          `json:"type"`
	Version       int             `json:"version"`
	Source        string          `json:"source"`
	OccurredAt    time.Time       `json:"occurred_at"`
	CorrelationID uuid.UUID       `json:"correlation_id"`
	Payload       json.RawMessage `json:"payload"`
}

// New constrói um envelope Event, serializando payload no campo Payload.
func New(eventType, source string, correlationID uuid.UUID, payload any) (Event, error) {
	if eventType == "" {
		return Event{}, fmt.Errorf("events: type is required")
	}
	if source == "" {
		return Event{}, fmt.Errorf("events: source is required")
	}
	if correlationID == uuid.Nil {
		correlationID = uuid.New()
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("events: marshal payload: %w", err)
	}

	return Event{
		ID:            uuid.New(),
		Type:          eventType,
		Version:       EnvelopeVersion,
		Source:        source,
		OccurredAt:    time.Now().UTC(),
		CorrelationID: correlationID,
		Payload:       raw,
	}, nil
}

// UnmarshalPayload decodifica o payload do evento em dst.
func (e Event) UnmarshalPayload(dst any) error {
	return json.Unmarshal(e.Payload, dst)
}

// EventPublisher publica um envelope de evento já totalmente formado.
// Implementações precisam usar o Type do evento como routing key e devem
// oferecer garantia de entrega pelo menos uma vez (at-least-once —
// ex.: publisher confirms do RabbitMQ).
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

// MessageHandler processa um evento consumido. Retornar nil confirma
// (acknowledge) a mensagem; retornar um erro dispara a política de
// retry/DLQ do transporte. Handlers precisam ser idempotentes — o mesmo id
// de evento pode ser entregue mais de uma vez (ex.: numa redelivery após
// falha de rede antes do ack chegar ao broker).
type MessageHandler func(ctx context.Context, event Event) error

// EventConsumer assina handler a uma origem específica do transporte
// (uma fila) e bloqueia até ctx ser cancelado ou ocorrer um erro
// irrecuperável.
type EventConsumer interface {
	Consume(ctx context.Context, handler MessageHandler) error
}
