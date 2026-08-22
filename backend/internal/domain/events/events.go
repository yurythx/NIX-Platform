// Package events defines the platform-wide event envelope and the
// messaging abstractions the domain/application layers depend on.
// Concrete transport (RabbitMQ) lives in internal/platform/messaging and
// implements these interfaces — the domain never imports an AMQP client.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EnvelopeVersion is the current event envelope schema version.
const EnvelopeVersion = 1

// Event is the standard envelope every published/consumed message carries.
// Type doubles as the RabbitMQ routing key and must follow the
// "<context>.<entity>.<action>" convention, e.g. "diario_oficial.job.completed".
type Event struct {
	ID            uuid.UUID       `json:"id"`
	Type          string          `json:"type"`
	Version       int             `json:"version"`
	Source        string          `json:"source"`
	OccurredAt    time.Time       `json:"occurred_at"`
	CorrelationID uuid.UUID       `json:"correlation_id"`
	Payload       json.RawMessage `json:"payload"`
}

// New builds an Event envelope, marshaling payload into the Payload field.
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

// UnmarshalPayload decodes the event payload into dst.
func (e Event) UnmarshalPayload(dst any) error {
	return json.Unmarshal(e.Payload, dst)
}

// EventPublisher publishes a fully-formed event envelope. Implementations
// must use the event's Type as the routing key and should provide
// at-least-once delivery guarantees (e.g. RabbitMQ publisher confirms).
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

// MessageHandler processes one consumed event. Returning nil acknowledges
// the message; returning an error triggers the transport's retry/DLQ
// policy. Handlers must be idempotent — the same event ID may be delivered
// more than once.
type MessageHandler func(ctx context.Context, event Event) error

// EventConsumer subscribes handler to a transport-specific source (queue)
// and blocks until ctx is cancelled or an unrecoverable error occurs.
type EventConsumer interface {
	Consume(ctx context.Context, handler MessageHandler) error
}
