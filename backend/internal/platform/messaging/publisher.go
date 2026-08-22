package messaging

import (
	"context"
	"encoding/json"
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/yurythx/nix-platform/internal/domain/events"
)

// Publisher implements events.EventPublisher over a topic-exchange
// publish with Publisher Confirms (§14): every Publish call blocks until
// RabbitMQ has confirmed the message was accepted, or returns an error.
type Publisher struct {
	conn *Connection
}

// NewPublisher builds a Publisher over conn. Compile-time check that it
// satisfies the domain-facing interface.
var _ events.EventPublisher = (*Publisher)(nil)

func NewPublisher(conn *Connection) *Publisher {
	return &Publisher{conn: conn}
}

// Publish sends event to ExchangeEvents using event.Type as the routing
// key, and waits for RabbitMQ's publisher confirm before returning.
func (p *Publisher) Publish(ctx context.Context, event events.Event) error {
	ch, err := p.conn.Channel()
	if err != nil {
		return fmt.Errorf("messaging: open channel: %w", err)
	}
	defer ch.Close()

	if err := ch.Confirm(false); err != nil {
		return fmt.Errorf("messaging: enable publisher confirms: %w", err)
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("messaging: marshal event envelope: %w", err)
	}

	confirmation, err := ch.PublishWithDeferredConfirmWithContext(ctx, ExchangeEvents, event.Type, false, false, amqp.Publishing{
		ContentType:   "application/json",
		DeliveryMode:  amqp.Persistent,
		MessageId:     event.ID.String(),
		CorrelationId: event.CorrelationID.String(),
		Timestamp:     event.OccurredAt,
		Type:          event.Type,
		Body:          body,
		Headers: amqp.Table{
			RetryHeader: int32(0),
		},
	})
	if err != nil {
		return fmt.Errorf("messaging: publish %s: %w", event.Type, err)
	}

	ok, err := confirmation.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("messaging: wait for publisher confirm on %s: %w", event.Type, err)
	}
	if !ok {
		return fmt.Errorf("messaging: broker nacked publish of %s (id=%s)", event.Type, event.ID)
	}
	return nil
}
