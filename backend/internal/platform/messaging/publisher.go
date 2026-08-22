package messaging

import (
	"context"
	"encoding/json"
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
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
	ctx, span := tracer.Start(ctx, "publish "+event.Type,
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "rabbitmq"),
			attribute.String("messaging.destination.name", ExchangeEvents),
			attribute.String("messaging.rabbitmq.routing_key", event.Type),
			attribute.String("messaging.message.id", event.ID.String()),
		),
	)
	defer span.End()

	ch, err := p.conn.Channel()
	if err != nil {
		return traceErr(span, fmt.Errorf("messaging: open channel: %w", err))
	}
	defer ch.Close()

	if err := ch.Confirm(false); err != nil {
		return traceErr(span, fmt.Errorf("messaging: enable publisher confirms: %w", err))
	}

	body, err := json.Marshal(event)
	if err != nil {
		return traceErr(span, fmt.Errorf("messaging: marshal event envelope: %w", err))
	}

	headers := amqp.Table{RetryHeader: int32(0)}
	otel.GetTextMapPropagator().Inject(ctx, amqpHeaderCarrier(headers))

	confirmation, err := ch.PublishWithDeferredConfirmWithContext(ctx, ExchangeEvents, event.Type, false, false, amqp.Publishing{
		ContentType:   "application/json",
		DeliveryMode:  amqp.Persistent,
		MessageId:     event.ID.String(),
		CorrelationId: event.CorrelationID.String(),
		Timestamp:     event.OccurredAt,
		Type:          event.Type,
		Body:          body,
		Headers:       headers,
	})
	if err != nil {
		return traceErr(span, fmt.Errorf("messaging: publish %s: %w", event.Type, err))
	}

	ok, err := confirmation.WaitContext(ctx)
	if err != nil {
		return traceErr(span, fmt.Errorf("messaging: wait for publisher confirm on %s: %w", event.Type, err))
	}
	if !ok {
		return traceErr(span, fmt.Errorf("messaging: broker nacked publish of %s (id=%s)", event.Type, event.ID))
	}

	metrics.RabbitMQPublishedTotal.WithLabelValues(event.Type).Inc()
	return nil
}

// traceErr records err on span and marks it as an error status, returning
// err unchanged so callers can `return traceErr(span, err)` in one line.
func traceErr(span trace.Span, err error) error {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}
