package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// Consumer implements events.EventConsumer for a single queue. Retries are
// application-controlled: on handler failure it sleeps for a backoff
// interval, then republishes an updated copy of the message (with an
// incremented attempt count) and acks the original — rather than relying
// on RabbitMQ's native requeue, which cannot carry an updated attempt
// count. Once RabbitMQConfig.MaxRetries is exhausted, the delivery is
// nacked without requeue, which RabbitMQ routes natively to the queue's
// configured DLQ (§11/§12/§13).
type Consumer struct {
	conn        *Connection
	queueName   string
	prefetch    int
	maxRetries  int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	logger      *slog.Logger
}

var _ events.EventConsumer = (*Consumer)(nil)

// NewConsumer builds a Consumer for queueName.
func NewConsumer(conn *Connection, queueName string, prefetch, maxRetries int, logger *slog.Logger) *Consumer {
	return &Consumer{
		conn:        conn,
		queueName:   queueName,
		prefetch:    prefetch,
		maxRetries:  maxRetries,
		baseBackoff: 2 * time.Second,
		maxBackoff:  30 * time.Second,
		logger:      logger,
	}
}

// Consume subscribes to the queue and dispatches each delivery to handler
// on its own goroutine (bounded by prefetch, so a slow handler or retry
// backoff never blocks unrelated messages). It blocks until ctx is
// cancelled, then waits for in-flight deliveries to finish before
// returning.
func (c *Consumer) Consume(ctx context.Context, handler events.MessageHandler) error {
	ch, err := c.conn.Channel()
	if err != nil {
		return fmt.Errorf("messaging: open channel for queue %s: %w", c.queueName, err)
	}

	var (
		wg    sync.WaitGroup
		ackMu sync.Mutex // serializes every operation on the shared channel `ch`, including its Close
		sem   = make(chan struct{}, max(c.prefetch, 1))
	)
	// Closing `ch` must never race an in-flight Ack/Nack issued by a
	// handler goroutine — both go through ackMu, and wg.Wait() below
	// guarantees every such goroutine has already finished before this
	// runs.
	defer func() {
		ackMu.Lock()
		_ = ch.Close()
		ackMu.Unlock()
	}()

	if err := ch.Qos(c.prefetch, 0, false); err != nil {
		return fmt.Errorf("messaging: set QoS for queue %s: %w", c.queueName, err)
	}

	// Deliberately Consume (not ConsumeWithContext): the context variant
	// spawns an internal goroutine that calls ch.Cancel on ctx.Done(),
	// racing our own Ack/Nack calls on the same channel outside ackMu's
	// protection. We fully own shutdown ourselves below instead — once
	// ctx is done we stop reading deliveries and close ch under ackMu.
	deliveries, err := ch.Consume(c.queueName, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("messaging: consume queue %s: %w", c.queueName, err)
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case d, ok := <-deliveries:
			if !ok {
				wg.Wait()
				return nil
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(d amqp.Delivery) {
				defer wg.Done()
				defer func() { <-sem }()
				c.handleDelivery(ctx, &ackMu, d, handler)
			}(d)
		}
	}
}

func (c *Consumer) handleDelivery(ctx context.Context, ackMu *sync.Mutex, d amqp.Delivery, handler events.MessageHandler) {
	logger := c.logger.With(slog.String("queue", c.queueName), slog.String("routing_key", d.RoutingKey), slog.String("message_id", d.MessageId))

	ctx = otel.GetTextMapPropagator().Extract(ctx, amqpHeaderCarrier(d.Headers))
	ctx, span := tracer.Start(ctx, "consume "+d.RoutingKey,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "rabbitmq"),
			attribute.String("messaging.destination.name", c.queueName),
			attribute.String("messaging.rabbitmq.routing_key", d.RoutingKey),
			attribute.String("messaging.message.id", d.MessageId),
		),
	)
	defer span.End()

	var event events.Event
	if err := json.Unmarshal(d.Body, &event); err != nil {
		// A malformed envelope can never succeed on retry — send it
		// straight to the DLQ instead of burning retry attempts on it.
		logger.Error("dropping undecodable message to DLQ", slog.Any("error", err))
		_ = traceErr(span, err)
		metrics.RabbitMQDLQTotal.WithLabelValues(c.queueName).Inc()
		ackMu.Lock()
		_ = d.Nack(false, false)
		ackMu.Unlock()
		return
	}

	handlerErr := handler(ctx, event)
	if handlerErr == nil {
		metrics.RabbitMQConsumedTotal.WithLabelValues(c.queueName).Inc()
		ackMu.Lock()
		_ = d.Ack(false)
		ackMu.Unlock()
		return
	}
	_ = traceErr(span, handlerErr)
	metrics.RabbitMQFailedTotal.WithLabelValues(c.queueName).Inc()

	attempt := attemptFromHeaders(d.Headers) + 1
	logger = logger.With(slog.Int("attempt", attempt), slog.Any("handler_error", handlerErr))

	if attempt > c.maxRetries {
		logger.Error("handler failed, max retries exhausted, routing to DLQ")
		metrics.RabbitMQDLQTotal.WithLabelValues(c.queueName).Inc()
		ackMu.Lock()
		_ = d.Nack(false, false)
		ackMu.Unlock()
		return
	}

	backoff := computeBackoff(attempt, c.baseBackoff, c.maxBackoff)
	logger.Warn("handler failed, retrying after backoff", slog.Duration("backoff", backoff))
	metrics.RabbitMQRetryTotal.WithLabelValues(c.queueName).Inc()

	select {
	case <-time.After(backoff):
	case <-ctx.Done():
		// Shutting down: put it straight back on the queue for whichever
		// consumer picks it up next, rather than blocking shutdown on a
		// full backoff sleep.
		ackMu.Lock()
		_ = d.Nack(false, true)
		ackMu.Unlock()
		return
	}

	// The republish-and-wait-for-confirm below deliberately does NOT
	// inherit ctx's cancellation: once the retried copy has been
	// published, a concurrent, unrelated event on this same consumer
	// (another delivery succeeding and triggering shutdown, or shutdown
	// itself) must not turn a publish that already reached the broker
	// into a spurious "failure" that falls back to native requeue and
	// double-delivers the message. A bounded timeout still protects
	// against a genuinely stuck broker.
	retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	err := c.republish(retryCtx, d, event, attempt)
	cancel()
	if err != nil {
		logger.Error("retry republish failed, falling back to native requeue", slog.Any("error", err))
		ackMu.Lock()
		_ = d.Nack(false, true)
		ackMu.Unlock()
		return
	}

	ackMu.Lock()
	_ = d.Ack(false)
	ackMu.Unlock()
}

// republish sends an updated copy of the message (with an incremented
// attempt header) back through the exchange, using a fresh channel and
// publisher confirms — independent of the shared consume channel `ch`.
func (c *Consumer) republish(ctx context.Context, d amqp.Delivery, event events.Event, attempt int) error {
	ch, err := c.conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	if err := ch.Confirm(false); err != nil {
		return err
	}

	headers := amqp.Table{}
	for k, v := range d.Headers {
		headers[k] = v
	}
	headers[RetryHeader] = int32(attempt)

	confirmation, err := ch.PublishWithDeferredConfirmWithContext(ctx, ExchangeEvents, d.RoutingKey, false, false, amqp.Publishing{
		ContentType:   d.ContentType,
		DeliveryMode:  amqp.Persistent,
		MessageId:     event.ID.String(),
		CorrelationId: event.CorrelationID.String(),
		Timestamp:     event.OccurredAt,
		Type:          event.Type,
		Body:          d.Body,
		Headers:       headers,
	})
	if err != nil {
		return err
	}

	ok, err := confirmation.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("messaging: broker nacked retry republish of %s", event.Type)
	}
	return nil
}

func attemptFromHeaders(headers amqp.Table) int {
	v, ok := headers[RetryHeader]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int32:
		return int(n)
	case int64:
		return int(n)
	case int:
		return n
	case int16:
		return int(n)
	default:
		return 0
	}
}

func computeBackoff(attempt int, base, maxDur time.Duration) time.Duration {
	d := base
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= maxDur {
			return maxDur
		}
	}
	return d
}
