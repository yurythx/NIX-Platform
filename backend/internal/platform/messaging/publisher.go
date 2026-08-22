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

// Publisher implementa events.EventPublisher publicando num exchange topic
// com Publisher Confirms (§14): toda chamada a Publish bloqueia até o
// RabbitMQ confirmar que a mensagem foi aceita, ou retorna um erro — isso
// é o que garante que "o outbox marcou como publicado" só acontece depois
// que a mensagem realmente chegou no broker, não apenas foi escrita no
// socket.
type Publisher struct {
	conn *Connection
}

// Checagem em tempo de compilação de que Publisher satisfaz a interface
// voltada para o domínio.
var _ events.EventPublisher = (*Publisher)(nil)

// NewPublisher constrói um Publisher sobre conn.
func NewPublisher(conn *Connection) *Publisher {
	return &Publisher{conn: conn}
}

// Publish envia event para ExchangeEvents usando event.Type como routing
// key, e espera a confirmação do publisher do RabbitMQ antes de retornar.
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

	// Toda mensagem nasce com o contador de tentativa em zero — só o
	// consumer o incrementa, ao republicar como retry (ver consumer.go).
	// Também injeta o contexto de trace atual nos headers AMQP, para que
	// o consumer do outro lado consiga continuar o mesmo trace (§51).
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

// traceErr registra err no span e marca seu status como erro, retornando
// err sem alterá-lo — assim quem chama pode escrever
// `return traceErr(span, err)` numa linha só, sem repetir a lógica de
// registro de erro em cada ponto de retorno.
func traceErr(span trace.Span, err error) error {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}
