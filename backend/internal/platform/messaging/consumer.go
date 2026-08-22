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

// Consumer implementa events.EventConsumer para uma única fila. Os retries
// são controlados pela aplicação: quando o handler falha, o consumer
// espera um intervalo de backoff, depois republica uma cópia atualizada da
// mensagem (com a contagem de tentativas incrementada) e faz ack da
// original — em vez de depender do requeue nativo do RabbitMQ, que não
// consegue carregar uma contagem de tentativas atualizada. Uma vez que
// RabbitMQConfig.MaxRetries se esgota, a entrega é nackada sem requeue, o
// que o RabbitMQ roteia nativamente para a DLQ configurada da fila
// (§11/§12/§13).
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

// NewConsumer constrói um Consumer para queueName.
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

// Consume assina a fila e despacha cada entrega para handler em sua
// própria goroutine (limitada por prefetch, para que um handler lento ou
// um backoff de retry nunca bloqueie mensagens não relacionadas). Bloqueia
// até ctx ser cancelado, e então espera as entregas em andamento
// terminarem antes de retornar.
func (c *Consumer) Consume(ctx context.Context, handler events.MessageHandler) error {
	ch, err := c.conn.Channel()
	if err != nil {
		return fmt.Errorf("messaging: open channel for queue %s: %w", c.queueName, err)
	}

	var (
		wg    sync.WaitGroup
		ackMu sync.Mutex // serializa toda operação no canal compartilhado `ch`, incluindo seu Close
		sem   = make(chan struct{}, max(c.prefetch, 1))
	)
	// Fechar `ch` nunca pode competir (race) com um Ack/Nack em andamento
	// emitido por uma goroutine de handler — ambos passam por ackMu, e o
	// wg.Wait() abaixo garante que toda goroutine desse tipo já terminou
	// antes deste defer rodar.
	defer func() {
		ackMu.Lock()
		_ = ch.Close()
		ackMu.Unlock()
	}()

	if err := ch.Qos(c.prefetch, 0, false); err != nil {
		return fmt.Errorf("messaging: set QoS for queue %s: %w", c.queueName, err)
	}

	// Deliberadamente Consume (não ConsumeWithContext): a variante com
	// contexto cria uma goroutine interna que chama ch.Cancel quando
	// ctx.Done() dispara, competindo com nossas próprias chamadas de
	// Ack/Nack no mesmo canal fora da proteção de ackMu. Preferimos
	// controlar o shutdown por conta própria abaixo — assim que ctx
	// termina, paramos de ler entregas e fechamos ch sob ackMu.
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

	// Extrai o contexto de trace propagado nos headers AMQP (injetado pelo
	// publisher) para que o span de consumo continue o mesmo trace da
	// requisição HTTP que originou o evento (§51).
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
		// Um envelope malformado nunca vai ter sucesso numa nova
		// tentativa — manda direto para a DLQ em vez de queimar
		// tentativas de retry nele.
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
		// Processo entrando em shutdown: devolve a mensagem direto para a
		// fila para o próximo consumer que a pegar, em vez de bloquear o
		// shutdown esperando um backoff completo.
		ackMu.Lock()
		_ = d.Nack(false, true)
		ackMu.Unlock()
		return
	}

	// O republish-e-espera-confirmação abaixo deliberadamente NÃO herda o
	// cancelamento de ctx: uma vez que a cópia com retry já foi publicada,
	// um evento concorrente e não relacionado neste mesmo consumer (outra
	// entrega tendo sucesso e disparando o shutdown, ou o próprio
	// shutdown) não pode transformar uma publicação que já chegou no
	// broker numa "falha" espúria que cai de volta no requeue nativo e
	// entrega a mensagem em duplicidade. Um timeout limitado ainda protege
	// contra um broker genuinamente travado.
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

// republish envia uma cópia atualizada da mensagem (com o header de
// tentativa incrementado) de volta pelo exchange, usando um canal novo e
// publisher confirms — independente do canal de consumo compartilhado `ch`,
// para que o retry não dispute o mesmo canal usado para ack/nack das
// entregas.
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

// attemptFromHeaders lê o número da tentativa atual gravado em RetryHeader
// (0 se a mensagem nunca foi republicada como retry, ou seja, é a primeira
// entrega). O AMQP pode desserializar inteiros em tipos Go diferentes
// dependendo do broker, por isso os vários casos abaixo.
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

// computeBackoff calcula o atraso exponencial (base, 2×base, 4×base, ...)
// para a tentativa informada, limitado por maxDur.
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
