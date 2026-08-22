package messaging

import (
	"go.opentelemetry.io/otel"

	amqp "github.com/rabbitmq/amqp091-go"
)

var tracer = otel.Tracer("nix.messaging")

// amqpHeaderCarrier adapta amqp.Table para o TextMapCarrier do otel, para
// que o contexto de trace viaje junto com uma mensagem do Publish até o
// Consume — vira no-op quando o tracing está desabilitado (padrão do §51),
// e um link real entre processos (requisição HTTP -> outbox -> RabbitMQ ->
// worker) quando está configurado, permitindo ver o fluxo completo de um
// job num único trace.
type amqpHeaderCarrier amqp.Table

func (c amqpHeaderCarrier) Get(key string) string {
	v, ok := c[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (c amqpHeaderCarrier) Set(key, value string) {
	c[key] = value
}

func (c amqpHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}
