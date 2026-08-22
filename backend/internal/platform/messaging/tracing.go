package messaging

import (
	"go.opentelemetry.io/otel"

	amqp "github.com/rabbitmq/amqp091-go"
)

var tracer = otel.Tracer("nix.messaging")

// amqpHeaderCarrier adapts amqp.Table to otel's TextMapCarrier so trace
// context travels with a message from Publish to Consume — a no-op when
// tracing is disabled (§51's default), and a real cross-process link
// (HTTP request -> outbox -> RabbitMQ -> worker) when it's configured.
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
