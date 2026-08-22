package messaging

import (
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ExchangeEvents is the platform's single topic exchange (§8). Every
// published event's routing key is its envelope Type, following the
// "<context>.<entity>.<action>" convention (§9).
const ExchangeEvents = "nix.events"

// QueueSpec describes one durable work queue: which routing key patterns
// it's bound to on ExchangeEvents, and the dead-letter queue messages land
// in once they exhaust RabbitMQConfig.MaxRetries (§11).
type QueueSpec struct {
	Name        string
	DLQName     string
	RoutingKeys []string
}

// RetryHeader carries the current delivery attempt count. It is not a
// native AMQP header — the platform sets/reads it explicitly so retries
// can use application-controlled backoff (see consumer.go) instead of a
// second TTL/DLX-bounce queue per routing key.
const RetryHeader = "x-nix-attempt"

var (
	// QueueDiarioOficialWorker consumes only the trigger event a Diário
	// Oficial job run starts from; job.completed/failed are published BY
	// this worker, not consumed by it.
	QueueDiarioOficialWorker = QueueSpec{
		Name:        "nix.diario_oficial.worker",
		DLQName:     "nix.diario_oficial.dlq",
		RoutingKeys: []string{"diario_oficial.job.created"},
	}

	// QueueIntegrationWorker handles the generic "run an integration
	// test" flow shared by every SecOps provider (VirusTotal today, more
	// later per §36/§76) without needing a new queue per provider.
	QueueIntegrationWorker = QueueSpec{
		Name:        "nix.integration.worker",
		DLQName:     "nix.integration.dlq",
		RoutingKeys: []string{"integration.test.requested"},
	}

	// QueueNotificationWebsocket feeds the WebSocket Hub (§37/§72): it is
	// bound to every event type the frontend should be notified about,
	// not only explicit "notification.created" events.
	QueueNotificationWebsocket = QueueSpec{
		Name:    "nix.notification.websocket",
		DLQName: "nix.notification.dlq",
		RoutingKeys: []string{
			"notification.created",
			"diario_oficial.job.completed",
			"diario_oficial.job.failed",
			"integration.test.completed",
			"integration.status.changed",
		},
	}
)

// AllQueues lists every queue the platform declares at startup.
func AllQueues() []QueueSpec {
	return []QueueSpec{QueueDiarioOficialWorker, QueueIntegrationWorker, QueueNotificationWebsocket}
}

// DeclareTopology idempotently declares the exchange, every queue and DLQ,
// and their bindings. Safe to call from both cmd/api and cmd/worker on
// every startup — redeclaring identical topology is a documented no-op in
// RabbitMQ; it only errors if an existing entity's properties differ.
func DeclareTopology(ch *amqp.Channel, specs []QueueSpec) error {
	if err := ch.ExchangeDeclare(
		ExchangeEvents,
		"topic",
		true,  // durable
		false, // autoDelete
		false, // internal
		false, // noWait
		nil,
	); err != nil {
		return fmt.Errorf("messaging: declare exchange %s: %w", ExchangeEvents, err)
	}

	for _, spec := range specs {
		if err := declareQueue(ch, spec); err != nil {
			return err
		}
	}
	return nil
}

func declareQueue(ch *amqp.Channel, spec QueueSpec) error {
	// DLQ: a plain durable sink. Nothing dead-letters out of it.
	if _, err := ch.QueueDeclare(spec.DLQName, true, false, false, false, nil); err != nil {
		return fmt.Errorf("messaging: declare DLQ %s: %w", spec.DLQName, err)
	}

	// Main queue: final failures (Nack with requeue=false, issued once
	// RABBITMQ_MAX_RETRIES is exhausted) are routed natively to the DLQ
	// via the default exchange using the DLQ's own name as routing key.
	mainArgs := amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": spec.DLQName,
	}
	if _, err := ch.QueueDeclare(spec.Name, true, false, false, false, mainArgs); err != nil {
		return fmt.Errorf("messaging: declare queue %s: %w", spec.Name, err)
	}

	for _, key := range spec.RoutingKeys {
		if err := ch.QueueBind(spec.Name, key, ExchangeEvents, false, nil); err != nil {
			return fmt.Errorf("messaging: bind queue %s to key %s: %w", spec.Name, key, err)
		}
	}
	return nil
}
