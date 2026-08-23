package messaging

import (
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ExchangeEvents é o único exchange topic da plataforma (§8). A routing
// key de todo evento publicado é o Type do seu envelope, seguindo a
// convenção "<contexto>.<entidade>.<ação>" (§9) — ex.:
// "diario_oficial.job.completed".
const ExchangeEvents = "nix.events"

// QueueSpec descreve uma fila de trabalho durável: a quais padrões de
// routing key ela está vinculada (bind) no ExchangeEvents, e a fila de
// dead letter (DLQ) para onde as mensagens vão quando esgotam
// RabbitMQConfig.MaxRetries (§11).
type QueueSpec struct {
	Name        string
	DLQName     string
	RoutingKeys []string
}

// RetryHeader carrega a contagem da tentativa de entrega atual. Não é um
// header nativo do AMQP — a plataforma o define/lê explicitamente para que
// os retries usem um backoff controlado pela aplicação (ver consumer.go)
// em vez de uma segunda fila de TTL/DLX-bounce por routing key.
const RetryHeader = "x-nix-attempt"

var (
	// QueueDiarioOficialWorker consome apenas o evento-gatilho que inicia
	// uma execução do job do Diário Oficial; job.completed/failed são
	// publicados POR este worker, não consumidos por ele.
	QueueDiarioOficialWorker = QueueSpec{
		Name:        "nix.diario_oficial.worker",
		DLQName:     "nix.diario_oficial.dlq",
		RoutingKeys: []string{"diario_oficial.job.created"},
	}

	// QueueScanningWorker consome apenas o evento-gatilho que inicia uma
	// execução de scan (ex.: o TrivyScanner clonando um repositório e
	// escaneando); scanning.scan.completed/failed são publicados POR este
	// worker, não consumidos por ele.
	QueueScanningWorker = QueueSpec{
		Name:        "nix.scanning.worker",
		DLQName:     "nix.scanning.dlq",
		RoutingKeys: []string{"scanning.scan.requested"},
	}

	// QueueNotificationWebsocket alimenta o Hub de WebSocket (§37/§72):
	// está vinculada a todo tipo de evento sobre o qual o frontend deve
	// ser notificado, não só a eventos explícitos "notification.created".
	QueueNotificationWebsocket = QueueSpec{
		Name:    "nix.notification.websocket",
		DLQName: "nix.notification.dlq",
		RoutingKeys: []string{
			"notification.created",
			"diario_oficial.job.completed",
			"diario_oficial.job.failed",
			"integration.status.changed",
			"scanning.scan.completed",
			"scanning.scan.failed",
		},
	}
)

// AllQueues lista toda fila que a plataforma declara no startup.
func AllQueues() []QueueSpec {
	return []QueueSpec{QueueDiarioOficialWorker, QueueScanningWorker, QueueNotificationWebsocket}
}

// DeclareTopology declara de forma idempotente o exchange, toda fila e sua
// DLQ, e seus bindings. Seguro de chamar tanto do cmd/api quanto do
// cmd/worker em todo startup — redeclarar uma topologia idêntica é um
// no-op documentado no RabbitMQ; só dá erro se as propriedades de uma
// entidade já existente forem diferentes das que estão sendo declaradas
// agora.
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
	// DLQ: um sink durável simples. Nada sai dela por dead-letter — é o
	// fim da linha, onde mensagens que esgotaram os retries ficam
	// esperando investigação manual.
	if _, err := ch.QueueDeclare(spec.DLQName, true, false, false, false, nil); err != nil {
		return fmt.Errorf("messaging: declare DLQ %s: %w", spec.DLQName, err)
	}

	// Fila principal: falhas finais (Nack com requeue=false, emitido uma
	// vez que RABBITMQ_MAX_RETRIES se esgota) são roteadas nativamente
	// para a DLQ via o exchange padrão (default exchange), usando o
	// próprio nome da DLQ como routing key.
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
