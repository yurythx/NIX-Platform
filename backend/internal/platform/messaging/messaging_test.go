package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/events"
)

// Estes testes exercitam o protocolo AMQP real do RabbitMQ (declaração de
// exchange/fila, publisher confirms, ack/nack manual, backoff de retry,
// roteamento de DLQ) contra um broker ao vivo. São pulados se
// TEST_RABBITMQ_URL não estiver definida, para que `go test ./...`
// continue passando sem infraestrutura, mas não são mocks — defina
// TEST_RABBITMQ_URL (ex.: amqp://nix:nix_password@localhost:5672/nix)
// para de fato rodá-los.
func testConnection(t *testing.T) *Connection {
	t.Helper()
	url := os.Getenv("TEST_RABBITMQ_URL")
	if url == "" {
		t.Skip("TEST_RABBITMQ_URL not set; skipping live RabbitMQ integration test")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	conn, err := Connect(context.Background(), url, logger)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testQueueSpec constrói um QueueSpec com nome único (para que execuções
// paralelas/anteriores de teste nunca colidam) e registra a limpeza para
// removê-lo.
func testQueueSpec(t *testing.T, conn *Connection) QueueSpec {
	t.Helper()
	suffix := uuid.NewString()[:8]
	spec := QueueSpec{
		Name:        "test.messaging." + suffix,
		DLQName:     "test.messaging." + suffix + ".dlq",
		RoutingKeys: []string{"test.messaging." + suffix + ".event"},
	}

	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()

	if err := DeclareTopology(ch, []QueueSpec{spec}); err != nil {
		t.Fatalf("DeclareTopology: %v", err)
	}

	t.Cleanup(func() {
		ch, err := conn.Channel()
		if err != nil {
			return
		}
		defer ch.Close()
		_, _ = ch.QueueDelete(spec.Name, false, false, false)
		_, _ = ch.QueueDelete(spec.DLQName, false, false, false)
	})

	return spec
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestDeclareTopology_IsIdempotent(t *testing.T) {
	conn := testConnection(t)
	spec := testQueueSpec(t, conn)

	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()

	// Declarar a mesma topologia de novo não pode dar erro.
	if err := DeclareTopology(ch, []QueueSpec{spec}); err != nil {
		t.Fatalf("second DeclareTopology call failed: %v", err)
	}
}

func TestPublisher_PublishIsConfirmedAndConsumable(t *testing.T) {
	conn := testConnection(t)
	spec := testQueueSpec(t, conn)
	publisher := NewPublisher(conn)

	corrID := uuid.New()
	event, err := events.New(spec.RoutingKeys[0], "nix.test", corrID, map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("events.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, event); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Consome de volta diretamente (contornando o Consumer) para provar
	// que realmente chegou na fila, durável e com o corpo certo.
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()

	msg, ok, err := ch.Get(spec.Name, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a message in the queue, got none")
	}
	_ = msg.Ack(false)

	var got events.Event
	if err := json.Unmarshal(msg.Body, &got); err != nil {
		t.Fatalf("unmarshal delivered body: %v", err)
	}
	if got.ID != event.ID {
		t.Errorf("delivered event ID = %v, want %v", got.ID, event.ID)
	}
	if got.Type != event.Type {
		t.Errorf("delivered event Type = %q, want %q", got.Type, event.Type)
	}
	if got.CorrelationID != corrID {
		t.Errorf("delivered CorrelationID = %v, want %v", got.CorrelationID, corrID)
	}
}

func TestConsumer_AcksOnSuccess(t *testing.T) {
	conn := testConnection(t)
	spec := testQueueSpec(t, conn)
	publisher := NewPublisher(conn)
	consumer := NewConsumer(conn, spec.Name, 5, 3, testLogger())

	event, _ := events.New(spec.RoutingKeys[0], "nix.test", uuid.New(), map[string]string{"k": "v"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, event); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var handled int32
	consumeCtx, stopConsume := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- consumer.Consume(consumeCtx, func(ctx context.Context, e events.Event) error {
			atomic.AddInt32(&handled, 1)
			stopConsume()
			return nil
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for consumer to process and shut down")
	}

	if atomic.LoadInt32(&handled) != 1 {
		t.Fatalf("handled = %d, want 1", handled)
	}

	assertQueueEmpty(t, conn, spec.Name)
}

func TestConsumer_RetriesThenSucceeds(t *testing.T) {
	conn := testConnection(t)
	spec := testQueueSpec(t, conn)
	publisher := NewPublisher(conn)
	consumer := NewConsumer(conn, spec.Name, 5, 3, testLogger())
	consumer.baseBackoff = 200 * time.Millisecond // keep the test fast
	consumer.maxBackoff = 200 * time.Millisecond

	event, _ := events.New(spec.RoutingKeys[0], "nix.test", uuid.New(), map[string]string{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, event); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var attempts int32
	consumeCtx, stopConsume := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- consumer.Consume(consumeCtx, func(ctx context.Context, e events.Event) error {
			n := atomic.AddInt32(&attempts, 1)
			if n < 2 {
				return fmt.Errorf("simulated transient failure")
			}
			stopConsume()
			return nil
		})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for retry to succeed")
	}

	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", got)
	}
	assertQueueEmpty(t, conn, spec.Name)
	assertQueueEmpty(t, conn, spec.DLQName)
}

func TestConsumer_ExhaustsRetriesAndRoutesToDLQ(t *testing.T) {
	conn := testConnection(t)
	spec := testQueueSpec(t, conn)
	publisher := NewPublisher(conn)
	const maxRetries = 2
	consumer := NewConsumer(conn, spec.Name, 5, maxRetries, testLogger())
	consumer.baseBackoff = 100 * time.Millisecond
	consumer.maxBackoff = 100 * time.Millisecond

	event, _ := events.New(spec.RoutingKeys[0], "nix.test", uuid.New(), map[string]string{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, event); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var attempts int32
	var once sync.Once
	consumeCtx, stopConsume := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- consumer.Consume(consumeCtx, func(ctx context.Context, e events.Event) error {
			n := atomic.AddInt32(&attempts, 1)
			if int(n) > maxRetries {
				once.Do(stopConsume)
			}
			return fmt.Errorf("always fails")
		})
	}()

	// O handler continua falhando para sempre; passado maxRetries ele
	// nunca seria chamado de novo para ESTA mensagem (ela é roteada para
	// a DLQ), então para o consumer logo depois de vermos maxRetries+1
	// tentativas (a última sendo a que dispara o nack de DLQ) ou por
	// timeout.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		stopConsume()
		<-done
	}

	if got := atomic.LoadInt32(&attempts); got != maxRetries+1 {
		t.Fatalf("attempts = %d, want %d (initial + %d retries)", got, maxRetries+1, maxRetries)
	}

	assertQueueEmpty(t, conn, spec.Name)
	assertQueueHasMessage(t, conn, spec.DLQName)
}

func assertQueueEmpty(t *testing.T, conn *Connection, queue string) {
	t.Helper()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()

	// Dá ao RabbitMQ um instante para assentar o ack/requeue antes de
	// inspecionarmos a profundidade da fila.
	time.Sleep(300 * time.Millisecond)

	q, err := ch.QueueInspect(queue)
	if err != nil {
		t.Fatalf("QueueInspect(%s): %v", queue, err)
	}
	if q.Messages != 0 {
		t.Errorf("queue %s has %d messages, want 0", queue, q.Messages)
	}
}

func assertQueueHasMessage(t *testing.T, conn *Connection, queue string) {
	t.Helper()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()

	time.Sleep(300 * time.Millisecond)

	q, err := ch.QueueInspect(queue)
	if err != nil {
		t.Fatalf("QueueInspect(%s): %v", queue, err)
	}
	if q.Messages == 0 {
		t.Errorf("queue %s has 0 messages, want at least 1", queue)
	}
}
