package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
)

// These tests run against the real, migrated PostgreSQL used across this
// backend's test suite (and, for one test, a real RabbitMQ) — skipped
// unless TEST_DATABASE_URL is set, so `go test ./...` stays green without
// infrastructure.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live outbox integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// truncateOutbox clears outbox_events so each test's publishPendingBatch
// call only ever sees rows it wrote itself — publishPendingBatch
// deliberately scans every pending row regardless of aggregate, exactly
// like the real worker would, so tests must not leak state into each other.
//
// This only works against leaks from tests within THIS package/binary.
// Other packages (diario_oficial, secops) write real outbox_events rows
// via the same live database too and don't publish/clean them up — run
// with `go test ./... -p 1` (see Makefile/README) so package test
// binaries never run concurrently against the shared table.
func truncateOutbox(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM outbox_events`); err != nil {
		t.Fatalf("truncate outbox_events: %v", err)
	}
}

func countOutboxRows(t *testing.T, pool *pgxpool.Pool, aggregateID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox_events WHERE aggregate_id = $1`, aggregateID).Scan(&n); err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	return n
}

func TestWriter_WritesWithinTransaction(t *testing.T) {
	pool := testPool(t)
	truncateOutbox(t, pool)
	writer := NewWriter("nix.test")

	aggregateID := uuid.NewString()
	corrID := uuid.New()

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if err := writer.Write(context.Background(), tx, "test.aggregate.created", "test_aggregate", aggregateID, corrID, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if got := countOutboxRows(t, pool, aggregateID); got != 1 {
		t.Fatalf("outbox row count = %d, want 1", got)
	}

	var status string
	var payload []byte
	err = pool.QueryRow(context.Background(),
		`SELECT status, payload FROM outbox_events WHERE aggregate_id = $1`, aggregateID,
	).Scan(&status, &payload)
	if err != nil {
		t.Fatalf("query row: %v", err)
	}
	if status != "pending" {
		t.Errorf("status = %q, want pending", status)
	}

	var event events.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if event.Type != "test.aggregate.created" {
		t.Errorf("event.Type = %q", event.Type)
	}
	if event.CorrelationID != corrID {
		t.Errorf("event.CorrelationID = %v, want %v", event.CorrelationID, corrID)
	}
}

func TestWriter_RollbackDiscardsEvent(t *testing.T) {
	pool := testPool(t)
	truncateOutbox(t, pool)
	writer := NewWriter("nix.test")
	aggregateID := uuid.NewString()

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := writer.Write(context.Background(), tx, "test.aggregate.created", "test_aggregate", aggregateID, uuid.New(), nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if got := countOutboxRows(t, pool, aggregateID); got != 0 {
		t.Fatalf("outbox row count after rollback = %d, want 0 (atomicity with business tx broken)", got)
	}
}

// failingPublisher always fails, to exercise the outbox's retry/give-up path.
type failingPublisher struct {
	calls int32
}

func (f *failingPublisher) Publish(ctx context.Context, event events.Event) error {
	atomic.AddInt32(&f.calls, 1)
	return fmt.Errorf("simulated broker unavailable")
}

func TestPublisher_ExhaustsAttemptsAndMarksFailed(t *testing.T) {
	pool := testPool(t)
	truncateOutbox(t, pool)
	writer := NewWriter("nix.test")
	aggregateID := uuid.NewString()

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := writer.Write(context.Background(), tx, "test.aggregate.created", "test_aggregate", aggregateID, uuid.New(), nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	fp := &failingPublisher{}
	pub := NewPublisher(pool, fp, testLogger())
	pub.maxAttempts = 3

	ctx := context.Background()
	for i := 0; i < pub.maxAttempts; i++ {
		if err := pub.publishPendingBatch(ctx); err != nil {
			t.Fatalf("publishPendingBatch: %v", err)
		}
	}

	var status string
	var attempts int
	var lastError string
	err = pool.QueryRow(ctx, `SELECT status, attempts, last_error FROM outbox_events WHERE aggregate_id = $1`, aggregateID).
		Scan(&status, &attempts, &lastError)
	if err != nil {
		t.Fatalf("query row: %v", err)
	}

	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if attempts != pub.maxAttempts {
		t.Errorf("attempts = %d, want %d", attempts, pub.maxAttempts)
	}
	if lastError == "" {
		t.Error("expected last_error to be recorded")
	}
	if got := atomic.LoadInt32(&fp.calls); got != int32(pub.maxAttempts) {
		t.Errorf("publisher was called %d times, want %d (a failed row must not be retried again)", got, pub.maxAttempts)
	}

	// One more poll: the row is now "failed", not "pending" — must not be
	// picked up again.
	if err := pub.publishPendingBatch(ctx); err != nil {
		t.Fatalf("publishPendingBatch: %v", err)
	}
	if got := atomic.LoadInt32(&fp.calls); got != int32(pub.maxAttempts) {
		t.Errorf("publisher was called again after row was marked failed: calls = %d", got)
	}
}

func TestPublisher_PublishesPendingRowToRealBroker(t *testing.T) {
	rmqURL := os.Getenv("TEST_RABBITMQ_URL")
	if rmqURL == "" {
		t.Skip("TEST_RABBITMQ_URL not set; skipping live broker outbox test")
	}
	pool := testPool(t)

	conn, err := messaging.Connect(context.Background(), rmqURL, testLogger())
	if err != nil {
		t.Fatalf("messaging.Connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	suffix := uuid.NewString()[:8]
	spec := messaging.QueueSpec{
		Name:        "test.outbox." + suffix,
		DLQName:     "test.outbox." + suffix + ".dlq",
		RoutingKeys: []string{"test.outbox." + suffix + ".event"},
	}
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	if err := messaging.DeclareTopology(ch, []messaging.QueueSpec{spec}); err != nil {
		t.Fatalf("DeclareTopology: %v", err)
	}
	ch.Close()
	t.Cleanup(func() {
		ch, err := conn.Channel()
		if err != nil {
			return
		}
		defer ch.Close()
		_, _ = ch.QueueDelete(spec.Name, false, false, false)
		_, _ = ch.QueueDelete(spec.DLQName, false, false, false)
	})

	writer := NewWriter("nix.test")
	aggregateID := uuid.NewString()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := writer.Write(context.Background(), tx, spec.RoutingKeys[0], "test_aggregate", aggregateID, uuid.New(), map[string]string{"hello": "outbox"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	publisher := messaging.NewPublisher(conn)
	pub := NewPublisher(pool, publisher, testLogger())

	if err := pub.publishPendingBatch(context.Background()); err != nil {
		t.Fatalf("publishPendingBatch: %v", err)
	}

	var status string
	err = pool.QueryRow(context.Background(), `SELECT status FROM outbox_events WHERE aggregate_id = $1`, aggregateID).Scan(&status)
	if err != nil {
		t.Fatalf("query row: %v", err)
	}
	if status != "published" {
		t.Fatalf("status = %q, want published", status)
	}

	getCh, err := conn.Channel()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer getCh.Close()

	msg, ok, err := getCh.Get(spec.Name, true)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected the outbox event to have reached the real queue")
	}
	var delivered events.Event
	if err := json.Unmarshal(msg.Body, &delivered); err != nil {
		t.Fatalf("unmarshal delivered body: %v", err)
	}
	if delivered.Type != spec.RoutingKeys[0] {
		t.Errorf("delivered event Type = %q, want %q", delivered.Type, spec.RoutingKeys[0])
	}
}

// countingPublisher records how many times each event ID was published, to
// detect double-publishing under concurrent batches.
type countingPublisher struct {
	mu     sync.Mutex
	counts map[string]int
}

func newCountingPublisher() *countingPublisher {
	return &countingPublisher{counts: map[string]int{}}
}

func (c *countingPublisher) Publish(ctx context.Context, event events.Event) error {
	c.mu.Lock()
	c.counts[event.ID.String()]++
	c.mu.Unlock()
	return nil
}

func TestPublisher_ConcurrentBatches_NoDoublePublish(t *testing.T) {
	pool := testPool(t)
	truncateOutbox(t, pool)
	writer := NewWriter("nix.test")

	const rowCount = 20
	aggregateID := uuid.NewString()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for i := 0; i < rowCount; i++ {
		if err := writer.Write(context.Background(), tx, "test.aggregate.created", "test_aggregate", aggregateID, uuid.New(), map[string]int{"i": i}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	cp := newCountingPublisher()
	pubA := NewPublisher(pool, cp, testLogger())
	pubB := NewPublisher(pool, cp, testLogger())
	pubA.batchSize = rowCount
	pubB.batchSize = rowCount

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = pubA.publishPendingBatch(context.Background()) }()
	go func() { defer wg.Done(); _ = pubB.publishPendingBatch(context.Background()) }()
	wg.Wait()

	// A third pass in case SKIP LOCKED caused one batch to see fewer rows
	// than the other grabbed (rows never processed by either goroutine).
	_ = pubA.publishPendingBatch(context.Background())

	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.counts) != rowCount {
		t.Fatalf("published %d distinct events, want %d", len(cp.counts), rowCount)
	}
	for id, n := range cp.counts {
		if n != 1 {
			t.Errorf("event %s published %d times, want exactly 1", id, n)
		}
	}
}
