package audit

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live audit integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestWriter_Record(t *testing.T) {
	pool := testPool(t)
	writer := NewWriter(pool)
	corrID := uuid.New()

	err := writer.Record(context.Background(), Entry{
		Action:        ActionIntegrationTest,
		ResourceType:  "integration",
		ResourceID:    "virustotal",
		Metadata:      map[string]any{"result": "online"},
		CorrelationID: &corrID,
		IPAddress:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	var action, resourceType, resourceID string
	err = pool.QueryRow(context.Background(),
		`SELECT action, resource_type, resource_id FROM audit_logs WHERE correlation_id = $1`, corrID,
	).Scan(&action, &resourceType, &resourceID)
	if err != nil {
		t.Fatalf("query row: %v", err)
	}

	if action != ActionIntegrationTest {
		t.Errorf("action = %q", action)
	}
	if resourceType != "integration" {
		t.Errorf("resource_type = %q", resourceType)
	}
	if resourceID != "virustotal" {
		t.Errorf("resource_id = %q", resourceID)
	}
}

func TestWriter_Record_NilUserAndEmptyIP(t *testing.T) {
	pool := testPool(t)
	writer := NewWriter(pool)
	corrID := uuid.New()

	err := writer.Record(context.Background(), Entry{
		Action:        ActionLogin,
		CorrelationID: &corrID,
	})
	if err != nil {
		t.Fatalf("Record with nil user/empty IP: %v", err)
	}
}
