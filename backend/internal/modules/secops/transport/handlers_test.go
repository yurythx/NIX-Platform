package transport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	"github.com/yurythx/nix-platform/internal/modules/secops/application"
	"github.com/yurythx/nix-platform/internal/modules/secops/domain"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// Mesmo raciocínio do handler_test.go de diario_oficial/transport:
// application.Service é transacional e recebe *pgxpool.Pool diretamente,
// então este teste roda contra o Postgres real (pula sem
// TEST_DATABASE_URL) — só o SecurityProvider externo é fake.

type fakeProvider struct {
	name string
	err  error
}

func (f *fakeProvider) Name() string                           { return f.name }
func (f *fakeProvider) TestConnection(_ context.Context) error { return f.err }
func (f *fakeProvider) AnalyzeTarget(_ context.Context, _ string) (*domain.SecCheckResult, error) {
	return &domain.SecCheckResult{Success: true}, nil
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live secops transport test")
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

type fakeFlags struct{ enabled bool }

func (f fakeFlags) IsEnabled(_ context.Context, _ string, _ bool) (bool, error) {
	return f.enabled, nil
}
func (f fakeFlags) List(_ context.Context) ([]configflags.Flag, error) { return nil, nil }
func (f fakeFlags) Set(_ context.Context, key string, enabled bool, _ string) (configflags.Flag, error) {
	return configflags.Flag{Key: key, Enabled: enabled}, nil
}

func newTestService(pool *pgxpool.Pool, flags configflags.Store) *application.Service {
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	integrationsSvc := integrations.NewService(integrationsInfra.NewPostgresRepository(pool))
	providers := map[string]domain.SecurityProvider{"virustotal": &fakeProvider{name: "virustotal"}}
	return application.NewService(pool, jobsRepo, outboxWriter, providers, integrationsSvc, nil, flags, testLogger())
}

func decodeEnvelope[T any](t *testing.T, body []byte) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response envelope: %v, body=%s", err, body)
	}
	return env.Data
}

func TestTestVirusTotal_CreatesJobAndReturns202(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, nil), testLogger())

	r := httptest.NewRequest(http.MethodPost, "/integrations/secops/virustotal/test", nil)
	rec := httptest.NewRecorder()

	h.TestVirusTotal(rec, r)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeEnvelope[testJobResponse](t, rec.Body.Bytes())
	if got.JobID == "" {
		t.Error("expected a non-empty job_id")
	}
	if got.Status != string(jobs.StatusQueued) {
		t.Errorf("Status = %q, want %q", got.Status, jobs.StatusQueued)
	}
}

func TestTestVirusTotal_FeatureDisabledReturns503(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: false}), testLogger())

	r := httptest.NewRequest(http.MethodPost, "/integrations/secops/virustotal/test", nil)
	rec := httptest.NewRecorder()

	h.TestVirusTotal(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (FEATURE_DISABLED)", rec.Code)
	}
}
