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

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/infrastructure"
	integrations "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// application.Service é transacional de verdade (job + evento de outbox
// gravados atomicamente — ver CreateTestJob) e recebe um *pgxpool.Pool
// diretamente, não uma interface abstrata; por isso este teste, como os
// já existentes de application/service_test.go, roda contra o Postgres
// real usado por todo este backend, pulando se TEST_DATABASE_URL não
// estiver definida — não é possível testar este handler com um fake puro
// sem reescrever o Service para aceitar um repositório abstrato, o que
// esta auditoria não pediu. Só a chamada HTTP externa ao Diário Oficial
// em si é fake (domain.Client), igual ao fakeClient da suíte de
// application.

type fakeClient struct {
	result *domain.CheckResult
	err    error
}

func (f *fakeClient) Check(_ context.Context) (*domain.CheckResult, error) {
	return f.result, f.err
}

func (f *fakeClient) Search(_ context.Context, _ domain.SearchQuery) (*domain.SearchResult, error) {
	return &domain.SearchResult{}, nil
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live diario_oficial transport test")
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

// fakeFlags controla só a flag que CreateTestJob confere — um Store real
// seria overkill pra decidir "habilitada" vs "desabilitada" neste teste.
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
	repo := infrastructure.NewPostgresRepository(pool)
	return application.NewService(pool, jobsRepo, outboxWriter, &fakeClient{}, repo, integrationsSvc, nil, flags, testLogger())
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

func TestTestDiarioOficial_CreatesJobAndReturns202(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, nil), testLogger()) // flags nil == sempre permitido

	r := httptest.NewRequest(http.MethodPost, "/integrations/diario-oficial/test", nil)
	rec := httptest.NewRecorder()

	h.TestDiarioOficial(rec, r)

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

func TestTestDiarioOficial_FeatureDisabledReturns503(t *testing.T) {
	pool := testPool(t)
	h := NewHandlers(newTestService(pool, fakeFlags{enabled: false}), testLogger())

	r := httptest.NewRequest(http.MethodPost, "/integrations/diario-oficial/test", nil)
	rec := httptest.NewRecorder()

	h.TestDiarioOficial(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (FEATURE_DISABLED)", rec.Code)
	}
}
