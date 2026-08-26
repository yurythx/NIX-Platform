// Testes de health.go (revisão de exibição de resultados — "quero ter
// uma tela onde mostra a saúde das ferramentas... antes de iniciá-las").
package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// fakeHealthCheckScanner implementa domain.CodeScanner + domain.HealthChecker
// — usado só pra testar CheckScannersHealth sem precisar de um sidecar
// de verdade no ar.
type fakeHealthCheckScanner struct {
	name string
	err  error
	// delay simula um sidecar lento — usado por
	// TestCheckScannersHealth_TimesOutSlowScanner.
	delay time.Duration
}

func (f *fakeHealthCheckScanner) Name() string { return f.name }

func (f *fakeHealthCheckScanner) Execute(context.Context, string) ([]domain.Finding, error) {
	panic("Execute should not be called by CheckScannersHealth")
}

func (f *fakeHealthCheckScanner) HealthCheck(ctx context.Context) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

var _ domain.HealthChecker = (*fakeHealthCheckScanner)(nil)

func TestCheckScannersHealth_ReportsHealthyAndUnhealthyScanners(t *testing.T) {
	pool := testPool(t)
	healthy := &fakeHealthCheckScanner{name: "healthy-scanner"}
	unhealthy := &fakeHealthCheckScanner{name: "unhealthy-scanner", err: errors.New("sidecar unreachable")}
	svc := newService(pool, healthy, unhealthy)

	results := svc.CheckScannersHealth(context.Background())

	byName := make(map[string]ScannerHealth, len(results))
	for _, r := range results {
		byName[r.Scanner] = r
	}

	h, ok := byName["healthy-scanner"]
	if !ok || !h.Healthy || h.Message != "" {
		t.Errorf("healthy-scanner = %+v, want Healthy=true Message=\"\"", h)
	}
	u, ok := byName["unhealthy-scanner"]
	if !ok || u.Healthy || u.Message != "sidecar unreachable" {
		t.Errorf("unhealthy-scanner = %+v, want Healthy=false Message=%q", u, "sidecar unreachable")
	}
}

func TestCheckScannersHealth_ResultsSortedByScannerName(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool,
		&fakeHealthCheckScanner{name: "zzz-scanner"},
		&fakeHealthCheckScanner{name: "aaa-scanner"},
		&fakeHealthCheckScanner{name: "mmm-scanner"},
	)

	results := svc.CheckScannersHealth(context.Background())

	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	for i := 1; i < len(results); i++ {
		if results[i-1].Scanner > results[i].Scanner {
			t.Errorf("results not sorted: %q came before %q", results[i-1].Scanner, results[i].Scanner)
		}
	}
}

// TestCheckScannersHealth_ScannerWithoutHealthChecker_IsSkipped prova
// que um domain.CodeScanner registrado que NÃO implementa
// domain.HealthChecker (nenhum dos 6 reais hoje, mas a interface é
// opcional de propósito) simplesmente não aparece no resultado, em vez
// de um erro ou um item incompleto.
func TestCheckScannersHealth_ScannerWithoutHealthChecker_IsSkipped(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "no-health-check-support"})

	results := svc.CheckScannersHealth(context.Background())

	for _, r := range results {
		if r.Scanner == "no-health-check-support" {
			t.Error("expected the scanner without HealthChecker support to be skipped, but it appeared in the results")
		}
	}
}

func TestCheckScannersHealth_TimesOutSlowScanner(t *testing.T) {
	pool := testPool(t)
	// delay bem maior que healthCheckTimeout — prova que a checagem em
	// si não trava esperando um sidecar travado, só reporta indisponível
	// depois do teto.
	slow := &fakeHealthCheckScanner{name: "slow-scanner", delay: healthCheckTimeout + 10*time.Second}
	svc := newService(pool, slow)

	start := time.Now()
	results := svc.CheckScannersHealth(context.Background())
	elapsed := time.Since(start)

	if elapsed > healthCheckTimeout+2*time.Second {
		t.Errorf("CheckScannersHealth took %v, want it to time out around %v, not wait for the slow scanner", elapsed, healthCheckTimeout)
	}
	if len(results) != 1 || results[0].Healthy {
		t.Errorf("results = %+v, want exactly one unhealthy result (timed out)", results)
	}
}
