package resilience

import (
	"errors"
	"testing"

	"github.com/sony/gobreaker/v2"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

func newTestBreaker(t *testing.T, consecutiveFailures uint32) *Breaker[string] {
	t.Helper()
	// Nomeia o breaker de forma única por teste — gobreaker registra
	// métricas Prometheus por nome, e testes rodando em paralelo (ou só
	// vários testes na mesma suíte) não podem compartilhar a série.
	return New[string](Options{
		Name:                t.Name(),
		ConsecutiveFailures: consecutiveFailures,
		MaxRequests:         1,
	})
}

func TestBreaker_ClosedStateExecutesNormally(t *testing.T) {
	b := newTestBreaker(t, 3)

	result, err := b.Execute(func() (string, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %q, want %q", result, "ok")
	}
	if b.State() != gobreaker.StateClosed {
		t.Errorf("State() = %v, want closed", b.State())
	}
}

func TestBreaker_OpensAfterConsecutiveFailuresAndFailsFast(t *testing.T) {
	const threshold = 3
	b := newTestBreaker(t, threshold)
	boom := errors.New("boom")

	calls := 0
	failingFn := func() (string, error) {
		calls++
		return "", boom
	}

	for i := 0; i < threshold; i++ {
		if _, err := b.Execute(failingFn); !errors.Is(err, boom) {
			t.Fatalf("chamada %d: err = %v, want o erro original %v (circuito ainda fechado)", i, err, boom)
		}
	}

	if b.State() != gobreaker.StateOpen {
		t.Fatalf("State() = %v, want open após %d falhas consecutivas", b.State(), threshold)
	}

	// Com o circuito aberto, fn não deve ser chamada de novo — o breaker
	// falha rápido, sem sobrecarregar o provedor que já está com problema.
	callsBefore := calls
	_, err := b.Execute(failingFn)
	if calls != callsBefore {
		t.Errorf("fn foi chamada com o circuito aberto — deveria falhar rápido sem executar fn")
	}

	appErr, ok := apperrors.As(err)
	if !ok {
		t.Fatalf("err = %v, want um *apperrors.Error", err)
	}
	if appErr.Code != "CIRCUIT_OPEN" {
		t.Errorf("appErr.Code = %q, want CIRCUIT_OPEN", appErr.Code)
	}
	if appErr.Status != 503 {
		t.Errorf("appErr.Status = %d, want 503", appErr.Status)
	}
}

func TestBreaker_SuccessResetsFailureCount(t *testing.T) {
	b := newTestBreaker(t, 3)
	boom := errors.New("boom")

	// Duas falhas (abaixo do limite de 3)...
	for i := 0; i < 2; i++ {
		_, _ = b.Execute(func() (string, error) { return "", boom })
	}
	// ...seguidas de um sucesso, que reseta a contagem de falhas
	// consecutivas — outra falha isolada depois não deveria já abrir o
	// circuito.
	if _, err := b.Execute(func() (string, error) { return "ok", nil }); err != nil {
		t.Fatalf("Execute (sucesso): %v", err)
	}
	if _, err := b.Execute(func() (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want o erro original (circuito ainda deveria estar fechado)", err)
	}
	if b.State() != gobreaker.StateClosed {
		t.Errorf("State() = %v, want closed — o sucesso no meio deveria ter resetado a sequência de falhas", b.State())
	}
}
