// Testes de health.go — CheckHealth só toca s.client (nenhum banco), por
// isso o Service é construído por struct literal direto (mesmo pacote —
// campos não exportados acessíveis aqui), não via NewService/newService:
// não precisa de TEST_DATABASE_URL, sempre roda.
package application

import (
	"context"
	"errors"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
)

func TestCheckHealth_Success_ReportsHealthy(t *testing.T) {
	svc := &Service{client: &fakeClient{result: &domain.CheckResult{StatusCode: 200, Summary: "responded with HTTP 200"}}}

	health := svc.CheckHealth(context.Background())

	if !health.Healthy {
		t.Errorf("Healthy = false, want true")
	}
	if health.Source != "djen" {
		t.Errorf("Source = %q, want djen", health.Source)
	}
	if health.Message != "responded with HTTP 200" {
		t.Errorf("Message = %q, want the Check summary", health.Message)
	}
	if health.CheckedAt.IsZero() {
		t.Error("CheckedAt is zero, want it set")
	}
}

func TestCheckHealth_Failure_ReportsUnhealthyWithMessage(t *testing.T) {
	svc := &Service{client: &fakeClient{err: errors.New("connection refused")}}

	health := svc.CheckHealth(context.Background())

	if health.Healthy {
		t.Error("Healthy = true, want false")
	}
	if health.Message != "connection refused" {
		t.Errorf("Message = %q, want the error text", health.Message)
	}
}
