// Testes de triage.go (Fase 14 — Maturidade de AppSec). Como todo teste
// de repositório real deste módulo (ver nota em service_test.go),
// exercitam infrastructure.PostgresRepository por trás de newService(pool)
// — nenhum fake aqui, a tabela scanning_finding_triage/migration 000023
// é exercitada de verdade.
package application

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

// newTriageService constrói um Service com a triagem de verdade
// configurada (ao contrário de newService/newServiceWithFlags, usados
// pelo resto deste pacote) e já cria um projeto novo pra testar contra —
// TriageFinding exige um projeto existente (ver TestTriageFinding_UnknownProject_ReturnsNotFound).
func newTriageService(t *testing.T, scanners ...domain.CodeScanner) (*Service, uuid.UUID) {
	t.Helper()
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newService(pool, scanners...).WithTriageRepository(repo)

	project, err := svc.CreateProjectGit(context.Background(), "test-project-triage-"+uuid.NewString(), "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}
	return svc, project.ID
}

func TestTriageFinding_RequiresReason(t *testing.T) {
	svc, projectID := newTriageService(t)

	err := svc.TriageFinding(context.Background(), projectID, "fp-1", domain.TriageFalsePositive, "", nil)
	if err == nil {
		t.Fatal("expected an error for an empty reason")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeBadRequest {
		t.Errorf("err = %v, want a BAD_REQUEST apperrors.Error", err)
	}
}

func TestTriageFinding_RejectsUnknownStatus(t *testing.T) {
	svc, projectID := newTriageService(t)

	err := svc.TriageFinding(context.Background(), projectID, "fp-1", domain.TriageStatus("archived"), "motivo válido", nil)
	if err == nil {
		t.Fatal("expected an error for an unrecognized status")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeBadRequest {
		t.Errorf("err = %v, want a BAD_REQUEST apperrors.Error", err)
	}
}

func TestTriageFinding_UnknownProject_ReturnsNotFound(t *testing.T) {
	svc, _ := newTriageService(t)

	err := svc.TriageFinding(context.Background(), uuid.New(), "fp-1", domain.TriageWontFix, "motivo válido", nil)
	if err == nil {
		t.Fatal("expected an error for an unknown project")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeNotFound {
		t.Errorf("err = %v, want a NOT_FOUND apperrors.Error", err)
	}
}

func TestTriageFinding_WithoutTriageRepositoryConfigured_ReturnsInternalError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool) // sem .WithTriageRepository — mesmo estado que todo outro teste deste pacote já usa

	err := svc.TriageFinding(context.Background(), uuid.New(), "fp-1", domain.TriageWontFix, "motivo válido", nil)
	if err == nil {
		t.Fatal("expected an error when triageRepo is nil")
	}
}

// TestTriageFinding_AppearsInProjectFindingHistory prova o round-trip
// completo: um achado real, gravado por um re-scan de verdade, ganha
// TriageStatus/TriageReason em ListProjectFindingsHistory depois de
// TriageFinding — não só que a linha foi gravada em
// scanning_finding_triage isoladamente.
func TestTriageFinding_AppearsInProjectFindingHistory(t *testing.T) {
	finding := domain.Finding{
		ID: "CVE-2026-TRIAGE-TEST", OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Severity: domain.SeverityHigh, Description: "dependência desatualizada", File: "go.sum", Line: 3,
	}
	fingerprint := domain.Fingerprint("trivy", finding.ID, finding.File, finding.Line)

	svc, projectID := newTriageService(t, &fakeScanner{name: "trivy", findings: []domain.Finding{finding}})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateProjectScanJob(ctx, corrID, []string{"trivy"}, projectID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob: %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	history, err := svc.ListProjectFindingsHistory(ctx, projectID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory (before triage): %v", err)
	}
	var beforeStatus string
	for _, h := range history {
		if h.Fingerprint == fingerprint {
			beforeStatus = h.TriageStatus
		}
	}
	if beforeStatus != "" {
		t.Fatalf("TriageStatus before triaging = %q, want empty (open)", beforeStatus)
	}

	if err := svc.TriageFinding(ctx, projectID, fingerprint, domain.TriageRiskAccepted, "mitigado por WAF em produção", nil); err != nil {
		t.Fatalf("TriageFinding: %v", err)
	}

	history, err = svc.ListProjectFindingsHistory(ctx, projectID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory (after triage): %v", err)
	}
	var found bool
	for _, h := range history {
		if h.Fingerprint != fingerprint {
			continue
		}
		found = true
		if h.TriageStatus != string(domain.TriageRiskAccepted) {
			t.Errorf("TriageStatus = %q, want %q", h.TriageStatus, domain.TriageRiskAccepted)
		}
		if h.TriageReason != "mitigado por WAF em produção" {
			t.Errorf("TriageReason = %q, want the reason just recorded", h.TriageReason)
		}
		if !h.StillPresent {
			t.Error("StillPresent = false, want true — triaging never changes presence, only whether a human already decided what to do about it")
		}
	}
	if !found {
		t.Fatal("ListProjectFindingsHistory did not include the triaged finding")
	}

	// UntriageFinding reabre — o achado volta a "" (aberto).
	if err := svc.UntriageFinding(ctx, projectID, fingerprint, nil); err != nil {
		t.Fatalf("UntriageFinding: %v", err)
	}
	history, err = svc.ListProjectFindingsHistory(ctx, projectID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory (after untriage): %v", err)
	}
	for _, h := range history {
		if h.Fingerprint == fingerprint && h.TriageStatus != "" {
			t.Errorf("TriageStatus after UntriageFinding = %q, want empty (reopened)", h.TriageStatus)
		}
	}
}

// TestTriageFinding_ReplacesPreviousDecision prova que triar de novo o
// MESMO fingerprint substitui a decisão anterior, em vez de rejeitar ou
// acumular.
func TestTriageFinding_ReplacesPreviousDecision(t *testing.T) {
	svc, projectID := newTriageService(t)
	ctx := context.Background()

	if err := svc.TriageFinding(ctx, projectID, "fp-replace", domain.TriageFalsePositive, "motivo inicial", nil); err != nil {
		t.Fatalf("TriageFinding (first): %v", err)
	}
	if err := svc.TriageFinding(ctx, projectID, "fp-replace", domain.TriageWontFix, "motivo revisado", nil); err != nil {
		t.Fatalf("TriageFinding (second): %v", err)
	}

	triage, err := svc.triageRepo.ListTriageByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListTriageByProject: %v", err)
	}
	got, ok := triage["fp-replace"]
	if !ok {
		t.Fatal("expected a triage entry for fp-replace")
	}
	if got.Status != domain.TriageWontFix || got.Reason != "motivo revisado" {
		t.Errorf("triage = %+v, want the SECOND decision to have replaced the first entirely", got)
	}
}

func TestUntriageFinding_NeverTriaged_IsNotAnError(t *testing.T) {
	svc, projectID := newTriageService(t)

	if err := svc.UntriageFinding(context.Background(), projectID, "fp-never-triaged", nil); err != nil {
		t.Errorf("UntriageFinding on a fingerprint that was never triaged: %v, want nil (idempotent)", err)
	}
}

func TestTriageFinding_ReasonTooLong_IsRejected(t *testing.T) {
	svc, projectID := newTriageService(t)

	huge := strings.Repeat("a", maxTriageReasonLength+1)
	err := svc.TriageFinding(context.Background(), projectID, "fp-1", domain.TriageWontFix, huge, nil)
	if err == nil {
		t.Fatal("expected an error for a reason above the length limit")
	}
}
