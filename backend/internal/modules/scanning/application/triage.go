// Arquivo triage.go (Fase 14 — Maturidade de AppSec,
// docs/roadmap-secops-orchestrator.md): TriageFinding/UntriageFinding —
// o que faltava pra esta plataforma sair de "só acha vulnerabilidade" pra
// "gerencia o ciclo de vida dela", o mesmo modelo que GitHub Advanced
// Security/Snyk/GitLab Secure já usam (achado aberto -> falso
// positivo/não vou corrigir/risco aceito -> opcionalmente reaberto).
package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
)

// maxTriageReasonLength: uma justificativa livre, mas não ilimitada — o
// mesmo espírito de limites de campo de texto já aplicados noutro lugar
// da plataforma, evita um body absurdamente grande virar uma linha de
// auditoria/banco do mesmo tamanho sem necessidade real.
const maxTriageReasonLength = 2000

// TriageFinding registra (ou substitui) a decisão de triagem de UM
// fingerprint dentro de UM projeto — ver domain.Triage sobre por que o
// escopo é (project_id, fingerprint), não um achado/scan individual.
// reason é obrigatório: uma supressão sem motivo registrado é
// exatamente o tipo de decisão que uma auditoria de segurança depois
// cobra explicação, e a resposta não pode ser "não sabemos".
func (s *Service) TriageFinding(ctx context.Context, projectID uuid.UUID, fingerprint string, status domain.TriageStatus, reason string, actorUserID *uuid.UUID) error {
	if s.triageRepo == nil {
		return apperrors.Internal(fmt.Errorf("scanning: triage repository not configured"))
	}
	if !domain.ValidTriageStatus(status) {
		return apperrors.BadRequest(fmt.Sprintf("invalid triage status %q — expected false_positive, wont_fix or risk_accepted", status))
	}
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return apperrors.BadRequest("fingerprint is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return apperrors.BadRequest("reason is required to triage a finding — record why, for whoever audits this decision later")
	}
	if len(reason) > maxTriageReasonLength {
		return apperrors.BadRequest(fmt.Sprintf("reason must be at most %d characters", maxTriageReasonLength))
	}

	// GetProject antes de gravar: um fingerprint triado num projeto que
	// não existe (ID errado, ou já foi de outro ambiente) seria uma
	// gravação silenciosamente inútil — scanning_finding_triage não tem
	// FOREIGN KEY pra scanning_projects (mesmo desacoplamento entre
	// tabelas do resto do módulo), então o banco não pegaria isso
	// sozinho.
	if _, err := s.repo.GetProject(ctx, projectID); err != nil {
		return err
	}

	if err := s.triageRepo.UpsertTriage(ctx, domain.Triage{
		ProjectID:   projectID,
		Fingerprint: fingerprint,
		Status:      status,
		Reason:      reason,
		ActorUserID: actorUserID,
	}); err != nil {
		return fmt.Errorf("scanning: triage finding: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:       actorUserID,
			Action:       audit.ActionFindingTriaged,
			ResourceType: "scanning_finding_triage",
			ResourceID:   fmt.Sprintf("%s/%s", projectID, fingerprint),
			Metadata:     map[string]any{"project_id": projectID.String(), "fingerprint": fingerprint, "status": string(status), "reason": reason},
		})
	}
	return nil
}

// UntriageFinding "reabre" um achado — apaga a decisão de triagem
// registrada, se alguma. Idempotente: chamar de novo num fingerprint já
// aberto (ou nunca triado) não é erro, mesmo princípio de
// domain.TriageRepository.DeleteTriage.
func (s *Service) UntriageFinding(ctx context.Context, projectID uuid.UUID, fingerprint string, actorUserID *uuid.UUID) error {
	if s.triageRepo == nil {
		return apperrors.Internal(fmt.Errorf("scanning: triage repository not configured"))
	}
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return apperrors.BadRequest("fingerprint is required")
	}

	if err := s.triageRepo.DeleteTriage(ctx, projectID, fingerprint); err != nil {
		return fmt.Errorf("scanning: untriage finding: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:       actorUserID,
			Action:       audit.ActionFindingUntriaged,
			ResourceType: "scanning_finding_triage",
			ResourceID:   fmt.Sprintf("%s/%s", projectID, fingerprint),
			Metadata:     map[string]any{"project_id": projectID.String(), "fingerprint": fingerprint},
		})
	}
	return nil
}
