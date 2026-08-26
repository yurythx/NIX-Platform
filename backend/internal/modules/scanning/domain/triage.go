package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TriageStatus é o desfecho que um humano atribui a um achado quando
// decide não corrigi-lo (ainda) — os três estados que GitHub Advanced
// Security/Snyk/GitLab Secure já usam, não uma taxonomia própria (Fase
// 14, docs/roadmap-secops-orchestrator.md, "Maturidade de AppSec"). Um
// achado sem nenhuma TriageStatus é implicitamente "aberto" — não existe
// um TriageStatusOpen: reabrir é APAGAR a linha de scanning_finding_triage
// (ver Repository.DeleteTriage), não gravar um quarto status.
type TriageStatus string

const (
	// TriageFalsePositive: a ferramenta errou — isto não é uma
	// vulnerabilidade de verdade neste contexto.
	TriageFalsePositive TriageStatus = "false_positive"
	// TriageWontFix: é real, mas a decisão do time é não corrigir (ex.:
	// código legado prestes a ser removido, esforço desproporcional ao
	// risco).
	TriageWontFix TriageStatus = "wont_fix"
	// TriageRiskAccepted: é real e vai ficar assim por ora — risco
	// avaliado e aceito conscientemente, geralmente com uma mitigação
	// compensatória documentada em Reason.
	TriageRiskAccepted TriageStatus = "risk_accepted"
)

// ValidTriageStatus reporta se s é um dos três valores reconhecidos —
// usado pela camada application antes de gravar, pra nunca persistir um
// status que a CHECK constraint da migration 000023 rejeitaria só depois
// da viagem ao banco.
func ValidTriageStatus(s TriageStatus) bool {
	switch s {
	case TriageFalsePositive, TriageWontFix, TriageRiskAccepted:
		return true
	default:
		return false
	}
}

// Triage é a decisão registrada para UM fingerprint dentro de UM projeto
// (não por achado/scan individual — ver comentário da migration 000023
// sobre por que o escopo é (project_id, fingerprint)). Reason nunca é
// vazio numa Triage persistida — a camada application rejeita a
// requisição antes de chegar aqui se vier em branco.
type Triage struct {
	ProjectID   uuid.UUID
	Fingerprint string
	Status      TriageStatus
	Reason      string
	ActorUserID *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TriageRepository persiste e consulta as decisões de triagem de um
// projeto. Interface própria, separada de Repository (não mais um método
// nela) — o volume de assinaturas que Repository já tem (achados,
// pacotes, progresso de scanner, projetos) não deveria crescer toda vez
// que um conceito novo, mesmo que pequeno, é adicionado; TriageRepository
// pode ser implementada por um tipo diferente do resto sem forçar todo
// fake de teste do domain.Repository a ganhar métodos que não usa.
type TriageRepository interface {
	// UpsertTriage grava (ou substitui, se já existia) a decisão de
	// triagem de um fingerprint dentro de um projeto — reaplicar a mesma
	// ação (ex.: trocar de "risk_accepted" pra "wont_fix" mais tarde)
	// atualiza a linha existente, nunca acumula histórico de decisões
	// antigas.
	UpsertTriage(ctx context.Context, t Triage) error

	// DeleteTriage remove a decisão de triagem de um fingerprint —
	// "reabrir": o achado volta a contar como aberto/still_present no
	// próximo ListProjectFindingsHistory. Idempotente: apagar um
	// fingerprint sem triagem nenhuma não é erro.
	DeleteTriage(ctx context.Context, projectID uuid.UUID, fingerprint string) error

	// ListTriageByProject retorna toda triagem registrada num projeto,
	// indexada por fingerprint — usado por
	// application.Service.ListProjectFindingsHistory pra decorar cada
	// grupo com sua triagem (se alguma), numa única consulta em vez de
	// uma por fingerprint.
	ListTriageByProject(ctx context.Context, projectID uuid.UUID) (map[string]Triage, error)
}
