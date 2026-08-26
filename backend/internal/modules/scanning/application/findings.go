// Arquivo findings.go: leitura de achados/pacotes já persistidos —
// ListFindings, ListPackages, ListRecentFindings e o histórico
// agrupado por fingerprint entre scans de um mesmo projeto
// (ListProjectFindingsHistory). Extraído de service.go (ver nota em
// scans.go) — mesmo pacote application, mesmo *Service.
package application

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// ListFindings retorna todo achado de uma execução de scan, mais
// severo/recente primeiro — menos os que baterem com o filtro de ruído
// (Fase 13), se a feature flag NoiseFilterFlagKey estiver ligada.
func (s *Service) ListFindings(ctx context.Context, scanID uuid.UUID) ([]domain.PersistedFinding, error) {
	findings, err := s.repo.ListByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings for scan %s: %w", scanID, err)
	}
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}
	return findings, nil
}

// ListPackages retorna o inventário (Fase 11 — Syft) de uma execução de
// scan, ordem alfabética de nome. Uma lista vazia (scan sem Syft, ou Syft
// não achou nenhum pacote) não é erro — mesmo princípio de ListFindings
// devolver uma lista vazia pra um scan limpo.
func (s *Service) ListPackages(ctx context.Context, scanID uuid.UUID) ([]domain.Package, error) {
	packages, err := s.repo.ListPackagesByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list packages for scan %s: %w", scanID, err)
	}
	return packages, nil
}

// ProjectFindingHistory (Fase 12 — deduplicação por fingerprint) é UM
// achado deduplicado ENTRE re-scans do MESMO projeto — nunca dentro de um
// scan só (cada linha de scan_findings já é um achado distinto por
// natureza, ver domain.Fingerprint). Representa a pergunta "esse mesmo
// problema já apareceu antes, nesse projeto, e ainda está presente?" —
// nunca respondida antes desta fase (só dava pra ver achados por scan
// individual, um de cada vez).
type ProjectFindingHistory struct {
	Fingerprint   string
	Scanner       string
	OWASPCategory string
	Severity      domain.Severity
	Description   string
	File          string
	Line          int
	// FirstSeenAt/LastSeenAt são MIN/MAX(created_at) entre toda ocorrência
	// deste fingerprint nos scans do projeto — "apareceu pela primeira vez
	// em X, ainda presente em Y" (o pedido literal do roadmap).
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	// ScanCount é quantos scans DISTINTOS deste projeto incluíram este
	// fingerprint — não quantas linhas de scan_findings (nunca deveria
	// duplicar dentro de um scan só, mas contado por scan mesmo assim,
	// nunca por linha, pra nunca inflar por acidente se algum dia
	// duplicar).
	ScanCount int
	// StillPresent indica se este fingerprint aparece no scan MAIS
	// RECENTE do projeto — a UI usa isto pra separar "ainda um problema"
	// de "já foi corrigido, só ficou no histórico".
	StillPresent bool
	// TriageStatus/TriageReason (Fase 14 — Maturidade de AppSec):
	// TriageStatus vazio ("") significa "aberto, nunca triado" — o
	// mesmo estado implícito que domain.TriageStatus documenta (não
	// existe um TriageStatusOpen persistido, ver ali). Ortogonal a
	// StillPresent: um achado pode continuar reaparecendo em todo
	// re-scan (StillPresent=true) e MESMO ASSIM estar triado — é
	// exatamente esse o propósito de "risco aceito"/"não vou corrigir",
	// ao contrário de "corrigido" (StillPresent=false), que não precisa
	// de nenhuma decisão humana pra parar de aparecer como pendente.
	TriageStatus string
	TriageReason string
	// TriageExpiresAt/TriageExpired (Fase 14, continuação — expiração de
	// triagem): TriageExpiresAt é nil quando a triagem não tem prazo (ou
	// quando TriageStatus é vazio — nunca houve triagem nenhuma pra ter
	// prazo). TriageExpired é true quando o prazo já passou — o achado
	// CONTINUA carregando TriageStatus/TriageReason (a decisão que
	// alguém tomou fica registrada, nunca é apagada só por vencer — ver
	// domain.Triage.ExpiresAt), mas volta a contar como ABERTO em
	// SecurityPosture/na ordenação abaixo, porque o prazo de revisão
	// passou e ninguém decidiu de novo.
	TriageExpiresAt *time.Time
	TriageExpired   bool
}

// ListProjectFindingsHistory agrupa por Fingerprint todo achado de TODOS
// os scans de um projeto (Fase 12) — reaproveita ListProjectScans (mesma
// consulta que já filtra por projeto) pra saber quais scan_ids pertencem
// a ele, busca os achados desses scans numa viagem só
// (repo.ListByScanIDs) e agrupa em memória: o volume de achados por
// projeto nesta plataforma nunca justificou um GROUP BY no banco pra
// isto. Uma lista vazia (projeto nunca escaneado, ou sem achado nenhum
// em nenhum scan) não é erro.
func (s *Service) ListProjectFindingsHistory(ctx context.Context, projectID uuid.UUID) ([]ProjectFindingHistory, error) {
	scans, err := s.ListProjectScans(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, nil
	}
	// scans[0] é o mais recente — ListProjectScans preserva a ordem de
	// ListRecentScans (ORDER BY created_at DESC), só filtrando por
	// projeto.
	mostRecentScanID := scans[0].JobID

	scanIDs := make([]uuid.UUID, len(scans))
	for i, sc := range scans {
		scanIDs[i] = sc.JobID
	}

	findings, err := s.repo.ListByScanIDs(ctx, scanIDs)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings history for project %s: %w", projectID, err)
	}
	// Filtro de ruído (Fase 13), aplicado ANTES do agrupamento por
	// fingerprint — um achado de ruído nunca conta pra ScanCount/
	// FirstSeenAt/LastSeenAt de nenhum grupo.
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}

	type group struct {
		entry     ProjectFindingHistory
		scansSeen map[uuid.UUID]bool
	}
	groups := make(map[string]*group)
	var order []string
	for _, f := range findings {
		g, ok := groups[f.FindingFingerprint]
		if !ok {
			g = &group{
				entry: ProjectFindingHistory{
					Fingerprint:   f.FindingFingerprint,
					Scanner:       f.Scanner,
					OWASPCategory: f.OWASPCategory,
					Severity:      f.Severity,
					Description:   f.Description,
					File:          f.File,
					Line:          f.Line,
					FirstSeenAt:   f.CreatedAt,
					LastSeenAt:    f.CreatedAt,
				},
				scansSeen: make(map[uuid.UUID]bool),
			}
			groups[f.FindingFingerprint] = g
			order = append(order, f.FindingFingerprint)
		}
		if f.CreatedAt.Before(g.entry.FirstSeenAt) {
			g.entry.FirstSeenAt = f.CreatedAt
		}
		if f.CreatedAt.After(g.entry.LastSeenAt) {
			g.entry.LastSeenAt = f.CreatedAt
		}
		if f.ScanID == mostRecentScanID {
			g.entry.StillPresent = true
		}
		g.scansSeen[f.ScanID] = true
	}

	// Triagem (Fase 14 — Maturidade de AppSec): uma consulta só, indexada
	// por fingerprint, decora todo grupo de uma vez — s.triageRepo pode
	// ser nil (mesmo princípio de tolerância a nil de s.flags) num teste
	// que nunca chamou WithTriageRepository; nesse caso todo achado
	// simplesmente aparece como "nunca triado", nunca um erro.
	var triageByFingerprint map[string]domain.Triage
	if s.triageRepo != nil {
		triageByFingerprint, err = s.triageRepo.ListTriageByProject(ctx, projectID)
		if err != nil {
			return nil, fmt.Errorf("scanning: list triage for project %s: %w", projectID, err)
		}
	}

	now := time.Now()
	out := make([]ProjectFindingHistory, 0, len(order))
	for _, fp := range order {
		g := groups[fp]
		g.entry.ScanCount = len(g.scansSeen)
		if t, ok := triageByFingerprint[fp]; ok {
			g.entry.TriageStatus = string(t.Status)
			g.entry.TriageReason = t.Reason
			g.entry.TriageExpiresAt = t.ExpiresAt
			g.entry.TriageExpired = t.Expired(now)
		}
		out = append(out, g.entry)
	}

	// Precisa de atenção AGORA (ainda presente E [nunca triado OU
	// triagem vencida]) primeiro; depois o que já foi triado e continua
	// dentro do prazo (alguém já decidiu o que fazer, não é mais um item
	// pendente de decisão); depois o que já saiu do scan mais recente
	// (presumido corrigido) — dentro de cada grupo, mais grave primeiro,
	// depois mais recente primeiro. Mesmo raciocínio de
	// findingSeverityOrder (postgres_repository.go), só que em memória,
	// já que este resultado nunca vem direto de uma única query SQL.
	sort.Slice(out, func(i, j int) bool {
		bucket := func(h ProjectFindingHistory) int {
			switch {
			case h.StillPresent && (h.TriageStatus == "" || h.TriageExpired):
				return 0
			case h.StillPresent:
				return 1
			default:
				return 2
			}
		}
		bi, bj := bucket(out[i]), bucket(out[j])
		if bi != bj {
			return bi < bj
		}
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out, nil
}

// severityRank dá a mesma ordem "mais grave primeiro" que
// findingSeverityOrder já usa em SQL (postgres_repository.go) — reescrita
// aqui em Go porque ListProjectFindingsHistory ordena em memória, não via
// ORDER BY.
func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 0
	case domain.SeverityHigh:
		return 1
	case domain.SeverityMedium:
		return 2
	default:
		return 3
	}
}

// ListRecentFindings retorna UMA PÁGINA dos achados mais graves/recentes
// entre TODAS as execuções de scan — a Fase 9 (UI no frontend) usa isto
// pra listar achados sem exigir que quem chama já saiba um scan_id de
// antemão (diferente de ListFindings, escopado a um scan só).
//
// Fase 14 (Maturidade de AppSec) trocou o antigo "limit sem OFFSET, teto
// fixo de 200, o resto simplesmente nunca aparece" por paginação de
// verdade — reaproveita o mesmo contrato pagination.Params/Meta que o
// resto da plataforma já usa (ex.: users.List), em vez de uma segunda
// convenção "limit"/"maxRecentFindings" só deste módulo.
// pagination.AbsoluteMaxPageSize (200) preserva o mesmo teto por página
// que já existia — só que agora dá pra pedir a PRÓXIMA página em vez de
// nunca ver o que passou dele.
func (s *Service) ListRecentFindings(ctx context.Context, page, pageSize int) ([]domain.PersistedFinding, pagination.Meta, error) {
	params := pagination.New(page, pageSize, pagination.AbsoluteMaxPageSize)

	findings, total, err := s.repo.ListRecentPage(ctx, params.Offset(), params.Limit())
	if err != nil {
		return nil, pagination.Meta{}, fmt.Errorf("scanning: list recent findings: %w", err)
	}
	// Filtro de ruído (Fase 13) aplicado DEPOIS da paginação — um achado
	// removido aqui pode deixar a página com menos linhas do que
	// PageSize mesmo havendo mais achados não-ruído noutra página; aceito
	// como o mesmo tipo de trade-off que qualquer filtro pós-consulta já
	// tem nesta plataforma (nunca justificou mover o filtro pro SQL só
	// por isso — configurável em runtime via feature flag, não vale a
	// complexidade de um WHERE dinâmico por padrão de caminho). Meta
	// continua refletindo o total ANTES do filtro de ruído — TotalPages
	// calculado sobre um total que o filtro pode reduzir na prática é uma
	// pequena imprecisão aceita pelo mesmo motivo.
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}
	return findings, pagination.NewMeta(params, total), nil
}
