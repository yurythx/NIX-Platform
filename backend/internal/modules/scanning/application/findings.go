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

	out := make([]ProjectFindingHistory, 0, len(order))
	for _, fp := range order {
		g := groups[fp]
		g.entry.ScanCount = len(g.scansSeen)
		out = append(out, g.entry)
	}

	// Ainda presente primeiro (o que precisa de atenção AGORA), depois
	// mais grave primeiro, depois mais recente primeiro — mesmo
	// raciocínio de findingSeverityOrder (postgres_repository.go), só que
	// em memória, já que este resultado nunca vem direto de uma única
	// query SQL.
	sort.Slice(out, func(i, j int) bool {
		if out[i].StillPresent != out[j].StillPresent {
			return out[i].StillPresent
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

// maxRecentFindings é o teto de ListRecentFindings — nenhum chamador
// consegue pedir mais que isso, nem passando um limit maior (evita uma
// consulta acidentalmente sem paginação nenhuma trazer a tabela inteira
// pro frontend de uma vez).
const maxRecentFindings = 200

// ListRecentFindings retorna os achados mais graves/recentes entre TODAS
// as execuções de scan — a Fase 9 (UI no frontend) usa isto pra listar
// achados sem exigir que quem chama já saiba um scan_id de antemão
// (diferente de ListFindings, escopado a um scan só). limit <= 0 usa um
// default razoável; limit > maxRecentFindings é truncado, nunca rejeitado
// com erro — um pedido "generoso demais" ainda é atendido, só que com o
// teto em vez do valor pedido.
func (s *Service) ListRecentFindings(ctx context.Context, limit int) ([]domain.PersistedFinding, error) {
	const defaultLimit = 50
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxRecentFindings {
		limit = maxRecentFindings
	}

	findings, err := s.repo.ListRecent(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list recent findings: %w", err)
	}
	// Filtro de ruído (Fase 13) aplicado DEPOIS do limit — um achado
	// removido aqui pode deixar a resposta com menos de `limit` linhas
	// mesmo havendo mais achados não-ruído além da janela buscada; aceito
	// como o mesmo tipo de trade-off que qualquer filtro pós-consulta já
	// tem nesta plataforma (nunca justificou mover o filtro pro SQL só
	// por isso — configurável em runtime via feature flag, não vale a
	// complexidade de um WHERE dinâmico por padrão de caminho).
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}
	return findings, nil
}
