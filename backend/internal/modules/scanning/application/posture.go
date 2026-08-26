// Arquivo posture.go (Fase 14 — Maturidade de AppSec,
// docs/roadmap-secops-orchestrator.md): a lacuna que a análise da sessão
// apontou como mais visível pra quem gerencia segurança, não só pra
// quem corrige achado por achado — nenhum lugar da plataforma respondia
// "quantos problemas abertos existem AGORA, no total" sem abrir
// /seguranca e contar na mão. SecurityPosture é essa resposta agregada,
// pronta pro card de "postura de segurança" do dashboard.
package application

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// maxPostureProjects limita quantos projetos entram no cálculo de
// SecurityPosture — cada projeto custa uma consulta a
// ListProjectFindingsHistory (que já é ela mesma algumas consultas, ver
// seu comentário), então este método tem custo O(projetos), não O(1).
// Um teto explícito, documentado, é preferível a paginar isto de verdade
// agora: no volume de projetos que esta plataforma atende hoje (uso
// interno de um time, não um SaaS multi-tenant), 200 projetos já é uma
// escala que ninguém neste ambiente chegou perto de alcançar.
const maxPostureProjects = 200

// maxTopVulnerableProjects é quantas entradas ProjectPosture.TopVulnerable
// carrega — só o suficiente pra um card de dashboard, nunca uma listagem
// completa (isso já existe: GET /scanning/projects).
const maxTopVulnerableProjects = 5

// SecurityPosture é a contagem de achados ABERTOS (ainda presentes no
// scan mais recente de cada projeto E não triados — ver
// ProjectFindingHistory.StillPresent/TriageStatus) agregada entre TODO
// projeto persistente — nunca acumula achado de re-scans antigos (um
// COUNT(*) direto em scan_findings contaria o mesmo achado uma vez por
// scan em que apareceu), e nunca conta um achado que um humano já
// decidiu que não precisa de ação agora (triado). Escopado a projetos
// (Fase 10), não a scan avulso — mesmo escopo que ProjectFindingHistory
// já tem, pelo mesmo motivo: só um projeto tem "estado atual" pra
// resumir (ver seu comentário sobre por que a triagem também é
// escopada assim).
type SecurityPosture struct {
	OpenCritical    int
	OpenHigh        int
	OpenMedium      int
	OpenLow         int
	TriagedCount    int
	ProjectsScanned int
	TopVulnerable   []ProjectPosture
}

// ProjectPosture é a contribuição de UM projeto pro SecurityPosture
// agregado — usado pra montar TopVulnerable, ordenado pelos projetos com
// mais achado crítico/alto aberto.
type ProjectPosture struct {
	ProjectID    string
	ProjectName  string
	OpenCritical int
	OpenHigh     int
}

// SecurityPosture calcula o resumo agregado — ver o tipo acima. Uma
// falha ao carregar o histórico de UM projeto é best-effort (loga e
// pula, mesmo padrão de ListProjects/handlers.go's lastScanByProject):
// um projeto com problema não deveria impedir o card de mostrar o
// resto.
func (s *Service) SecurityPosture(ctx context.Context) (SecurityPosture, error) {
	projects, err := s.repo.ListProjects(ctx, maxPostureProjects)
	if err != nil {
		return SecurityPosture{}, fmt.Errorf("scanning: list projects for security posture: %w", err)
	}

	var posture SecurityPosture
	perProject := make([]ProjectPosture, 0, len(projects))

	for _, p := range projects {
		history, err := s.ListProjectFindingsHistory(ctx, p.ID)
		if err != nil {
			s.logger.Warn("scanning: failed to load finding history for security posture (best-effort, skipping project)",
				slog.String("project_id", p.ID.String()), slog.Any("error", err))
			continue
		}
		if len(history) == 0 {
			continue
		}
		posture.ProjectsScanned++

		pp := ProjectPosture{ProjectID: p.ID.String(), ProjectName: p.Name}
		for _, h := range history {
			if !h.StillPresent {
				continue // presumido corrigido — não conta nem como aberto, nem como triado
			}
			// Triagem VENCIDA (h.TriageExpired) conta como aberta de novo,
			// não como triada — o prazo de revisão passou e ninguém
			// decidiu de novo, mesmo raciocínio do bucket de ordenação em
			// ListProjectFindingsHistory (findings.go).
			if h.TriageStatus != "" && !h.TriageExpired {
				posture.TriagedCount++
				continue
			}
			switch h.Severity {
			case domain.SeverityCritical:
				posture.OpenCritical++
				pp.OpenCritical++
			case domain.SeverityHigh:
				posture.OpenHigh++
				pp.OpenHigh++
			case domain.SeverityMedium:
				posture.OpenMedium++
			case domain.SeverityLow:
				posture.OpenLow++
			}
		}
		if pp.OpenCritical > 0 || pp.OpenHigh > 0 {
			perProject = append(perProject, pp)
		}
	}

	sort.Slice(perProject, func(i, j int) bool {
		// Crítico pesa mais que alto — um projeto com 1 crítico entra
		// antes de um com 10 altos, mesmo raciocínio de severityRank no
		// resto do módulo (crítico é qualitativamente mais urgente, não
		// só "mais um ponto na soma").
		wi := perProject[i].OpenCritical*1000 + perProject[i].OpenHigh
		wj := perProject[j].OpenCritical*1000 + perProject[j].OpenHigh
		return wi > wj
	})
	if len(perProject) > maxTopVulnerableProjects {
		perProject = perProject[:maxTopVulnerableProjects]
	}
	posture.TopVulnerable = perProject

	return posture, nil
}

// maxPostureHistoryDays limita PostureHistory pelo mesmo motivo que todo
// outro teto desta plataforma (ex.: pagination.AbsoluteMaxPageSize) —
// evita que um `days` absurdamente grande vire uma consulta sem limite
// nenhum; um ano de série temporal diária já é mais do que qualquer
// gráfico de tendência precisa mostrar de uma vez.
const maxPostureHistoryDays = 366

// SnapshotSecurityPosture calcula SecurityPosture(ctx) e grava o
// resultado como o snapshot do dia — chamado periodicamente pelo worker
// (ver internal/modules/scanning/worker's PostureSnapshotLoop), nunca
// por uma requisição HTTP direta: capturar a série temporal é
// responsabilidade de um processo de fundo, não de quem só quer LER a
// postura atual (GET /scanning/posture continua chamando SecurityPosture
// direto, sem gravar nada).
func (s *Service) SnapshotSecurityPosture(ctx context.Context) error {
	if s.postureRepo == nil {
		return apperrors.Internal(fmt.Errorf("scanning: posture repository not configured"))
	}
	posture, err := s.SecurityPosture(ctx)
	if err != nil {
		return err
	}
	snapshot := domain.PostureSnapshot{
		Date:            time.Now(),
		OpenCritical:    posture.OpenCritical,
		OpenHigh:        posture.OpenHigh,
		OpenMedium:      posture.OpenMedium,
		OpenLow:         posture.OpenLow,
		TriagedCount:    posture.TriagedCount,
		ProjectsScanned: posture.ProjectsScanned,
	}
	if err := s.postureRepo.SaveSnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("scanning: snapshot security posture: %w", err)
	}
	return nil
}

// PostureHistory retorna a série temporal de PostureSnapshot dos últimos
// `days` dias (default 30 se <= 0, teto em maxPostureHistoryDays) —
// alimenta o gráfico de tendência do dashboard.
func (s *Service) PostureHistory(ctx context.Context, days int) ([]domain.PostureSnapshot, error) {
	if s.postureRepo == nil {
		return nil, apperrors.Internal(fmt.Errorf("scanning: posture repository not configured"))
	}
	const defaultDays = 30
	if days <= 0 {
		days = defaultDays
	}
	if days > maxPostureHistoryDays {
		days = maxPostureHistoryDays
	}
	snapshots, err := s.postureRepo.ListSnapshots(ctx, days)
	if err != nil {
		return nil, fmt.Errorf("scanning: list posture history: %w", err)
	}
	return snapshots, nil
}
