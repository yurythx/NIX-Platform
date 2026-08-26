package transport

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// ToolResponse são os dados da ferramenta que encontrou um achado —
// pedido do usuário ("quero que esse detalhe tenha os dados da
// ferramenta"): o nome de exibição (não o slug interno de Scanner, ex.
// "SonarQube" em vez de "sonarqube") e, quando dá pra montar, um link
// direto pra abrir ESSE achado na própria ferramenta (ver toolLink).
type ToolResponse struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

var toolDisplayNames = map[string]string{
	"trivy":     "Trivy",
	"gitleaks":  "Gitleaks",
	"syft":      "Syft",
	"semgrep":   "Semgrep",
	"sonarqube": "SonarQube",
	"zap":       "OWASP ZAP",
}

func toolDisplayName(scanner string) string {
	if name, ok := toolDisplayNames[scanner]; ok {
		return name
	}
	return scanner
}

// toolLink monta, quando possível, um link pra abrir o achado (ou pelo
// menos a regra/CVE por trás dele) na própria ferramenta que encontrou:
//   - sonarqube: a lista de issues do projeto, já filtrada por essa
//     regra — precisa de sonarQubePublicURL configurado
//     (SCANNING_SONARQUBE_PUBLIC_URL, o endereço que o NAVEGADOR
//     consegue abrir, diferente do endereço interno que o worker usa),
//     senão fica vazio — nunca um link quebrado. A project key é
//     recalculada por domain.SonarProjectKey a partir do alvo salvo no
//     achado — a MESMA derivação que o scanner usou pra gravar lá,
//     nunca precisa ser persistida à parte.
//   - trivy: quando o ID do achado é um CVE, a página pública da NVD.
//   - semgrep: a regra no Semgrep Registry (as regras do ruleset
//     default, p/owasp-top-ten, são todas públicas lá).
//   - zap: sem achado individual (o ID do alerta não é estável o
//     bastante entre versões pra montar um link direto por achado),
//     aponta pro índice de alertas do próprio projeto ZAP.
func toolLink(scanner, findingID, target, sonarQubePublicURL string) string {
	switch scanner {
	case "sonarqube":
		if sonarQubePublicURL == "" || target == "" {
			return ""
		}
		projectKey := domain.SonarProjectKey(target)
		return fmt.Sprintf("%s/project/issues?id=%s&rules=%s&resolved=false",
			strings.TrimRight(sonarQubePublicURL, "/"), url.QueryEscape(projectKey), url.QueryEscape(findingID))
	case "trivy":
		if strings.HasPrefix(findingID, "CVE-") {
			return "https://nvd.nist.gov/vuln/detail/" + findingID
		}
		return ""
	case "semgrep":
		if findingID == "" {
			return ""
		}
		return "https://semgrep.dev/r/" + findingID
	case "zap":
		return "https://www.zaproxy.org/docs/alerts/"
	default:
		return ""
	}
}

// FindingResponse é o formato público de um achado persistido — mesmo
// padrão de integrations/transport/dto.go: o domain.PersistedFinding
// nunca é serializado direto (seus campos não têm tag json, então
// sairiam em PascalCase, inconsistente com o resto da API, que é sempre
// snake_case).
type FindingResponse struct {
	ID            string `json:"id"`
	ScanID        string `json:"scan_id"`
	Scanner       string `json:"scanner"`
	Target        string `json:"target"`
	FindingID     string `json:"finding_id"`
	OWASPCategory string `json:"owasp_category"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	// Snippet (Fase 12) vem vazio pra achados de antes desta fase, ou
	// pra um achado sem File/Line específico (ex.: uma vulnerabilidade
	// de dependência do Trivy, ou o próprio Gitleaks, que grava só o
	// match mascarado — nunca linhas reais do arquivo, ver
	// gitleaks_scanner.go) — nunca tratado como erro pelo cliente, só
	// "sem trecho disponível".
	Snippet     string       `json:"snippet,omitempty"`
	Fingerprint string       `json:"fingerprint"`
	CreatedAt   time.Time    `json:"created_at"`
	Tool        ToolResponse `json:"tool"`
}

func toFindingResponse(f domain.PersistedFinding, sonarQubePublicURL string) FindingResponse {
	return FindingResponse{
		ID:            f.RecordID.String(),
		ScanID:        f.ScanID.String(),
		Scanner:       f.Scanner,
		Target:        f.Target,
		FindingID:     f.Finding.ID,
		OWASPCategory: f.OWASPCategory,
		Severity:      string(f.Severity),
		Description:   f.Description,
		File:          f.File,
		Line:          f.Line,
		Snippet:       f.Snippet,
		Fingerprint:   f.FindingFingerprint,
		CreatedAt:     f.CreatedAt,
		Tool: ToolResponse{
			Name: toolDisplayName(f.Scanner),
			URL:  toolLink(f.Scanner, f.Finding.ID, f.Target, sonarQubePublicURL),
		},
	}
}

func toFindingResponses(list []domain.PersistedFinding, sonarQubePublicURL string) []FindingResponse {
	out := make([]FindingResponse, 0, len(list))
	for _, f := range list {
		out = append(out, toFindingResponse(f, sonarQubePublicURL))
	}
	return out
}

// PackageResponse é o formato público de um pacote do inventário (Fase 11
// — Syft) — mesmo raciocínio de FindingResponse, snake_case explícito em
// vez de serializar domain.Package direto.
type PackageResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	License string `json:"license"`
}

func toPackageResponses(list []domain.Package) []PackageResponse {
	out := make([]PackageResponse, 0, len(list))
	for _, p := range list {
		out = append(out, PackageResponse{Name: p.Name, Version: p.Version, Type: p.Type, License: p.License})
	}
	return out
}

// ScannerFailureResponse é o formato público de domain.ScannerFailure,
// com Hint computado aqui (camada de apresentação) — o texto de "como
// corrigir" nunca fica persistido, só é derivado de Code/Message/Scanner
// na hora de montar a resposta HTTP (ver remediationHint), pra poder
// melhorar a sugestão sem precisar reprocessar nenhum job antigo.
type ScannerFailureResponse struct {
	Scanner string `json:"scanner"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

func toScannerFailureResponses(list []domain.ScannerFailure) []ScannerFailureResponse {
	out := make([]ScannerFailureResponse, 0, len(list))
	for _, f := range list {
		out = append(out, ScannerFailureResponse{
			Scanner: f.Scanner,
			Code:    f.Code,
			Message: f.Message,
			Hint:    remediationHint(f),
		})
	}
	return out
}

// remediationHint traduz uma falha de scanner numa sugestão de correção
// acionável — o "como corrigir" que o usuário pediu explicitamente, ao
// lado de "qual ferramenta achou o erro" (Scanner) e "que tipo de erro"
// (Code), que domain.ScannerFailure já carrega sem precisar de nenhum
// texto adicional aqui. Verifica primeiro por trechos conhecidos da
// MENSAGEM — as causas mais comuns já vistas em produção neste ambiente
// (git clone falhando contra repositório privado/inexistente, ZAP sem
// nenhum host na allowlist) — caindo pra uma sugestão só pelo Code
// quando a mensagem não bate com nenhum desses casos conhecidos: nunca
// fica sem hint nenhum, mesmo para um erro nunca visto antes.
func remediationHint(f domain.ScannerFailure) string {
	msg := strings.ToLower(f.Message)

	switch {
	case strings.Contains(msg, "could not read username") || strings.Contains(msg, "authentication failed") || strings.Contains(msg, "permission denied"):
		return "O repositório parece exigir autenticação (privado, ou credencial expirada/errada). Use um repositório público, ou configure acesso autenticado antes de disparar o scan — hoje o worker só clona via HTTPS anônimo."
	case strings.Contains(msg, "repository") && strings.Contains(msg, "not found"):
		return "O repositório informado não existe, ou a URL está errada. Confira o endereço https:// e, se usou um branch/tag depois de \"#\", confirme que ele existe."
	case strings.Contains(msg, "no hosts are allowlisted") || strings.Contains(msg, "allowlist"):
		return "O ZAP só ataca hosts explicitamente autorizados. Adicione o host à variável de ambiente SCANNING_ZAP_ALLOWED_HOSTS do backend-worker e dispare o scan de novo."
	case strings.Contains(msg, "resolves to a private/internal address") || strings.Contains(msg, "private/internal"):
		return "O host do alvo resolve para um endereço privado/interno — bloqueado por proteção contra SSRF. Use um alvo público, alcançável pela internet."
	case strings.Contains(msg, "git clone failed"):
		return "Falha ao clonar o alvo via git. Confira se a URL é https://, se o repositório é público, e se o branch/tag depois de \"#\" (se algum foi passado) existe."
	case strings.Contains(msg, "target must be an https") || strings.Contains(msg, "not a valid branch/tag"):
		return "O alvo enviado não está no formato esperado. Para Trivy/Semgrep/SonarQube, uma URL https:// de um repositório git (opcionalmente com #branch); para o ZAP, a URL http(s) de um serviço já rodando."
	}

	switch f.Code {
	case string(apperrors.CodeValidation):
		return "O alvo enviado não passou na validação. Confira o formato (URL https:// para Trivy/Semgrep/SonarQube, URL http(s) de um serviço rodando para o ZAP)."
	case string(apperrors.CodeDependencyUnavailable):
		return "A ferramenta, ou uma dependência dela (git, o binário do scanner, a API do SonarQube/ZAP), não respondeu como esperado. Veja a mensagem acima para o motivo específico; se persistir, verifique se o serviço está no ar."
	case string(apperrors.CodeNotFound):
		return "O scanner pedido não está registrado neste ambiente — confira o nome (trivy, semgrep, sonarqube, zap)."
	default:
		return "Erro inesperado nesta ferramenta. Consulte a mensagem acima; se persistir, verifique os logs do backend-worker."
	}
}

// ScannerRunResponse é o formato público de domain.ScannerRun — o
// progresso de UM scanner dentro de um job, incluindo enquanto o job
// ainda está "processing" (Status == "running"). DurationMs só aparece
// depois que o scanner termina (FinishedAt != nil) — computado aqui, não
// persistido, pra nunca poder divergir de FinishedAt-StartedAt.
type ScannerRunResponse struct {
	Scanner       string     `json:"scanner"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	DurationMs    *int64     `json:"duration_ms,omitempty"`
	FindingsCount *int       `json:"findings_count,omitempty"`
	Error         string     `json:"error,omitempty"`
	// ProgressDetail: sub-progresso em texto livre (ex.: "ataque ativo:
	// 42%") — só um ProgressReportingScanner preenche isto (hoje: ZAP), e
	// só enquanto Status == "running"; omitido do JSON pros demais
	// scanners e depois que este termina (ver domain.ScannerRun.ProgressDetail).
	ProgressDetail string `json:"progress_detail,omitempty"`
}

func toScannerRunResponses(list []domain.ScannerRun) []ScannerRunResponse {
	out := make([]ScannerRunResponse, 0, len(list))
	for _, r := range list {
		resp := ScannerRunResponse{
			Scanner:        r.Scanner,
			Status:         string(r.Status),
			StartedAt:      r.StartedAt,
			FinishedAt:     r.FinishedAt,
			FindingsCount:  r.FindingsCount,
			Error:          r.Error,
			ProgressDetail: r.ProgressDetail,
		}
		if r.FinishedAt != nil {
			d := r.FinishedAt.Sub(r.StartedAt).Milliseconds()
			resp.DurationMs = &d
		}
		out = append(out, resp)
	}
	return out
}

// scanProgressPercent é uma métrica simples e honesta de "quanto falta":
// a fração de scanners PEDIDOS que já chegaram a um estado terminal
// (succeeded ou failed), não uma estimativa de tempo — os scanners rodam
// em paralelo e com durações bem diferentes entre si (um git clone
// rápido vs. um scan ZAP de minutos), então "tempo restante" seria um
// palpite; "quantos dos N já terminaram" é um fato.
func scanProgressPercent(s *application.ScanStatus) int {
	// Um job num status TERMINAL é sempre 100%, mesmo que ScannerRuns
	// esteja vazio — caso real de um job completado antes desta tabela
	// existir (scanning_scanner_runs, migration 000016): sem essa
	// checagem, um job já concluído há muito tempo apareceria travado em
	// 0% só por não ter nenhuma linha de progresso granular gravada.
	switch s.Status {
	case "completed", "failed", "dead_letter":
		return 100
	}

	total := len(s.RequestedScanners)
	if total == 0 {
		return 0
	}
	finished := 0
	for _, run := range s.ScannerRuns {
		if run.Status != domain.ScannerRunRunning {
			finished++
		}
	}
	return finished * 100 / total
}

// ScanStatusResponse é o formato público de application.ScanStatus —
// consultado pela UI depois de disparar um scan (ver
// Handlers.GetScanStatus), pra mostrar não só os achados de quem teve
// sucesso mas também, pela primeira vez, qual scanner falhou, de que
// tipo foi o erro e como corrigir — antes desta mudança essa informação
// só existia no log do worker. ScannerRuns/ProgressPercent dão
// visibilidade EM ANDAMENTO (mesmo job "processing"), não só o resumo
// final — o painel de progresso pedido pelo usuário depende disso.
type ScanStatusResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
	Target string `json:"target"`
	// ProjectID (exposto a partir da revisão de exibição de resultados —
	// docs/roadmap-secops-orchestrator.md, Fase 14) — nil pra um scan
	// avulso, o mesmo application.ScanStatus.ProjectID que já existia
	// internamente desde a Fase 10, só nunca tinha chegado à API. O
	// frontend usa isto pra saber se um achado deste scan pode ser
	// TRIADO (a triagem é escopada a projeto, ver domain.Triage) sem
	// precisar adivinhar ou fazer uma segunda consulta.
	ProjectID         *string                  `json:"project_id,omitempty"`
	RequestedScanners []string                 `json:"requested_scanners"`
	SucceededScanners []string                 `json:"succeeded_scanners"`
	FailedScanners    []ScannerFailureResponse `json:"failed_scanners"`
	ScannerRuns       []ScannerRunResponse     `json:"scanner_runs"`
	ProgressPercent   int                      `json:"progress_percent"`
	Attempts          int                      `json:"attempts"`
	CreatedAt         time.Time                `json:"created_at"`
	StartedAt         *time.Time               `json:"started_at,omitempty"`
	FinishedAt        *time.Time               `json:"finished_at,omitempty"`
}

// nonNilStrings garante que o campo nunca serializa como JSON `null` —
// um []string zero-valor (nil) do Go vira `null` em JSON por padrão, não
// `[]`, e um cliente HTTP que assume (corretamente, pelo contrato desta
// API) que um campo de lista SEMPRE é uma lista quebraria em `null`. Bug
// real: jobs de scan de antes da Fase 7 (Orquestração concorrente) têm
// um payload sem a chave "scanners" — s.RequestedScanners chegava nil
// aqui, `/seguranca` inteira parava de carregar (TypeError: Cannot read
// properties of null (reading 'join')) por causa de 3 jobs antigos de
// verdade neste ambiente.
func nonNilStrings(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func toScanStatusResponse(s *application.ScanStatus) ScanStatusResponse {
	var projectID *string
	if s.ProjectID != nil {
		id := s.ProjectID.String()
		projectID = &id
	}
	return ScanStatusResponse{
		JobID:             s.JobID.String(),
		Status:            s.Status,
		Target:            s.Target,
		ProjectID:         projectID,
		RequestedScanners: nonNilStrings(s.RequestedScanners),
		SucceededScanners: nonNilStrings(s.SucceededScanners),
		FailedScanners:    toScannerFailureResponses(s.FailedScanners),
		ScannerRuns:       toScannerRunResponses(s.ScannerRuns),
		ProgressPercent:   scanProgressPercent(s),
		Attempts:          s.Attempts,
		CreatedAt:         s.CreatedAt,
		StartedAt:         s.StartedAt,
		FinishedAt:        s.FinishedAt,
	}
}

func toScanStatusResponses(list []*application.ScanStatus) []ScanStatusResponse {
	out := make([]ScanStatusResponse, 0, len(list))
	for _, s := range list {
		out = append(out, toScanStatusResponse(s))
	}
	return out
}

// ProjectResponse é o formato público de um domain.Project (Fase 10).
// Target vem vazio pra um projeto criado por upload (nunca teve um alvo
// git) — o frontend usa SourceType, não a ausência de Target, pra decidir
// como exibir o card (ver lib/scanning conventions). LastScan é opcional:
// nil pra um projeto ainda nunca escaneado, ou quando quem monta a
// resposta não buscou o histórico (ver toProjectResponse/handlers.go's
// ListProjects) — nunca um campo que o cliente precise tratar como
// sempre presente.
type ProjectResponse struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	SourceType string              `json:"source_type"`
	Target     string              `json:"target,omitempty"`
	CreatedAt  time.Time           `json:"created_at"`
	LastScan   *ScanStatusResponse `json:"last_scan,omitempty"`
}

func toProjectResponse(p domain.Project, lastScan *application.ScanStatus) ProjectResponse {
	resp := ProjectResponse{
		ID:         p.ID.String(),
		Name:       p.Name,
		SourceType: string(p.SourceType),
		Target:     p.Target,
		CreatedAt:  p.CreatedAt,
	}
	if lastScan != nil {
		r := toScanStatusResponse(lastScan)
		resp.LastScan = &r
	}
	return resp
}

func toProjectResponses(projects []domain.Project, lastScanByProject map[string]*application.ScanStatus) []ProjectResponse {
	out := make([]ProjectResponse, 0, len(projects))
	for _, p := range projects {
		out = append(out, toProjectResponse(p, lastScanByProject[p.ID.String()]))
	}
	return out
}

// ProjectFindingHistoryResponse é o formato público de
// application.ProjectFindingHistory (Fase 12 — deduplicação por
// fingerprint) — "achado X apareceu pela primeira vez no scan de 12/08,
// ainda presente no scan de 20/08", o pedido literal do roadmap.
type ProjectFindingHistoryResponse struct {
	Fingerprint   string       `json:"fingerprint"`
	Scanner       string       `json:"scanner"`
	OWASPCategory string       `json:"owasp_category"`
	Severity      string       `json:"severity"`
	Description   string       `json:"description"`
	File          string       `json:"file"`
	Line          int          `json:"line"`
	FirstSeenAt   time.Time    `json:"first_seen_at"`
	LastSeenAt    time.Time    `json:"last_seen_at"`
	ScanCount     int          `json:"scan_count"`
	StillPresent  bool         `json:"still_present"`
	Tool          ToolResponse `json:"tool"`
	// TriageStatus (Fase 14 — Maturidade de AppSec): "" quando o achado
	// nunca foi triado (o estado "aberto" implícito, ver
	// domain.TriageStatus) — nunca omitido do JSON (sem omitempty),
	// diferente de campos opcionais como Snippet, porque "" AQUI é um
	// valor com significado próprio ("aberto"), não "ainda não
	// implementado nesta versão do achado" — o frontend distingue os
	// dois de propósito.
	TriageStatus string `json:"triage_status"`
	TriageReason string `json:"triage_reason,omitempty"`
	// TriageExpiresAt/TriageExpired (Fase 14, continuação — expiração de
	// triagem): os dois omitidos quando a triagem não tem prazo (ou não
	// existe triagem nenhuma) — omitempty em TriageExpired é seguro
	// aqui porque "sem triagem" e "triagem sem prazo, não vencida"
	// colapsam no mesmo false ausente; o frontend só olha pra este campo
	// quando TriageStatus já não é vazio.
	TriageExpiresAt *time.Time `json:"triage_expires_at,omitempty"`
	TriageExpired   bool       `json:"triage_expired,omitempty"`
}

// SecurityPostureResponse é o formato público de
// application.SecurityPosture (Fase 14 — Maturidade de AppSec) — o card
// "postura de segurança" do dashboard.
type SecurityPostureResponse struct {
	OpenCritical    int                      `json:"open_critical"`
	OpenHigh        int                      `json:"open_high"`
	OpenMedium      int                      `json:"open_medium"`
	OpenLow         int                      `json:"open_low"`
	TriagedCount    int                      `json:"triaged_count"`
	ProjectsScanned int                      `json:"projects_scanned"`
	TopVulnerable   []ProjectPostureResponse `json:"top_vulnerable"`
}

type ProjectPostureResponse struct {
	ProjectID    string `json:"project_id"`
	ProjectName  string `json:"project_name"`
	OpenCritical int    `json:"open_critical"`
	OpenHigh     int    `json:"open_high"`
}

func toSecurityPostureResponse(p application.SecurityPosture) SecurityPostureResponse {
	top := make([]ProjectPostureResponse, 0, len(p.TopVulnerable))
	for _, pp := range p.TopVulnerable {
		top = append(top, ProjectPostureResponse{
			ProjectID: pp.ProjectID, ProjectName: pp.ProjectName,
			OpenCritical: pp.OpenCritical, OpenHigh: pp.OpenHigh,
		})
	}
	return SecurityPostureResponse{
		OpenCritical: p.OpenCritical, OpenHigh: p.OpenHigh, OpenMedium: p.OpenMedium, OpenLow: p.OpenLow,
		TriagedCount: p.TriagedCount, ProjectsScanned: p.ProjectsScanned, TopVulnerable: top,
	}
}

// PostureSnapshotResponse é o formato público de domain.PostureSnapshot
// (Fase 14, continuação — tendência histórica) — um ponto da série
// temporal que alimenta o gráfico de tendência do dashboard.
type PostureSnapshotResponse struct {
	Date            string `json:"date"` // YYYY-MM-DD, não um timestamp — só a data importa (ver domain.PostureSnapshot.Date)
	OpenCritical    int    `json:"open_critical"`
	OpenHigh        int    `json:"open_high"`
	OpenMedium      int    `json:"open_medium"`
	OpenLow         int    `json:"open_low"`
	TriagedCount    int    `json:"triaged_count"`
	ProjectsScanned int    `json:"projects_scanned"`
}

func toPostureSnapshotResponses(list []domain.PostureSnapshot) []PostureSnapshotResponse {
	out := make([]PostureSnapshotResponse, 0, len(list))
	for _, s := range list {
		out = append(out, PostureSnapshotResponse{
			Date:            s.Date.Format("2006-01-02"),
			OpenCritical:    s.OpenCritical,
			OpenHigh:        s.OpenHigh,
			OpenMedium:      s.OpenMedium,
			OpenLow:         s.OpenLow,
			TriagedCount:    s.TriagedCount,
			ProjectsScanned: s.ProjectsScanned,
		})
	}
	return out
}

func toProjectFindingHistoryResponses(list []application.ProjectFindingHistory) []ProjectFindingHistoryResponse {
	out := make([]ProjectFindingHistoryResponse, 0, len(list))
	for _, h := range list {
		out = append(out, ProjectFindingHistoryResponse{
			Fingerprint:     h.Fingerprint,
			Scanner:         h.Scanner,
			OWASPCategory:   h.OWASPCategory,
			Severity:        string(h.Severity),
			Description:     h.Description,
			File:            h.File,
			Line:            h.Line,
			FirstSeenAt:     h.FirstSeenAt,
			LastSeenAt:      h.LastSeenAt,
			ScanCount:       h.ScanCount,
			StillPresent:    h.StillPresent,
			Tool:            ToolResponse{Name: toolDisplayName(h.Scanner)},
			TriageStatus:    h.TriageStatus,
			TriageReason:    h.TriageReason,
			TriageExpiresAt: h.TriageExpiresAt,
			TriageExpired:   h.TriageExpired,
		})
	}
	return out
}
