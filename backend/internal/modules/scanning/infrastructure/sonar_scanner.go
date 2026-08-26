package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// SonarScannerName é o valor que identifica este CodeScanner no registro
// do scanning.Service.
const SonarScannerName = "sonarqube"

// SonarScanner é o terceiro CodeScanner real da plataforma (Fase 5 do
// roadmap de segurança): qualidade de código/bugs/vulnerabilidades via um
// servidor SonarQube self-hosted (decisão explícita do usuário — ver
// docker-compose.yml e docs/roadmap-secops-orchestrator.md).
//
// Diferença estrutural em relação a TrivyScanner/SemgrepScanner: os dois
// primeiros são processos que rodam do início ao fim e devolvem o
// resultado completo no próprio stdout. O SonarQube é assíncrono em DOIS
// níveis — o `sonar-scanner` CLI só faz upload do relatório e retorna
// (não espera processar); o processamento de fato (a "Compute Engine" do
// servidor) roda depois, em segundo plano, no próprio SonarQube. Por
// isso Execute aqui, além de clonar+rodar o CLI, ainda precisa: (1) ler
// o ID da tarefa que o CLI grava em .scannerwork/report-task.txt, (2)
// consultar a API do servidor até a tarefa terminar, e só então (3)
// buscar os achados via /api/issues/search — nenhum desses três passos
// existe nos outros dois scanners.
//
// Mesmo alvo/mecânica de clonagem que TrivyScanner/SemgrepScanner (ver
// git_clone.go) — a validação de alvo e a defesa de SSRF são
// compartilhadas, nunca duplicadas.
//
// Containerização (§ decisão do usuário — "gitguard usa cada solução
// containerizada, vamos fazer do mesmo jeito", ver
// docs/roadmap-secops-orchestrator.md): Execute não roda mais
// `sonar-scanner` dentro do próprio processo — clona pra dentro de um
// volume compartilhado (workspaceDir) e chama o sidecar `sonar-scanner-cli`
// (cmd/sonar-sidecar) via HTTP, que roda o CLI no PRÓPRIO container
// isolado e devolve só o ceTaskId (não o JSON nativo de uma ferramenta —
// o sonar-scanner CLI não produz um relatório de achados, só faz upload;
// ver comentário no topo de cmd/sonar-sidecar/main.go pra por que este
// sidecar precisa de acesso de ESCRITA ao volume, ao contrário dos
// outros três). waitForAnalysis/fetchIssues abaixo continuam falando
// HTTP direto com o servidor SonarQube de verdade (serverURL) — não são
// afetados pela containerização do CLI, que é um passo local anterior a
// essas duas chamadas.
//
// Nunca teve um ExecuteLocal/LocalScanner (ao contrário de Trivy/
// Gitleaks/Semgrep): a Fase 8 (cmd/secscan) já escopava isso fora de
// propósito — SonarQube exige um servidor rodando e credenciais, não dá
// pra rodar "local" sem rede de qualquer forma. Por isso Execute aqui
// sempre exige o sidecar configurado, sem o fallback os/exec que
// TrivyScanner.ExecuteLocal/SemgrepScanner.ExecuteLocal têm — nunca
// existiu um caminho que precisasse dele.
type SonarScanner struct {
	// sidecarURL é o endereço do sidecar (ex.: http://sonar-scanner-cli:8080)
	// que Execute chama via HTTP pra rodar o CLI — vazio reporta o
	// scanner como indisponível, mesmo princípio de serverURL vazio.
	// Nome deliberadamente diferente de "serviceURL" (a convenção nos
	// outros três scanners) pra nunca ser confundido com serverURL
	// abaixo (o SERVIDOR SonarQube em si — uma URL completamente
	// diferente). Mesma posição de TrivyScanner.serviceURL/workspaceDir
	// na assinatura do construtor abaixo — só os dois campos
	// serverURL/token logo depois são exclusivos deste scanner (os
	// outros três não falam com um servidor de análise separado).
	sidecarURL string
	// workspaceDir é o diretório BASE (dentro do volume compartilhado
	// com o sidecar) onde Execute clona o alvo — ver cloneShallow.
	workspaceDir string
	serverURL    string
	token        string
	httpClient   *http.Client
	cloneTimeout time.Duration
	// analysisTimeout, ao contrário de cloneTimeout, é exclusivo deste
	// scanner — os outros três não têm uma segunda fase assíncrona
	// (a Compute Engine do servidor) pra esperar depois do clone.
	analysisTimeout time.Duration
	logger          *slog.Logger
}

// NewSonarScanner constrói o adapter — mesma ordem de parâmetros que
// NewTrivyScanner/NewGitleaksScanner/NewSemgrepScanner (sidecarURL,
// workspaceDir, ..., cloneTimeout, logger), com serverURL/token
// inseridos no meio por serem exclusivos deste scanner. serverURL vazio
// é uma configuração válida (mesmo princípio de
// DiarioOficialConfig.BaseURL) — Execute reporta o scanner como
// indisponível em vez de o worker inteiro falhar ao inicializar quando o
// SonarQube ainda não foi configurado. sidecarURL vazio tem o mesmo
// efeito (mesmo princípio de TrivyScanner.serviceURL vazio) — os dois
// precisam estar preenchidos pra este scanner funcionar.
func NewSonarScanner(sidecarURL, workspaceDir, serverURL, token string, cloneTimeout, analysisTimeout time.Duration, logger *slog.Logger) *SonarScanner {
	return &SonarScanner{
		sidecarURL:      strings.TrimRight(sidecarURL, "/"),
		workspaceDir:    workspaceDir,
		serverURL:       strings.TrimRight(serverURL, "/"),
		token:           token,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		cloneTimeout:    cloneTimeout,
		analysisTimeout: analysisTimeout,
		logger:          logger,
	}
}

var _ domain.CodeScanner = (*SonarScanner)(nil)

func (s *SonarScanner) Name() string { return SonarScannerName }

// Execute clona o alvo, submete a análise ao servidor SonarQube
// configurado (via o sidecar `sonar-scanner-cli`), espera a Compute
// Engine processá-la, e busca os achados (issues) resultantes.
func (s *SonarScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if s.serverURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: sonarqube: SCANNING_SONARQUBE_URL is not configured")
	}
	if s.sidecarURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: sonarqube: SCANNING_SONAR_SCANNER_SERVICE_URL is not configured")
	}

	dir, cleanup, err := cloneShallow(ctx, target, s.cloneTimeout, s.workspaceDir, s.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	projectKey := sonarProjectKey(target)
	taskID, err := s.scanRemote(ctx, dir, projectKey)
	if err != nil {
		return nil, err
	}

	analysisCtx, cancel := context.WithTimeout(ctx, s.analysisTimeout)
	defer cancel()
	if err := s.waitForAnalysis(analysisCtx, taskID); err != nil {
		return nil, err
	}

	return s.fetchIssues(ctx, projectKey)
}

// sonarProjectKey deriva a project key do SonarQube a partir do alvo —
// ver domain.SonarProjectKey (movida pra lá porque transport.toolLink
// também precisa da mesma derivação, pra montar o link "abrir no
// SonarQube" de um achado já persistido, sem rodar scanner nenhum).
func sonarProjectKey(target string) string {
	return domain.SonarProjectKey(target)
}

// scanRemote pede pro sidecar (cmd/sonar-sidecar) rodar
// `sonar-scanner` contra dir, que precisa estar dentro do volume
// compartilhado que os dois containers montam (o sidecar em
// leitura-escrita, diferente dos outros três — ver o comentário no topo
// de cmd/sonar-sidecar/main.go). Devolve o ceTaskId que o CLI gravou,
// pronto pra waitForAnalysis consultar.
func (s *SonarScanner) scanRemote(ctx context.Context, dir, projectKey string) (string, error) {
	body, err := json.Marshal(struct {
		Path       string `json:"path"`
		HostURL    string `json:"host_url"`
		Token      string `json:"token"`
		ProjectKey string `json:"project_key"`
	}{Path: dir, HostURL: s.serverURL, Token: s.token, ProjectKey: projectKey})
	if err != nil {
		return "", fmt.Errorf("scanning: sonarqube: encode scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sidecarURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("scanning: sonarqube: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: sidecar unreachable: %s", err.Error()))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: read sidecar response: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return "", apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: scan failed: %s", extractErrorLine(errResp.Error)))
	}

	var scanResp struct {
		CETaskID string `json:"ce_task_id"`
	}
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return "", fmt.Errorf("scanning: sonarqube: decode sidecar response: %w", err)
	}
	if scanResp.CETaskID == "" {
		return "", fmt.Errorf("scanning: sonarqube: sidecar returned no ce_task_id")
	}
	return scanResp.CETaskID, nil
}

// sonarTaskResponse é o subconjunto de GET /api/ce/task que este adapter
// usa.
type sonarTaskResponse struct {
	Task struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"task"`
}

// waitForAnalysis consulta /api/ce/task até a Compute Engine do
// SonarQube terminar de processar o relatório enviado — PENDING/IN_PROGRESS
// continuam o loop, SUCCESS retorna, FAILED/CANCELED viram erro.
func (s *SonarScanner) waitForAnalysis(ctx context.Context, taskID string) error {
	taskURL := fmt.Sprintf("%s/api/ce/task?id=%s", s.serverURL, url.QueryEscape(taskID))
	for {
		var task sonarTaskResponse
		if err := s.getJSON(ctx, taskURL, &task); err != nil {
			return err
		}
		switch task.Task.Status {
		case "SUCCESS":
			return nil
		case "FAILED", "CANCELED":
			return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: analysis %s: %s", strings.ToLower(task.Task.Status), task.Task.ErrorMessage))
		}

		select {
		case <-ctx.Done():
			return apperrors.DependencyUnavailable("scanning: sonarqube: timed out waiting for the analysis to finish processing")
		case <-time.After(2 * time.Second):
		}
	}
}

// sonarIssuesResponse é o subconjunto de GET /api/issues/search que este
// adapter usa.
type sonarIssuesResponse struct {
	Paging struct {
		Total int `json:"total"`
	} `json:"paging"`
	Issues []struct {
		RuleKey   string `json:"rule"`
		Severity  string `json:"severity"`
		Component string `json:"component"`
		Line      int    `json:"line"`
		Message   string `json:"message"`
	} `json:"issues"`
}

// sonarIssuesPageSize é o maior valor de "ps" que a API aceita.
const sonarIssuesPageSize = 500

// fetchIssues busca todo issue (bug, vulnerabilidade, code smell) do
// projeto, paginando conforme necessário.
//
// Deliberadamente NÃO busca "security hotspots" (/api/hotspots/search):
// verificado contra o servidor real que esse endpoint exige um
// token/permissão de leitura de projeto diferente da que um
// GLOBAL_ANALYSIS_TOKEN concede (erro "Insufficient privileges"), e
// hotspots são conceitualmente diferentes de um achado confirmado — eles
// exigem revisão humana pra decidir se são um problema de verdade.
// Tratá-los como Finding automático misrepresentaria "precisa de
// triagem" como "problema confirmado".
//
// OWASPCategory fica sempre vazio: verificado contra a API real desta
// versão (26.8, Community Edition) que não existe mais um campo
// estruturado de mapeamento OWASP/CWE em /api/rules/show ou
// /api/rules/search (só texto livre dentro de descriptionSections em
// HTML) — ao contrário do Trivy/Semgrep, que expõem isso como dado
// estruturado.
func (s *SonarScanner) fetchIssues(ctx context.Context, projectKey string) ([]domain.Finding, error) {
	var findings []domain.Finding
	for page := 1; ; page++ {
		pageURL := fmt.Sprintf("%s/api/issues/search?componentKeys=%s&ps=%d&p=%d",
			s.serverURL, url.QueryEscape(projectKey), sonarIssuesPageSize, page)

		var resp sonarIssuesResponse
		if err := s.getJSON(ctx, pageURL, &resp); err != nil {
			return nil, err
		}
		for _, issue := range resp.Issues {
			findings = append(findings, domain.Finding{
				ID:          issue.RuleKey,
				Severity:    normalizeSonarSeverity(issue.Severity),
				Description: issue.Message,
				File:        strings.TrimPrefix(issue.Component, projectKey+":"),
				Line:        issue.Line,
			})
		}
		if len(resp.Issues) == 0 || page*sonarIssuesPageSize >= resp.Paging.Total {
			break
		}
	}
	return findings, nil
}

// normalizeSonarSeverity traduz a escala legada de 5 níveis do SonarQube
// (BLOCKER/CRITICAL/MAJOR/MINOR/INFO — ainda o campo top-level "severity"
// de todo issue na API atual, confirmado contra o servidor real) pra
// domain.Severity. BLOCKER e CRITICAL colapsam nos dois pro mesmo
// CRITICAL — perde granularidade, mas domain.Severity só tem quatro
// níveis por desenho (ver o comentário do tipo em domain/scanner.go).
func normalizeSonarSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "BLOCKER", "CRITICAL":
		return domain.SeverityCritical
	case "MAJOR":
		return domain.SeverityHigh
	case "MINOR":
		return domain.SeverityMedium
	default: // INFO, ou qualquer valor desconhecido
		return domain.SeverityLow
	}
}

// getJSON busca url autenticado com o token (Bearer, confirmado contra o
// servidor real — o esquema recomendado pelas versões atuais do
// SonarQube) e decodifica a resposta JSON em dst.
func (s *SonarScanner) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("scanning: sonarqube: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: sonarqube: unexpected status %d: %s", resp.StatusCode, firstLine(string(body))))
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("scanning: sonarqube: decode response: %w", err)
	}
	return nil
}
