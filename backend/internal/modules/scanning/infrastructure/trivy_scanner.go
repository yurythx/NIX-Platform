package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// TrivyScannerName é o valor que identifica este CodeScanner no registro
// do scanning.Service (o "nome" que o cliente HTTP passa em
// POST /api/v1/scanning/scans).
const TrivyScannerName = "trivy"

// TrivyScanner é o primeiro CodeScanner real da plataforma (Strategy
// Pattern — ver domain.CodeScanner): escaneia dependências (go.mod,
// go.sum, package-lock.json, ...) e Dockerfiles/IaC via `trivy fs`.
//
// Alvo e por que não escaneia containers/imagens: o worker roda numa
// imagem mínima sem o código-fonte do repositório e sem acesso ao daemon
// Docker, e nenhuma imagem construída pelo CI é publicada em um registry
// hoje — então não há de onde ler um Dockerfile ou uma imagem em tempo de
// execução sem primeiro obter o código de algum lugar. A escolha desta
// fase (decisão explícita do usuário, registrada em
// docs/roadmap-secops-orchestrator.md) foi clonar o repositório via git
// para um diretório temporário (ver git_clone.go, compartilhado com
// SemgrepScanner) e rodar `trivy fs` nele — sem exigir montar o socket do
// Docker (superfície de ataque equivalente a root no host) nem depender
// de um registry que ainda não existe.
//
// Deliberadamente NÃO roda o scanner "secret" do Trivy: o CI já roda
// gitleaks para a mesma categoria (secret scanning) — rodar os dois seria
// a mesma redundância que levou a pular TruffleHog nesta fase.
//
// Containerização (§ decisão do usuário — "gitguard usa cada solução
// containerizada, vamos fazer do mesmo jeito", ver
// docs/roadmap-secops-orchestrator.md): Execute (o caminho de produção,
// via worker) não roda mais `trivy` dentro do próprio processo — clona
// pra dentro de um volume compartilhado (workspaceDir) e chama o sidecar
// `trivy-scanner` (cmd/trivy-sidecar) via HTTP, que roda o binário no
// PRÓPRIO container isolado. ExecuteLocal (usado só por cmd/secscan, um
// CLI standalone que nunca depende de rede) continua rodando o binário
// local via os/exec, sem mudança nenhuma — os dois caminhos convergem no
// mesmo parseTrivyReport, então o formato do achado nunca diverge entre
// eles.
type TrivyScanner struct {
	// trivyPath só é usado por ExecuteLocal.
	trivyPath string
	// serviceURL é o endereço do sidecar (ex.: http://trivy-scanner:8080)
	// que Execute chama via HTTP — vazio reporta o scanner como
	// indisponível, mesmo princípio de SonarScanner.serverURL vazio.
	serviceURL string
	// workspaceDir é o diretório BASE (dentro do volume compartilhado com
	// o sidecar) onde Execute clona o alvo — ver cloneShallow.
	workspaceDir string
	httpClient   *http.Client
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// NewTrivyScanner constrói o adapter. trivyPath é o caminho do binário
// `trivy` local (só usado por ExecuteLocal); serviceURL é o endereço do
// sidecar containerizado que Execute chama via HTTP (vazio = scanner
// "trivy" reportado como indisponível no caminho de produção, mas
// ExecuteLocal continua funcionando — útil pra rodar cmd/secscan sem o
// resto da stack no ar); workspaceDir é o diretório base do clone de
// Execute, compartilhado com o sidecar (vazio usa o temp dir padrão do
// SO, correto quando não há sidecar nenhum rodando).
func NewTrivyScanner(trivyPath, serviceURL, workspaceDir string, cloneTimeout time.Duration, logger *slog.Logger) *TrivyScanner {
	return &TrivyScanner{
		trivyPath:    trivyPath,
		serviceURL:   strings.TrimRight(serviceURL, "/"),
		workspaceDir: workspaceDir,
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
		cloneTimeout: cloneTimeout,
		logger:       logger,
	}
}

var _ domain.CodeScanner = (*TrivyScanner)(nil)

func (t *TrivyScanner) Name() string { return TrivyScannerName }

// Execute clona o alvo (raso, um branch só) via cloneShallow pro volume
// compartilhado com o sidecar, e pede pro sidecar rodar `trivy fs` nesse
// caminho via HTTP — sempre removido ao final, sucesso ou erro (o
// worker é dono do diretório; o sidecar só lê).
func (t *TrivyScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if t.serviceURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: trivy: SCANNING_TRIVY_SERVICE_URL is not configured")
	}

	dir, cleanup, err := cloneShallow(ctx, target, t.cloneTimeout, t.workspaceDir, t.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return t.scanRemote(ctx, dir)
}

// ExecuteLocal roda `trivy fs` direto contra dir, sem clonar nada e sem
// depender do sidecar — usado pela Fase 8 (cmd/secscan), onde o
// repositório já está no disco (um checkout local, ou o próprio CI que
// já fez `actions/checkout`) e o binário `trivy` já é esperado estar
// disponível localmente, sem rede nenhuma envolvida. Nunca remove dir:
// quem chama é dono do diretório (ao contrário de Execute, que é dono do
// diretório temporário que ele mesmo criou via cloneShallow).
func (t *TrivyScanner) ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error) {
	// --scanners vuln,misconfig: deliberadamente sem "secret" (ver
	// comentário do tipo acima).
	cmd := exec.CommandContext(ctx, t.trivyPath, "fs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: scan failed: %s", extractErrorLine(stderr.String())))
	}
	return parseTrivyReport(stdout.Bytes())
}

// scanRemote pede pro sidecar (cmd/trivy-sidecar) rodar `trivy fs` contra
// dir, que precisa estar dentro do volume compartilhado que os dois
// containers montam. dir é repassado como está — o sidecar enxerga o
// MESMO caminho, já que o volume é montado no mesmo ponto (/workspace)
// dos dois lados.
func (t *TrivyScanner) scanRemote(ctx context.Context, dir string) ([]domain.Finding, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: dir})
	if err != nil {
		return nil, fmt.Errorf("scanning: trivy: encode scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.serviceURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scanning: trivy: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: sidecar unreachable: %s", err.Error()))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: read sidecar response: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: scan failed: %s", extractErrorLine(errResp.Error)))
	}

	return parseTrivyReport(respBody)
}

// trivyReport é o subconjunto do JSON de saída do `trivy` (formato
// "json") que este adapter usa — bem menos campos do que o schema
// completo da ferramenta, só o que vira um domain.Finding.
type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Message       string `json:"Message"`
			Severity      string `json:"Severity"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func parseTrivyReport(raw []byte) ([]domain.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("scanning: trivy: decode report: %w", err)
	}

	var findings []domain.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, domain.Finding{
				ID:            v.VulnerabilityID,
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Severity:      normalizeTrivySeverity(v.Severity),
				Description:   fmt.Sprintf("%s (pacote %s@%s, corrigido em %s)", v.Title, v.PkgName, v.InstalledVersion, orDash(v.FixedVersion)),
				File:          result.Target,
			})
		}
		for _, m := range result.Misconfigurations {
			findings = append(findings, domain.Finding{
				ID:            m.ID,
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Severity:      normalizeTrivySeverity(m.Severity),
				Description:   fmt.Sprintf("%s: %s", m.Title, m.Message),
				File:          result.Target,
				Line:          m.CauseMetadata.StartLine,
			})
		}
	}
	return findings, nil
}

// normalizeTrivySeverity traduz a escala do Trivy pra domain.Severity —
// as quatro que importam já batem 1:1 com o vocabulário do Trivy (por
// desenho, ver o comentário de domain.Severity). "UNKNOWN" (Trivy não
// conseguiu classificar) vira LOW por segurança: nunca descartar
// silenciosamente um achado só porque a gravidade não pôde ser
// determinada.
func normalizeTrivySeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
