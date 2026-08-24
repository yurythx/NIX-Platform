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

// GitleaksScannerName é o valor que identifica este CodeScanner no registro
// do scanning.Service.
const GitleaksScannerName = "gitleaks"

// GitleaksScanner (Fase 11 — ver docs/roadmap-secops-orchestrator.md, seção
// "Extensão") escaneia segredos commitados (chaves de API, tokens, senhas)
// via `gitleaks detect`. Mesmo esqueleto do TrivyScanner JÁ CONTAINERIZADO
// (ver "Containerização" no roadmap): Execute clona via cloneShallow pro
// volume compartilhado scanning_workspace e chama o sidecar
// `gitleaks-scanner` (cmd/gitleaks-sidecar) via HTTP — nunca roda o binário
// dentro do próprio worker. ExecuteLocal continua lendo um diretório já no
// disco direto (upload .zip, Fase 10 / cmd/secscan) via os/exec local, sem
// rede nenhuma envolvida — os dois caminhos convergem no mesmo
// parseGitleaksReport, então o formato do achado nunca diverge entre eles.
//
// Por que não é redundante com o gitleaks que já roda no CI deste próprio
// repositório (Fase 2, pulada por esse exato motivo à época): o CI só cobre
// o que está em PRs/commits DESTE repositório; este scanner sob demanda
// cobre QUALQUER alvo que o usuário aponte pela UI — mesmo raciocínio que já
// vale pra Trivy/Semgrep/SonarQube não serem "redundantes" com o CI mesmo o
// CI já rodando govulncheck/npm audit (ver Reconciliação, decisão 3).
//
// --no-git: escaneia os arquivos como estão no disco, não o histórico de
// commits — consistente com o clone raso (--depth 1) que Trivy/Semgrep
// também só enxergam; histórico completo é um modo separado, fora de
// escopo aqui.
type GitleaksScanner struct {
	// gitleaksPath só é usado por ExecuteLocal.
	gitleaksPath string
	// serviceURL é o endereço do sidecar (ex.: http://gitleaks-scanner:8080)
	// que Execute chama via HTTP — vazio reporta o scanner como
	// indisponível, mesmo princípio de TrivyScanner.serviceURL vazio.
	serviceURL string
	// workspaceDir é o diretório BASE (dentro do volume compartilhado com o
	// sidecar) onde Execute clona o alvo — ver cloneShallow.
	workspaceDir string
	httpClient   *http.Client
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// NewGitleaksScanner constrói o adapter — mesmos parâmetros e mesmo
// significado de NewTrivyScanner.
func NewGitleaksScanner(gitleaksPath, serviceURL, workspaceDir string, cloneTimeout time.Duration, logger *slog.Logger) *GitleaksScanner {
	return &GitleaksScanner{
		gitleaksPath: gitleaksPath,
		serviceURL:   strings.TrimRight(serviceURL, "/"),
		workspaceDir: workspaceDir,
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
		cloneTimeout: cloneTimeout,
		logger:       logger,
	}
}

var _ domain.CodeScanner = (*GitleaksScanner)(nil)

func (g *GitleaksScanner) Name() string { return GitleaksScannerName }

// Execute clona o alvo (raso, um branch só) via cloneShallow pro volume
// compartilhado com o sidecar, e pede pro sidecar rodar `gitleaks detect`
// nesse caminho via HTTP — sempre removido ao final, sucesso ou erro (o
// worker é dono do diretório; o sidecar só lê).
func (g *GitleaksScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if g.serviceURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: gitleaks: SCANNING_GITLEAKS_SERVICE_URL is not configured")
	}

	dir, cleanup, err := cloneShallow(ctx, target, g.cloneTimeout, g.workspaceDir, g.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return g.scanRemote(ctx, dir)
}

// ExecuteLocal roda `gitleaks detect` direto contra dir, sem clonar nada e
// sem depender do sidecar — usado pela Fase 8 (cmd/secscan) e pela Fase 10
// (projeto criado por upload .zip). Nunca remove dir: quem chama é dono do
// diretório.
func (g *GitleaksScanner) ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error) {
	cmd := exec.CommandContext(ctx, g.gitleaksPath, "detect",
		"--source", dir,
		"--no-git",
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--exit-code", "0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: gitleaks: scan failed: %s", extractErrorLine(stderr.String())))
	}
	return parseGitleaksReport(stdout.Bytes(), dir)
}

// scanRemote pede pro sidecar (cmd/gitleaks-sidecar) rodar `gitleaks
// detect` contra dir, que precisa estar dentro do volume compartilhado que
// os dois containers montam.
func (g *GitleaksScanner) scanRemote(ctx context.Context, dir string) ([]domain.Finding, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: dir})
	if err != nil {
		return nil, fmt.Errorf("scanning: gitleaks: encode scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.serviceURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scanning: gitleaks: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: gitleaks: sidecar unreachable: %s", err.Error()))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: gitleaks: read sidecar response: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: gitleaks: scan failed: %s", extractErrorLine(errResp.Error)))
	}

	return parseGitleaksReport(respBody, dir)
}

// gitleaksFinding é o subconjunto do JSON de saída do `gitleaks` (formato
// "json") que este adapter usa.
type gitleaksFinding struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
}

// parseGitleaksReport lê o array JSON produzido por `gitleaks detect
// --report-format json`. Quando nenhum segredo é encontrado, o gitleaks não
// escreve um array vazio "[]" — não escreve NADA em stdout (--report-path
// /dev/stdout com zero achados é um arquivo vazio), então corpo em branco
// (ou só espaço) é tratado como "nenhum achado", não como erro de parsing.
//
// baseDir é o diretório que foi passado como --source: o gitleaks devolve
// "File" com esse prefixo embutido (ex.: "/workspace/nix-scan-123/app.go"),
// já que anda o próprio caminho absoluto que recebeu — diferente do trivy,
// que já normaliza pra um caminho relativo sozinho. Removido aqui pra
// nenhum caminho interno efêmero (o nome do diretório de clone) vazar pro
// achado mostrado ao usuário, mesmo padrão que parseTrivyReport já entrega
// (Target relativo, ex.: "go.mod").
func parseGitleaksReport(raw []byte, baseDir string) ([]domain.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var report []gitleaksFinding
	if err := json.Unmarshal(trimmed, &report); err != nil {
		return nil, fmt.Errorf("scanning: gitleaks: decode report: %w", err)
	}

	prefix := strings.TrimRight(baseDir, "/") + "/"
	findings := make([]domain.Finding, 0, len(report))
	for _, f := range report {
		findings = append(findings, domain.Finding{
			ID:   f.RuleID,
			File: strings.TrimPrefix(f.File, prefix),
			// A07:2021 é onde o próprio OWASP mapeia CWE-798 (Use of
			// Hard-coded Credentials) — ver o Data Mapping oficial do Top
			// 10 2021.
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			// Gitleaks não tem campo de severidade nativo (é binário: achou
			// um segredo ou não) — todo achado mapeia pra CRITICAL, um
			// segredo commitado é sempre grave, nunca um "talvez" (ver
			// docs/roadmap-secops-orchestrator.md, Fase 11).
			Severity:    domain.SeverityCritical,
			Description: fmt.Sprintf("%s (regra %s)", f.Description, f.RuleID),
			Line:        f.StartLine,
			// Snippet mascarado, nunca o segredo em texto puro (f.Match/
			// f.Secret ficam de fora de propósito): o próprio achado não
			// pode se tornar um novo vazamento, seja em log, em resposta de
			// API ou na tela do usuário.
			Snippet: maskSecretSnippet(f.Match),
		})
	}
	return findings, nil
}

// maskSecretSnippet preserva só as bordas de match (contexto suficiente pra
// localizar a linha) e mascara o meio — nunca devolve o segredo inteiro em
// claro em nenhuma camada acima deste parser.
func maskSecretSnippet(match string) string {
	const keep = 3
	if len(match) <= keep*2 {
		return strings.Repeat("*", len(match))
	}
	return match[:keep] + strings.Repeat("*", len(match)-keep*2) + match[len(match)-keep:]
}
