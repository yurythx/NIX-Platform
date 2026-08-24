package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
type TrivyScanner struct {
	trivyPath    string
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// NewTrivyScanner constrói o adapter. trivyPath é o caminho do binário
// `trivy` (normalmente só "trivy", resolvido via PATH — configurável para
// ambientes que o instalam em outro lugar).
func NewTrivyScanner(trivyPath string, cloneTimeout time.Duration, logger *slog.Logger) *TrivyScanner {
	return &TrivyScanner{trivyPath: trivyPath, cloneTimeout: cloneTimeout, logger: logger}
}

var _ domain.CodeScanner = (*TrivyScanner)(nil)

func (t *TrivyScanner) Name() string { return TrivyScannerName }

// Execute clona o alvo (raso, um branch só) via cloneShallow e roda
// `trivy fs` no diretório resultante — sempre removido ao final, sucesso
// ou erro.
func (t *TrivyScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	dir, cleanup, err := cloneShallow(ctx, target, t.cloneTimeout, t.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return t.scanFS(ctx, dir)
}

// ExecuteLocal roda `trivy fs` direto contra dir, sem clonar nada — usado
// pela Fase 8 (cmd/secscan), onde o repositório já está no disco (um
// checkout local, ou o próprio CI que já fez `actions/checkout`) e clonar
// de novo seria redundante. Nunca remove dir: quem chama é dono do
// diretório (ao contrário de Execute, que é dono do diretório temporário
// que ele mesmo criou via cloneShallow).
func (t *TrivyScanner) ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error) {
	return t.scanFS(ctx, dir)
}

func (t *TrivyScanner) scanFS(ctx context.Context, dir string) ([]domain.Finding, error) {
	// --scanners vuln,misconfig: deliberadamente sem "secret" (ver
	// comentário do tipo acima).
	cmd := exec.CommandContext(ctx, t.trivyPath, "fs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: scan failed: %s", firstLine(stderr.String())))
	}
	return parseTrivyReport(stdout.Bytes())
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
