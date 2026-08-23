package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
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
// para um diretório temporário e rodar `trivy fs` nele — sem exigir
// montar o socket do Docker (superfície de ataque equivalente a root no
// host) nem depender de um registry que ainda não existe.
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

// refPattern restringe o que aceitamos depois de "#" no alvo a algo que
// só pode ser um nome de branch/tag git — nunca uma flag (não pode
// começar com "-") nem conter espaço/metacaractere.
var refPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// parseTarget separa "<url-git-https>[#branch-ou-tag]" e valida os dois
// pedaços. Só aceita https:// deliberadamente: file:// permitiria ler
// qualquer caminho local acessível ao processo do worker (leitura
// arbitrária de arquivo disfarçada de "clonar um repositório"), e
// ssh://.../git@... exigiria gerenciar uma chave privada dentro do
// worker — nenhum dos dois vale o risco/complexidade extra para esta
// fase. Exigir o prefixo "https://" também garante, por construção, que o
// valor nunca começa com "-": mesmo passado como argv separado (nunca via
// shell), um valor começando com "-" poderia ser interpretado pelo git
// como uma flag em vez de uma URL — injeção de argumento, não de shell,
// mas real do mesmo jeito com os/exec.
func parseTarget(target string) (repoURL, ref string, err error) {
	repoURL, ref, _ = strings.Cut(target, "#")
	if !strings.HasPrefix(repoURL, "https://") {
		return "", "", fmt.Errorf("scanning: trivy target must be an https:// git URL, got %q", target)
	}
	if ref != "" && !refPattern.MatchString(ref) {
		return "", "", fmt.Errorf("scanning: trivy target ref %q is not a valid branch/tag name", ref)
	}
	return repoURL, ref, nil
}

// Execute clona repoURL (raso, um branch só) para um diretório temporário
// e roda `trivy fs` nele. O diretório é sempre removido ao final,
// sucesso ou erro — nunca deixa código de terceiros no disco do worker
// depois de um scan.
func (t *TrivyScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	repoURL, ref, err := parseTarget(target)
	if err != nil {
		return nil, apperrors.Validation(err.Error())
	}

	dir, err := os.MkdirTemp("", "nix-trivy-*")
	if err != nil {
		return nil, fmt.Errorf("scanning: trivy: create temp dir: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			t.logger.Warn("scanning: trivy: failed to clean up temp dir", slog.String("dir", dir), slog.Any("error", rmErr))
		}
	}()

	cloneCtx, cancel := context.WithTimeout(ctx, t.cloneTimeout)
	defer cancel()
	if err := t.cloneRepo(cloneCtx, repoURL, ref, dir); err != nil {
		return nil, err
	}

	return t.scanFS(ctx, dir)
}

func (t *TrivyScanner) cloneRepo(ctx context.Context, repoURL, ref, dir string) error {
	args := []string{"clone", "--depth", "1", "--single-branch"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, repoURL, dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: trivy: git clone failed: %s", firstLine(stderr.String())))
	}
	return nil
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

// firstLine evita despejar um stderr de várias linhas (potencialmente com
// detalhe interno do binário) inteiro numa mensagem de erro voltada ao
// cliente HTTP — só a primeira linha, o resto fica só no log.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "unknown error"
	}
	return s
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
				Severity:      normalizeSeverity(v.Severity),
				Description:   fmt.Sprintf("%s (pacote %s@%s, corrigido em %s)", v.Title, v.PkgName, v.InstalledVersion, orDash(v.FixedVersion)),
				File:          result.Target,
			})
		}
		for _, m := range result.Misconfigurations {
			findings = append(findings, domain.Finding{
				ID:            m.ID,
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Severity:      normalizeSeverity(m.Severity),
				Description:   fmt.Sprintf("%s: %s", m.Title, m.Message),
				File:          result.Target,
				Line:          m.CauseMetadata.StartLine,
			})
		}
	}
	return findings, nil
}

// normalizeSeverity traduz a escala do Trivy pra domain.Severity — as
// quatro que importam já batem 1:1 com o vocabulário do Trivy (por
// desenho, ver o comentário de domain.Severity). "UNKNOWN" (Trivy não
// conseguiu classificar) vira LOW por segurança: nunca descartar
// silenciosamente um achado só porque a gravidade não pôde ser
// determinada.
func normalizeSeverity(s string) domain.Severity {
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
