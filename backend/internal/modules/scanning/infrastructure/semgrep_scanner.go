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

// SemgrepScannerName é o valor que identifica este CodeScanner no
// registro do scanning.Service.
const SemgrepScannerName = "semgrep"

// SemgrepScanner é o segundo CodeScanner real da plataforma (Fase 4 do
// roadmap de segurança): SAST via `semgrep scan`, cobrindo A03 Injection
// e o restante do OWASP Top 10 que análise estática de código alcança.
//
// Mesmo alvo/mecânica que TrivyScanner: clona o repositório via git para
// um diretório temporário (ver git_clone.go, compartilhado entre os
// dois — a validação de alvo e a defesa de SSRF vivem num único lugar,
// nunca duplicadas) e roda a ferramenta nele.
//
// config é o(s) ruleset(s) do Semgrep Registry a rodar — por padrão
// "p/owasp-top-ten" (exatamente o que o roadmap propõe), mantido pela
// comunidade Semgrep e atualizado independente de um deploy desta
// plataforma.
//
// Containerização (§ decisão do usuário — "gitguard usa cada solução
// containerizada, vamos fazer do mesmo jeito", ver
// docs/roadmap-secops-orchestrator.md): mesmo esqueleto de TrivyScanner/
// GitleaksScanner já containerizados. Execute (o caminho de produção, via
// worker) não roda mais `semgrep` dentro do próprio processo — clona pra
// dentro de um volume compartilhado (workspaceDir) e chama o sidecar
// `semgrep-scanner` (cmd/semgrep-sidecar) via HTTP. ExecuteLocal (usado
// por cmd/secscan e, sem sidecar configurado, pela Fase 10/upload .zip)
// continua rodando o binário local via os/exec quando não há sidecar —
// os dois caminhos convergem no mesmo parseSemgrepReport, então o
// formato do achado nunca diverge entre eles.
type SemgrepScanner struct {
	// semgrepPath só é usado por ExecuteLocal sem sidecar configurado.
	semgrepPath string
	config      string
	// serviceURL é o endereço do sidecar (ex.: http://semgrep-scanner:8080)
	// que Execute chama via HTTP — vazio reporta o scanner como
	// indisponível, mesmo princípio de TrivyScanner.serviceURL vazio.
	serviceURL string
	// workspaceDir é o diretório BASE (dentro do volume compartilhado com
	// o sidecar) onde Execute clona o alvo — ver cloneShallow.
	workspaceDir string
	httpClient   *http.Client
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// DefaultSemgrepConfig é o ruleset do Semgrep Registry usado quando
// nenhum outro é configurado.
const DefaultSemgrepConfig = "p/owasp-top-ten"

// NewSemgrepScanner constrói o adapter. semgrepPath é o caminho do
// binário `semgrep` local (só usado por ExecuteLocal sem sidecar
// configurado); serviceURL é o endereço do sidecar containerizado que
// Execute chama via HTTP (vazio = scanner "semgrep" reportado como
// indisponível no caminho de produção, mas ExecuteLocal continua
// funcionando — útil pra rodar cmd/secscan sem o resto da stack no ar);
// workspaceDir é o diretório base do clone de Execute, compartilhado com
// o sidecar (vazio usa o temp dir padrão do SO, correto quando não há
// sidecar nenhum rodando) — mesmos quatro parâmetros que NewTrivyScanner/
// NewGitleaksScanner já recebem.
func NewSemgrepScanner(semgrepPath, serviceURL, workspaceDir, config string, cloneTimeout time.Duration, logger *slog.Logger) *SemgrepScanner {
	if config == "" {
		config = DefaultSemgrepConfig
	}
	return &SemgrepScanner{
		semgrepPath:  semgrepPath,
		config:       config,
		serviceURL:   strings.TrimRight(serviceURL, "/"),
		workspaceDir: workspaceDir,
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
		cloneTimeout: cloneTimeout,
		logger:       logger,
	}
}

var _ domain.CodeScanner = (*SemgrepScanner)(nil)
var _ domain.LocalScanner = (*SemgrepScanner)(nil)

func (s *SemgrepScanner) Name() string { return SemgrepScannerName }

// Execute clona o alvo (raso, um branch só) via cloneShallow pro volume
// compartilhado com o sidecar, e pede pro sidecar rodar `semgrep scan`
// nesse caminho via HTTP — sempre removido ao final, sucesso ou erro (o
// worker é dono do diretório; o sidecar só lê).
func (s *SemgrepScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if s.serviceURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: semgrep: SCANNING_SEMGREP_SERVICE_URL is not configured")
	}

	dir, cleanup, err := cloneShallow(ctx, target, s.cloneTimeout, s.workspaceDir, s.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return s.scanRemote(ctx, dir)
}

// ExecuteLocal roda `semgrep scan` contra dir, sem clonar nada — usado
// pela Fase 8 (cmd/secscan) e, sem sidecar configurado, pela Fase 10
// (projeto criado por upload .zip). Nunca remove dir: quem chama é dono
// do diretório.
//
// Mesma escolha entre sidecar e binário local que TrivyScanner.ExecuteLocal
// faz, pelo mesmo motivo (o binário `semgrep` também não vive mais na
// imagem do worker desde a containerização): com serviceURL configurado
// (o caso real do worker em produção), reaproveita a mesma chamada HTTP
// que Execute usa (scanRemote), só que contra um diretório que já existe
// em vez de um que acabou de ser clonado. Sem serviceURL (cmd/secscan,
// que roda em CI/dev com o `semgrep` instalado separadamente, sem
// sidecar por perto): continua rodando o binário local via os/exec.
func (s *SemgrepScanner) ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error) {
	if s.serviceURL != "" {
		return s.scanRemote(ctx, dir)
	}

	// --quiet suprime a barra de progresso/banner interativo; o exit
	// code do semgrep é 0 tanto com quanto sem achados por padrão (não
	// passamos --error, que faria a ferramenta sair !=0 quando encontra
	// algo ERROR — queremos diferenciar "ferramenta falhou" de "achou
	// problema" pela nossa própria leitura do JSON, não pelo exit code).
	cmd := exec.CommandContext(ctx, s.semgrepPath, "scan", "--config", s.config, "--json", "--quiet", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: semgrep: scan failed: %s", extractErrorLine(stderr.String())))
	}
	return parseSemgrepReport(stdout.Bytes(), dir)
}

// scanRemote pede pro sidecar (cmd/semgrep-sidecar) rodar `semgrep scan`
// contra dir, que precisa estar dentro do volume compartilhado que os
// dois containers montam. Ao contrário de TrivyScanner/GitleaksScanner
// (argumentos fixos), o corpo da requisição também carrega s.config — o
// ruleset a rodar não é fixo no sidecar, é decidido pelo worker (ver
// comentário no topo de cmd/semgrep-sidecar/main.go).
func (s *SemgrepScanner) scanRemote(ctx context.Context, dir string) ([]domain.Finding, error) {
	body, err := json.Marshal(struct {
		Path   string `json:"path"`
		Config string `json:"config"`
	}{Path: dir, Config: s.config})
	if err != nil {
		return nil, fmt.Errorf("scanning: semgrep: encode scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serviceURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scanning: semgrep: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: semgrep: sidecar unreachable: %s", err.Error()))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: semgrep: read sidecar response: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: semgrep: scan failed: %s", extractErrorLine(errResp.Error)))
	}

	return parseSemgrepReport(respBody, dir)
}

// semgrepReport é o subconjunto do JSON de saída do `semgrep scan --json`
// que este adapter usa.
type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				// OWASP varia de tipo entre regras da comunidade — às
				// vezes uma string única, às vezes uma lista (verificado
				// contra a saída real do semgrep, não assumido) — por
				// isso RawMessage aqui, decodificado de forma tolerante
				// por firstOWASPCategory.
				OWASP json.RawMessage `json:"owasp"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func parseSemgrepReport(raw []byte, scanDir string) ([]domain.Finding, error) {
	var report semgrepReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("scanning: semgrep: decode report: %w", err)
	}

	findings := make([]domain.Finding, 0, len(report.Results))
	for _, r := range report.Results {
		findings = append(findings, domain.Finding{
			ID:            r.CheckID,
			OWASPCategory: firstOWASPCategory(r.Extra.Metadata.OWASP),
			Severity:      normalizeSemgrepSeverity(r.Extra.Severity),
			Description:   r.Extra.Message,
			File:          relativeToScanDir(r.Path, scanDir),
			Line:          r.Start.Line,
			// r.Path (não o File acima) — já é o caminho ABSOLUTO que o
			// semgrep reportou, direto utilizável por captureSnippet, sem
			// precisar remontar a partir do relativo + scanDir de novo.
			Snippet: captureSnippet(r.Path, r.Start.Line),
		})
	}
	return findings, nil
}

// firstOWASPCategory decodifica o campo "owasp" de forma tolerante:
// algumas regras do Semgrep Registry o publicam como uma lista de
// strings (uma entrada por versão do Top 10 que a regra mapeia, ex.:
// 2021 e 2025), outras como uma única string — comportamento real
// observado rodando a ferramenta contra um projeto vulnerável de
// verdade, não documentado explicitamente pelo Semgrep. Retorna a
// primeira entrada (ou a string única), ou "" se o campo não existir —
// mesma convenção de domain.Finding.OWASPCategory pra "não se aplica".
func firstOWASPCategory(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		if len(list) > 0 {
			return list[0]
		}
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single
	}
	return ""
}

// normalizeSemgrepSeverity traduz a escala do Semgrep OSS (ERROR/WARNING/INFO)
// pra domain.Severity. O Semgrep não tem um nível CRITICAL nativo no
// engine OSS — ERROR é o mais alto que a ferramenta emite por conta
// própria (confirmado rodando contra um projeto real), então mapeia pra
// HIGH, não CRITICAL; um valor desconhecido vira LOW pelo mesmo
// raciocínio de normalizeTrivySeverity: nunca descartar um achado
// silenciosamente só porque a gravidade não pôde ser determinada.
func normalizeSemgrepSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return domain.SeverityHigh
	case "WARNING":
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

// relativeToScanDir troca o prefixo do diretório temporário efêmero pelo
// caminho relativo dentro do repositório — sem isso, File carregaria um
// "/tmp/nix-scan-XXXXXX/..." que não significa nada fora da execução
// deste scan.
func relativeToScanDir(path, scanDir string) string {
	rel := strings.TrimPrefix(path, scanDir)
	return strings.TrimPrefix(rel, "/")
}
