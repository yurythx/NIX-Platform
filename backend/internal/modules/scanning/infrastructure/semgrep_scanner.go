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
type SemgrepScanner struct {
	semgrepPath  string
	config       string
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// DefaultSemgrepConfig é o ruleset do Semgrep Registry usado quando
// nenhum outro é configurado.
const DefaultSemgrepConfig = "p/owasp-top-ten"

// NewSemgrepScanner constrói o adapter. semgrepPath é o caminho do
// binário `semgrep` (normalmente só "semgrep", resolvido via PATH).
func NewSemgrepScanner(semgrepPath, config string, cloneTimeout time.Duration, logger *slog.Logger) *SemgrepScanner {
	if config == "" {
		config = DefaultSemgrepConfig
	}
	return &SemgrepScanner{semgrepPath: semgrepPath, config: config, cloneTimeout: cloneTimeout, logger: logger}
}

var _ domain.CodeScanner = (*SemgrepScanner)(nil)

func (s *SemgrepScanner) Name() string { return SemgrepScannerName }

// Execute clona o alvo (raso, um branch só) via cloneShallow e roda
// `semgrep scan` no diretório resultante — sempre removido ao final,
// sucesso ou erro.
func (s *SemgrepScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	dir, cleanup, err := cloneShallow(ctx, target, s.cloneTimeout, s.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return s.scanSource(ctx, dir)
}

func (s *SemgrepScanner) scanSource(ctx context.Context, dir string) ([]domain.Finding, error) {
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
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: semgrep: scan failed: %s", firstLine(stderr.String())))
	}
	return parseSemgrepReport(stdout.Bytes(), dir)
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
