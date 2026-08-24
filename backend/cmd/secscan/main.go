// Command secscan implementa a Fase 8 do roadmap de segurança
// (docs/roadmap-secops-orchestrator.md): uma interface única pra rodar os
// mesmos scanners do módulo scanning (backend/internal/modules/scanning)
// contra um repositório JÁ NO DISCO — localmente, na máquina de um
// desenvolvedor, ou dentro do CI depois de um `actions/checkout` — sem
// precisar do resto da plataforma rodando (sem Postgres, RabbitMQ,
// Keycloak; só os binários trivy/semgrep no PATH). Por isso este comando
// deliberadamente NÃO reaproveita internal/app.NewDependencies (que exige
// a config inteira do backend) nem o padrão job+outbox+worker — é um
// binário standalone, síncrono, pensado pra rodar uma vez e sair com um
// exit code que um pipeline de CI consegue usar como gate.
//
// Escopo desta fase: só trivy e semgrep — os dois únicos scanners que
// rodam contra um diretório local sem depender de um servidor externo já
// no ar (sonarqube exige um servidor SonarQube rodando e credenciais; zap
// nem se aplica, ataca um serviço vivo, não lê um diretório).
//
//	nix-secscan scan --repo . --scanners trivy,semgrep --fail-on HIGH
//
// Uso: docs/roadmap-secops-orchestrator.md (Fase 8) e o comentário de
// runScan abaixo documentam as flags. "Unifica" no sentido do roadmap:
// dá um único comando que já existia como 4 jobs de CI separados
// (govulncheck, npm audit, Trivy, gitleaks/CodeQL) pra rodar contra —
// sem substituir nenhum deles, ver ci.yml.
//
// --repo precisa apontar pra dentro de um repositório git de verdade (com
// .git, dono do processo que roda) — verificado rodando de propósito
// contra um checkout sem isso: sem git funcionando, o semgrep (por
// padrão, --use-git-ignore) não consegue distinguir arquivo
// gitignorado/rastreado de qualquer outro, e escaneia até artefato de
// build tipo frontend/.next ou node_modules, gerando ruído de código
// gerado/minificado em vez de código-fonte de verdade. `actions/checkout`
// no CI e um clone local normal sempre satisfazem isso — não é uma
// exigência que vale a pena contornar com flags de exclude extras aqui.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// exit codes: 0 nenhum achado atingiu --fail-on; 1 pelo menos um achado
// atingiu; 2 erro de uso/execução (scanner não rodou, flag inválida,
// ...) — a mesma convenção de três níveis que ferramentas de scanning de
// linha de comando já usam (ex.: o próprio trivy com --exit-code).
const (
	exitOK          = 0
	exitFindings    = 1
	exitUsageOrTool = 2
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nix-secscan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "usage: nix-secscan scan [flags]")
		fs.PrintDefaults()
		return exitUsageOrTool
	}

	var (
		repo          = fs.String("repo", ".", "caminho do repositório já no disco a escanear")
		scannersFlag  = fs.String("scanners", "trivy,semgrep", "lista separada por vírgula de scanners a rodar (trivy, semgrep)")
		trivyPath     = fs.String("trivy-path", "trivy", "caminho do binário trivy")
		semgrepPath   = fs.String("semgrep-path", "semgrep", "caminho do binário semgrep")
		semgrepConfig = fs.String("semgrep-config", "", "ruleset do Semgrep Registry (vazio usa o default, p/owasp-top-ten)")
		failOn        = fs.String("fail-on", "HIGH", "severidade mínima que faz o comando sair com exit code 1 (CRITICAL, HIGH, MEDIUM, LOW, ou NONE para nunca falhar)")
		jsonOutput    = fs.Bool("json", false, "imprime os achados como JSON em vez de uma tabela legível")
		timeout       = fs.Duration("timeout", 5*time.Minute, "tempo máximo total (todos os scanners juntos)")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsageOrTool
	}

	scannerNames := splitAndTrim(*scannersFlag)
	if len(scannerNames) == 0 {
		fmt.Fprintln(stderr, "nix-secscan: --scanners must list at least one scanner")
		return exitUsageOrTool
	}

	threshold, err := parseFailOn(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "nix-secscan:", err)
		return exitUsageOrTool
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	findings, toolErr := runScanners(scanCtx, scannerNames, *repo, *trivyPath, *semgrepPath, *semgrepConfig, logger)
	if toolErr != nil {
		fmt.Fprintln(stderr, "nix-secscan:", toolErr)
		return exitUsageOrTool
	}

	if *jsonOutput {
		_ = json.NewEncoder(stdout).Encode(findings)
	} else {
		printReport(stdout, findings)
	}

	if hasFindingAtOrAbove(findings, threshold) {
		return exitFindings
	}
	return exitOK
}

// localScanner é o subconjunto de domain.CodeScanner que este comando
// usa — só os scanners que sabem escanear um diretório já no disco (ver
// TrivyScanner.ExecuteLocal/SemgrepScanner.ExecuteLocal) satisfazem esta
// interface; o próprio domain.CodeScanner (Execute, que clona de uma URL
// remota) não se aplica aqui.
type localScanner interface {
	Name() string
	ExecuteLocal(ctx context.Context, dir string) ([]domain.Finding, error)
}

// runScanners roda cada scanner pedido, em sequência — ao contrário do
// scanning.Service.ProcessScanJob (Fase 7), que roda em paralelo. Um CLI
// de linha de comando se beneficia mais de saída previsível e fácil de
// ler (achados de um scanner nunca intercalados com o log de outro) do
// que do ganho de tempo de rodar dois processos pesados em paralelo numa
// única máquina de desenvolvedor/runner de CI — decisão deliberada, não
// uma limitação técnica.
func runScanners(ctx context.Context, scannerNames []string, repo, trivyPath, semgrepPath, semgrepConfig string, logger *slog.Logger) ([]domain.Finding, error) {
	available := map[string]localScanner{
		// serviceURL/workspaceDir vazios: secscan só chama ExecuteLocal
		// (abaixo), nunca Execute — os dois parâmetros são só do caminho
		// containerizado de produção (ver trivy_scanner.go), irrelevantes
		// aqui.
		infrastructure.TrivyScannerName:   infrastructure.NewTrivyScanner(trivyPath, "", "", 0, logger),
		infrastructure.SemgrepScannerName: infrastructure.NewSemgrepScanner(semgrepPath, semgrepConfig, 0, logger),
	}

	var all []domain.Finding
	for _, name := range scannerNames {
		scanner, ok := available[name]
		if !ok {
			return nil, fmt.Errorf("scanner %q is not supported by nix-secscan (only trivy/semgrep scan a local directory — sonarqube needs a running server, zap attacks a live service)", name)
		}
		findings, err := scanner.ExecuteLocal(ctx, repo)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, findings...)
	}
	return all, nil
}

// severityRank ordena da mais grave pra menos grave — usado tanto pra
// ordenar o relatório quanto pra decidir --fail-on.
var severityRank = map[domain.Severity]int{
	domain.SeverityCritical: 0,
	domain.SeverityHigh:     1,
	domain.SeverityMedium:   2,
	domain.SeverityLow:      3,
}

// parseFailOn valida o valor de --fail-on. "NONE" (case-insensitive)
// desativa o gate — nix-secscan sempre sai 0, útil pra rodar só como
// relatório informativo sem quebrar um pipeline.
func parseFailOn(s string) (domain.Severity, error) {
	if strings.EqualFold(s, "NONE") {
		return "", nil
	}
	sev := domain.Severity(strings.ToUpper(s))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("--fail-on must be one of CRITICAL, HIGH, MEDIUM, LOW, NONE, got %q", s)
	}
	return sev, nil
}

// hasFindingAtOrAbove reporta se algum achado é igual ou mais grave que
// threshold. threshold vazio (--fail-on NONE) nunca dispara.
func hasFindingAtOrAbove(findings []domain.Finding, threshold domain.Severity) bool {
	if threshold == "" {
		return false
	}
	thresholdRank := severityRank[threshold]
	for _, f := range findings {
		if severityRank[f.Severity] <= thresholdRank {
			return true
		}
	}
	return false
}

// printReport imprime achados ordenados por severidade (mais grave
// primeiro), formato de tabela simples — pensado pra ser lido por uma
// pessoa no terminal, não parseado (para isso, --json).
func printReport(w io.Writer, findings []domain.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "nix-secscan: no findings")
		return
	}

	sorted := make([]domain.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank[sorted[i].Severity] < severityRank[sorted[j].Severity]
	})

	counts := map[domain.Severity]int{}
	for _, f := range sorted {
		counts[f.Severity]++
		location := f.File
		if f.Line > 0 {
			location = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "[%s] %s %s — %s\n", f.Severity, f.ID, location, f.Description)
	}
	fmt.Fprintf(w, "\nnix-secscan: %d finding(s) — CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d\n",
		len(sorted), counts[domain.SeverityCritical], counts[domain.SeverityHigh], counts[domain.SeverityMedium], counts[domain.SeverityLow])
}

// splitAndTrim divide uma lista separada por vírgula descartando espaço
// em volta e entradas vazias — mesmo helper que
// internal/platform/config.splitAndTrim, reimplementado aqui porque este
// comando é deliberadamente standalone (não importa internal/platform/config,
// que puxaria a validação de config da plataforma inteira).
func splitAndTrim(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
