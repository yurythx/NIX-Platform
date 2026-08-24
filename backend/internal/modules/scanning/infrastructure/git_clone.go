// Package infrastructure implementa os domain.CodeScanner/domain.Repository
// do módulo scanning contra ferramentas reais (trivy, semgrep) e o
// PostgreSQL.
package infrastructure

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

// snippetContext é quantas linhas antes/depois de Finding.Line
// captureSnippet inclui — mesmo valor "~5 linhas" que o roadmap pede
// (Fase 12).
const snippetContext = 5

// captureSnippet lê até snippetContext linhas antes/depois de line
// (1-indexed) de path — best-effort: qualquer falha (arquivo ausente,
// linha fora do intervalo, path vazio, ...) devolve "", nunca um erro que
// faria o scan inteiro falhar só porque um snippet cosmético não pôde ser
// capturado. Chamado no momento do parsing do resultado de cada scanner
// (Trivy/Semgrep — ver trivy_scanner.go/semgrep_scanner.go), enquanto o
// diretório clonado/extraído ainda existe, ANTES do cleanup — nunca
// depois, sob demanda: a proposta original pedia um endpoint
// `GET /api/file-content` pra ler o arquivo do disco a qualquer momento,
// incompatível com a decisão de nunca manter um checkout persistente
// (ver docs/roadmap-secops-orchestrator.md, Fase 12).
//
// GitleaksScanner deliberadamente NÃO usa esta função — um achado de
// segredo já grava seu próprio Snippet mascarado (ver
// gitleaks_scanner.go's maskSecretSnippet), nunca as linhas reais do
// arquivo: mostrar contexto de verdade ao redor da linha revelaria o
// segredo em claro (a própria linha do achado), exatamente o vazamento
// que o mascaramento existe pra evitar.
func captureSnippet(path string, line int) string {
	if path == "" || line <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	idx := line - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}

	start := idx - snippetContext
	if start < 0 {
		start = 0
	}
	end := idx + snippetContext + 1
	if end > len(lines) {
		end = len(lines)
	}

	// Cada linha ganha o número REAL do arquivo como prefixo ("5: ...") —
	// sem isso, o snippet começando em qualquer lugar (Line pode estar
	// perto do início/fim do arquivo, onde snippetContext é truncado)
	// deixaria a UI sem como saber qual linha destacar como "a do
	// achado" nem mostrar a numeração real do arquivo. O frontend faz o
	// parsing inverso desse prefixo pra decidir o destaque (ver
	// FindingsTable.tsx).
	numbered := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		numbered = append(numbered, fmt.Sprintf("%d: %s", i+1, lines[i]))
	}
	return strings.Join(numbered, "\n")
}

// refPattern restringe o que aceitamos depois de "#" no alvo a algo que
// só pode ser um nome de branch/tag git — nunca uma flag (não pode
// começar com "-") nem conter espaço/metacaractere.
var refPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// parseGitTarget separa "<url-git-https>[#branch-ou-tag]" e valida os dois
// pedaços. Só aceita https:// deliberadamente: file:// permitiria ler
// qualquer caminho local acessível ao processo do worker (leitura
// arbitrária de arquivo disfarçada de "clonar um repositório"), e
// ssh://.../git@... exigiria gerenciar uma chave privada dentro do
// worker — nenhum dos dois vale o risco/complexidade extra por ora.
// Exigir o prefixo "https://" também garante, por construção, que o valor
// nunca começa com "-": mesmo passado como argv separado (nunca via
// shell), um valor começando com "-" poderia ser interpretado pelo git
// como uma flag em vez de uma URL — injeção de argumento, não de shell,
// mas real do mesmo jeito com os/exec.
func parseGitTarget(target string) (repoURL, ref string, err error) {
	repoURL, ref, _ = strings.Cut(target, "#")
	if !strings.HasPrefix(repoURL, "https://") {
		return "", "", fmt.Errorf("scanning: target must be an https:// git URL, got %q", target)
	}
	if ref != "" && !refPattern.MatchString(ref) {
		return "", "", fmt.Errorf("scanning: target ref %q is not a valid branch/tag name", ref)
	}
	return repoURL, ref, nil
}

// lookupIP é indireção de teste sobre net.LookupIP — permite que os
// testes controlem a resposta de DNS sem depender de rede real nem de um
// hostname específico continuar resolvendo pro mesmo IP para sempre.
var lookupIP = net.LookupIP

// validateHost resolve o host de repoURL e rejeita se qualquer IP
// resolvido for privado/loopback/link-local/não especificado/multicast —
// defesa em profundidade contra SSRF via uma URL controlada pelo
// chamador (quem tem scanning:manage poderia, de outra forma, apontar o
// `git clone` do worker pra um host só alcançável internamente).
//
// É uma checagem de melhor esforço, não uma proteção completa: o próprio
// `git` (um processo separado, cuja pilha de rede este código não
// controla) resolve o hostname de novo quando de fato conecta — uma
// resposta de DNS que muda entre esta checagem e a conexão do git (DNS
// rebinding) passaria por aqui. Aceito por ora dado que quem chama já
// precisa ter scanning:manage, o mesmo nível de confiança de qualquer
// outra ação administrativa de integração nesta plataforma.
func validateHost(repoURL string) error {
	u, err := url.Parse(repoURL)
	if err != nil {
		return fmt.Errorf("scanning: parse target URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("scanning: target URL has no host")
	}

	ips, err := lookupIP(host)
	if err != nil {
		return fmt.Errorf("scanning: resolve target host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isPrivateOrReserved(ip) {
			return fmt.Errorf("scanning: target host %q resolves to a private/internal address, refusing to clone", host)
		}
	}
	return nil
}

func isPrivateOrReserved(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// cloneShallow valida target (formato + SSRF via validateHost) e clona um
// branch/tag só (raso) para um novo diretório temporário — o ponto de
// entrada único que todo CodeScanner baseado em código-fonte usa (hoje:
// TrivyScanner, SemgrepScanner, SonarScanner), para que a validação de
// alvo e a defesa de SSRF vivam num único lugar e nunca divirjam entre
// scanners.
//
// baseDir é onde esse diretório temporário nasce — "" usa o padrão do
// próprio SO (os.MkdirTemp, o comportamento de sempre). Um scanner
// containerizado (§ Containerização — ver docs/roadmap-secops-
// orchestrator.md; hoje só TrivyScanner) passa o caminho do volume
// compartilhado com seu sidecar (`/workspace`, ScanningConfig.
// ScanningWorkspaceDir) em vez de "", pra que o diretório clonado fique
// visível também no container do sidecar, não só no do worker.
//
// Quem chama é responsável por invocar o cleanup retornado (sempre não
// nil quando err é nil) assim que terminar de usar o diretório — nunca
// deixa código de terceiros no disco do worker além do necessário.
func cloneShallow(ctx context.Context, target string, cloneTimeout time.Duration, baseDir string, logger *slog.Logger) (dir string, cleanup func(), err error) {
	repoURL, ref, err := parseGitTarget(target)
	if err != nil {
		return "", nil, apperrors.Validation(err.Error())
	}
	if err := validateHost(repoURL); err != nil {
		return "", nil, apperrors.Validation(err.Error())
	}

	dir, err = os.MkdirTemp(baseDir, "nix-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("scanning: create temp dir: %w", err)
	}
	cleanup = func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			logger.Warn("scanning: failed to clean up temp dir", slog.String("dir", dir), slog.Any("error", rmErr))
		}
	}

	cloneCtx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()
	if err := runGitClone(cloneCtx, repoURL, ref, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

func runGitClone(ctx context.Context, repoURL, ref, dir string) error {
	args := []string{"clone", "--depth", "1", "--single-branch"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, repoURL, dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: git clone failed: %s", extractErrorLine(stderr.String())))
	}
	return nil
}

// firstLine evita despejar um corpo de resposta HTTP de várias linhas
// (potencialmente JSON, potencialmente grande) inteiro numa mensagem de
// erro voltada ao cliente — só a primeira linha, o resto fica só no log.
// Usado só pelos dois casos de corpo de resposta HTTP (sonar_scanner.go,
// zap_scanner.go): ali a "primeira linha" já costuma ser o próprio corpo
// inteiro (JSON de uma linha só) ou algo razoável, sem o problema abaixo.
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

// extractErrorLine escolhe a linha mais útil do stderr de um subprocesso
// (git, trivy, semgrep, sonar-scanner) para reportar num erro voltado ao
// cliente HTTP. `git clone`, em especial, sempre imprime
// "Cloning into '...'..." como a PRIMEIRA linha mesmo quando falha, com o
// motivo real ("fatal: ...") numa linha seguinte — usar só a primeira
// linha (como firstLine faz) reportaria sempre essa linha inútil e nunca
// o motivo de verdade. Preferimos a primeira linha que pareça mesmo um
// erro (contém "fatal:" ou "error:", sem diferenciar maiúsculas de
// minúsculas — cobre a saída de git, trivy e semgrep); na ausência de
// uma, a ÚLTIMA linha não vazia costuma ser a mais específica (mensagens
// de progresso/contexto vêm antes, a causa raiz por último).
func extractErrorLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "fatal:") || strings.Contains(lower, "error:") {
			return line
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return "unknown error"
}
