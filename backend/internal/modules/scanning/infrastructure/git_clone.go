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
// TrivyScanner, SemgrepScanner), para que a validação de alvo e a defesa
// de SSRF vivam num único lugar e nunca divirjam entre scanners.
//
// Quem chama é responsável por invocar o cleanup retornado (sempre não
// nil quando err é nil) assim que terminar de usar o diretório — nunca
// deixa código de terceiros no disco do worker além do necessário.
func cloneShallow(ctx context.Context, target string, cloneTimeout time.Duration, logger *slog.Logger) (dir string, cleanup func(), err error) {
	repoURL, ref, err := parseGitTarget(target)
	if err != nil {
		return "", nil, apperrors.Validation(err.Error())
	}
	if err := validateHost(repoURL); err != nil {
		return "", nil, apperrors.Validation(err.Error())
	}

	dir, err = os.MkdirTemp("", "nix-scan-*")
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
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: git clone failed: %s", firstLine(stderr.String())))
	}
	return nil
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
