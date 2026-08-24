package application

import (
	"path/filepath"
	"strings"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// NoiseFilterFlagKey é a feature flag (configflags.Store, mesmo mecanismo
// que já liga/desliga diario_oficial_scraping_enabled) que controla se o
// filtro de ruído por caminho (Fase 13) é aplicado às listagens de
// achados — DESLIGADA por padrão (ver migrations/000020): um achado de
// segredo commitado dentro de um arquivo de teste ainda É um segredo
// real (Gitleaks, por design, não distingue "teste" de "produção"; um
// .env.example com uma chave de exemplo que por acaso é uma chave de
// verdade já vazada é exatamente o tipo de coisa que não deveria sumir
// silenciosamente) — mostrar tudo é o comportamento seguro, filtrar é
// opt-in explícito de quem administra a instância.
const NoiseFilterFlagKey = "scanning_noise_filter_enabled"

// defaultNoiseFilterPatterns é usado quando a flag está ligada mas
// ScanningConfig.NoiseFilterPatterns não foi configurado — um ponto de
// partida razoável, nunca o único jeito de configurar isto (ver
// SCANNING_NOISE_FILTER_PATTERNS).
var defaultNoiseFilterPatterns = []string{
	"/tests/",
	"/test/",
	"/fixtures/",
	"/testdata/",
	"*_test.go",
	".env.example",
}

// matchesNoisePattern decide se file bate com pattern — dois modos,
// escolhidos pela presença de "*" no próprio padrão:
//   - sem "*": substring match contra o caminho INTEIRO (ex.: "/tests/"
//     bate em "backend/tests/fixture.go", em qualquer profundidade —
//     nunca precisa ancorar no início nem no fim).
//   - com "*": glob (filepath.Match, suporta só um nível — sem "**"
//     recursivo) contra só o NOME do arquivo (ex.: "*_test.go" bate em
//     "handler_test.go" não importa o diretório).
//
// Um padrão malformado (filepath.Match retorna ErrBadPattern) nunca
// derruba a listagem inteira — só não bate com nada, silenciosamente.
func matchesNoisePattern(file, pattern string) bool {
	if file == "" || pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return strings.Contains(file, pattern)
	}
	matched, err := filepath.Match(pattern, filepath.Base(file))
	return err == nil && matched
}

// isNoise reporta se file bate com QUALQUER um dos patterns.
func isNoise(file string, patterns []string) bool {
	for _, p := range patterns {
		if matchesNoisePattern(file, p) {
			return true
		}
	}
	return false
}

// filterNoise remove de findings todo achado cujo File bate com algum
// padrão de patterns (ou defaultNoiseFilterPatterns, se patterns estiver
// vazio) — chamada só depois de confirmar que NoiseFilterFlagKey está
// ligada (ver Service.applyNoiseFilter); nunca aqui dentro, pra esta
// função continuar pura e testável sem depender de configflags.Store nem
// de contexto nenhum. Um achado sem File (ex.: um alerta de DAST do ZAP,
// que não é sobre um arquivo) nunca é filtrado — isNoise/
// matchesNoisePattern já devolvem false pra file vazio.
func filterNoise(findings []domain.PersistedFinding, patterns []string) []domain.PersistedFinding {
	if len(patterns) == 0 {
		patterns = defaultNoiseFilterPatterns
	}
	out := make([]domain.PersistedFinding, 0, len(findings))
	for _, f := range findings {
		if !isNoise(f.File, patterns) {
			out = append(out, f)
		}
	}
	return out
}
