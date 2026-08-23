package infrastructure

import (
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só a lógica pura do adapter (allowlist, extração
// de categoria OWASP das tags, severidade) — nenhum chama um daemon ZAP
// de verdade. O fluxo completo (spider real + scan ativo real +
// alertas reais) foi verificado manualmente contra um daemon real e um
// alvo deliberadamente vulnerável rodando localmente, registrado no
// roadmap.

func newTestZapScanner(allowedHosts []string) *ZapScanner {
	return NewZapScanner("http://zap:8080", "test-key", allowedHosts, 0, nil)
}

func TestValidateTarget_EmptyAllowlist_RejectsEverything(t *testing.T) {
	z := newTestZapScanner(nil)
	if _, err := z.validateTarget("https://staging.example.com/"); err == nil {
		t.Error("validateTarget with an empty allowlist = nil error, want rejection")
	}
}

func TestValidateTarget_HostNotInAllowlist_IsRejected(t *testing.T) {
	z := newTestZapScanner([]string{"staging.example.com"})
	if _, err := z.validateTarget("https://production.example.com/"); err == nil {
		t.Error("validateTarget with a host outside the allowlist = nil error, want rejection")
	}
}

func TestValidateTarget_AllowlistedHost_IsAccepted(t *testing.T) {
	z := newTestZapScanner([]string{"staging.example.com"})
	got, err := z.validateTarget("https://staging.example.com/app")
	if err != nil {
		t.Fatalf("validateTarget: %v", err)
	}
	if got != "https://staging.example.com/app" {
		t.Errorf("validateTarget = %q, want the target unchanged", got)
	}
}

func TestValidateTarget_CaseInsensitiveHostMatch(t *testing.T) {
	z := newTestZapScanner([]string{"Staging.Example.com"})
	if _, err := z.validateTarget("https://staging.example.com/"); err != nil {
		t.Errorf("validateTarget should match hosts case-insensitively: %v", err)
	}
}

func TestValidateTarget_RejectsNonHTTPScheme(t *testing.T) {
	z := newTestZapScanner([]string{"staging.example.com"})
	if _, err := z.validateTarget("ftp://staging.example.com/"); err == nil {
		t.Error("validateTarget with a non-http(s) scheme = nil error, want rejection")
	}
}

func TestZapOWASPCategory_ExtractsThe2021Tag(t *testing.T) {
	// Fixture espelhando as tags reais observadas num alerta do ZAP —
	// várias edições do OWASP Top 10 simultaneamente, só a 2021 importa
	// aqui.
	tags := map[string]string{
		"OWASP_2017_A05": "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html",
		"OWASP_2021_A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		"OWASP_2025_A01": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
		"CWE-264":        "https://cwe.mitre.org/data/definitions/264.html",
		"SYSTEMIC":       "",
	}
	got := zapOWASPCategory(tags)
	want := "A01:2021-Broken Access Control"
	if got != want {
		t.Errorf("zapOWASPCategory = %q, want %q", got, want)
	}
}

func TestZapOWASPCategory_NoOWASP2021Tag_ReturnsEmpty(t *testing.T) {
	tags := map[string]string{
		"CWE-264": "https://cwe.mitre.org/data/definitions/264.html",
	}
	if got := zapOWASPCategory(tags); got != "" {
		t.Errorf("zapOWASPCategory with no 2021 tag = %q, want empty", got)
	}
}

func TestNormalizeZapRisk(t *testing.T) {
	cases := map[string]domain.Severity{
		"High":          domain.SeverityHigh,
		"Medium":        domain.SeverityMedium,
		"Low":           domain.SeverityLow,
		"Informational": domain.SeverityLow,
		"garbage":       domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeZapRisk(input); got != want {
			t.Errorf("normalizeZapRisk(%q) = %q, want %q", input, got, want)
		}
	}
}
