package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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

// fakeZapDaemon simula só o suficiente da API real do ZAP (action/scan +
// view/status pra spider/ascan, view/alerts) pra exercitar
// ExecuteWithProgress de ponta a ponta sem depender de um daemon
// verdadeiro — status "100" já na PRIMEIRA checagem, de propósito: o
// loop real de runModule dorme 5s entre polls (time.After hardcoded),
// então terminar no primeiro poll é o que mantém este teste rápido, sem
// precisar de um clock injetável só pra isso.
func fakeZapDaemon(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/JSON/spider/action/scan/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"scan": "0"})
	})
	mux.HandleFunc("/JSON/spider/view/status/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "100"})
	})
	mux.HandleFunc("/JSON/ascan/action/scan/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"scan": "0"})
	})
	mux.HandleFunc("/JSON/ascan/view/status/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "100"})
	})
	mux.HandleFunc("/JSON/core/view/alerts/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"alerts": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestZapScanner_ExecuteWithProgress_ReportsSpiderAndAscanPhases: pedido
// do usuário — "quero saber em tempo real como está rodando o ataque".
// Confirma que report recebe uma string por fase (spider, depois ascan),
// nunca as duas misturadas nem faltando uma — sem isto, um scan real de
// minutos aparecia "rodando" parado do início ao fim.
func TestZapScanner_ExecuteWithProgress_ReportsSpiderAndAscanPhases(t *testing.T) {
	srv := fakeZapDaemon(t)
	z := NewZapScanner(srv.URL, "test-key", []string{"example.com"}, time.Minute, nil)

	var mu sync.Mutex
	var reports []string
	_, err := z.ExecuteWithProgress(context.Background(), "https://example.com/", func(detail string) {
		mu.Lock()
		reports = append(reports, detail)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("ExecuteWithProgress: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("reports = %v, want exactly 2 (uma checagem de spider, uma de ascan)", reports)
	}
	if reports[0] != "varredura (spider): 100%" {
		t.Errorf("reports[0] = %q, want a fase de spider", reports[0])
	}
	if reports[1] != "ataque ativo: 100%" {
		t.Errorf("reports[1] = %q, want a fase de ataque ativo", reports[1])
	}
}

// TestZapScanner_Execute_WorksWithoutAReporter: Execute (o método que só
// satisfaz domain.CodeScanner, sem sub-progresso) continua funcionando
// normalmente — internamente delega pra ExecuteWithProgress com um
// reporter no-op, nunca lança nem exige um report não-nulo de quem
// chama.
func TestZapScanner_Execute_WorksWithoutAReporter(t *testing.T) {
	srv := fakeZapDaemon(t)
	z := NewZapScanner(srv.URL, "test-key", []string{"example.com"}, time.Minute, nil)

	if _, err := z.Execute(context.Background(), "https://example.com/"); err != nil {
		t.Fatalf("Execute: %v", err)
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
