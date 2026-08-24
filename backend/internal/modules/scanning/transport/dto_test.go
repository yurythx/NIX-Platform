package transport

import (
	"strings"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Pedido do usuário: "quero que esse detalhe [do achado] tenha os dados
// da ferramenta" — toolLink/toolDisplayName são funções puras, sem
// Postgres nenhum envolvido, então testadas diretamente aqui.

func TestToolDisplayName(t *testing.T) {
	cases := []struct{ scanner, want string }{
		{"trivy", "Trivy"},
		{"semgrep", "Semgrep"},
		{"sonarqube", "SonarQube"},
		{"zap", "OWASP ZAP"},
		{"um-scanner-futuro-desconhecido", "um-scanner-futuro-desconhecido"},
	}
	for _, tc := range cases {
		if got := toolDisplayName(tc.scanner); got != tc.want {
			t.Errorf("toolDisplayName(%q) = %q, want %q", tc.scanner, got, tc.want)
		}
	}
}

func TestToolLink_Sonarqube_BuildsWorkingDeepLink(t *testing.T) {
	got := toolLink("sonarqube", "python:S3776", "https://github.com/org/repo.git", "http://localhost:9001")

	wantProjectKey := domain.SonarProjectKey("https://github.com/org/repo.git")
	if !strings.HasPrefix(got, "http://localhost:9001/project/issues?") {
		t.Errorf("toolLink = %q, want it to start with the configured public URL", got)
	}
	if !strings.Contains(got, "id="+wantProjectKey) && !strings.Contains(got, "id=nix-scan_github.com_org_repo") {
		t.Errorf("toolLink = %q, want it to reference project key %q (via domain.SonarProjectKey, the SAME derivation the scanner itself used to persist there)", got, wantProjectKey)
	}
	if !strings.Contains(got, "rules=python%3AS3776") {
		t.Errorf("toolLink = %q, want the rule key (URL-escaped) in the query string", got)
	}
}

func TestToolLink_Sonarqube_EmptyWithoutPublicURLConfigured(t *testing.T) {
	// SCANNING_SONARQUBE_PUBLIC_URL vazio (não configurado) — nunca um
	// link quebrado, só ausente, mesmo princípio de SonarQubeURL vazio
	// reportando o scanner como indisponível em vez de derrubar o worker.
	if got := toolLink("sonarqube", "python:S3776", "https://github.com/org/repo.git", ""); got != "" {
		t.Errorf("toolLink with no public URL configured = %q, want empty", got)
	}
}

func TestToolLink_Trivy_LinksToNVDOnlyForCVEs(t *testing.T) {
	if got := toolLink("trivy", "CVE-2026-12345", "target", ""); got != "https://nvd.nist.gov/vuln/detail/CVE-2026-12345" {
		t.Errorf("toolLink(trivy, CVE) = %q, want the NVD detail page", got)
	}
	// Nem todo achado do Trivy é um CVE (misconfig do Dockerfile, por
	// exemplo, usa um ID próprio, não CVE-...) — sem link nesse caso, em
	// vez de um link pra NVD que não existe.
	if got := toolLink("trivy", "DS002", "target", ""); got != "" {
		t.Errorf("toolLink(trivy, non-CVE) = %q, want empty", got)
	}
}

func TestToolLink_Semgrep_LinksToRegistry(t *testing.T) {
	const rule = "go.lang.security.audit.sql-injection"
	if got := toolLink("semgrep", rule, "target", ""); got != "https://semgrep.dev/r/"+rule {
		t.Errorf("toolLink(semgrep) = %q, want the Semgrep Registry page for the rule", got)
	}
}

func TestToolLink_Zap_LinksToAlertsIndex(t *testing.T) {
	if got := toolLink("zap", "any-alert-id", "target", ""); got != "https://www.zaproxy.org/docs/alerts/" {
		t.Errorf("toolLink(zap) = %q, want the ZAP alerts index", got)
	}
}

func TestToolLink_UnknownScanner_Empty(t *testing.T) {
	if got := toolLink("um-scanner-futuro", "id", "target", "http://localhost:9001"); got != "" {
		t.Errorf("toolLink(unknown scanner) = %q, want empty", got)
	}
}
