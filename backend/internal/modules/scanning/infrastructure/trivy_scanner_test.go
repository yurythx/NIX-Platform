package infrastructure

import (
	"strings"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só a lógica pura do adapter (validação de alvo,
// parsing do JSON do trivy) — nenhum deles chama os binários git/trivy de
// verdade, então rodam em qualquer ambiente, inclusive CI sem o trivy
// instalado.

func TestParseTarget_RejectsNonHTTPS(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git",
		"--upload-pack=/bin/sh",
		"",
		"http://example.com/repo.git", // http simples, não https
	}
	for _, target := range cases {
		if _, _, err := parseTarget(target); err == nil {
			t.Errorf("parseTarget(%q) = nil error, want rejection", target)
		}
	}
}

func TestParseTarget_AcceptsHTTPSWithOptionalRef(t *testing.T) {
	repoURL, ref, err := parseTarget("https://github.com/yurythx/nix-platform.git#main")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	if repoURL != "https://github.com/yurythx/nix-platform.git" {
		t.Errorf("repoURL = %q, want the URL without the ref suffix", repoURL)
	}
	if ref != "main" {
		t.Errorf("ref = %q, want %q", ref, "main")
	}

	repoURL, ref, err = parseTarget("https://github.com/yurythx/nix-platform.git")
	if err != nil {
		t.Fatalf("parseTarget (no ref): %v", err)
	}
	if ref != "" {
		t.Errorf("ref = %q, want empty when the target has no #ref suffix", ref)
	}
	if repoURL != "https://github.com/yurythx/nix-platform.git" {
		t.Errorf("repoURL = %q, want the full target", repoURL)
	}
}

func TestParseTarget_RejectsMaliciousRef(t *testing.T) {
	cases := []string{
		"--upload-pack=/bin/sh",
		"main; rm -rf /",
		"main space",
	}
	for _, ref := range cases {
		if _, _, err := parseTarget("https://github.com/org/repo.git#" + ref); err == nil {
			t.Errorf("parseTarget with ref %q = nil error, want rejection", ref)
		}
	}
}

func TestParseTrivyReport_VulnerabilitiesAndMisconfigurations(t *testing.T) {
	raw := []byte(`{
		"Results": [
			{
				"Target": "go.mod",
				"Vulnerabilities": [
					{"VulnerabilityID": "CVE-2026-0001", "PkgName": "example.com/dep", "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1", "Severity": "CRITICAL", "Title": "dependência vulnerável"}
				]
			},
			{
				"Target": "Dockerfile",
				"Misconfigurations": [
					{"ID": "DS002", "Title": "usuário root", "Message": "container roda como root", "Severity": "HIGH", "CauseMetadata": {"StartLine": 3}}
				]
			}
		]
	}`)

	findings, err := parseTrivyReport(raw)
	if err != nil {
		t.Fatalf("parseTrivyReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}

	vuln := findings[0]
	if vuln.ID != "CVE-2026-0001" || vuln.Severity != domain.SeverityCritical || vuln.OWASPCategory != "A06:2021-Vulnerable and Outdated Components" {
		t.Errorf("vuln finding = %+v, unexpected fields", vuln)
	}
	if !strings.Contains(vuln.Description, "example.com/dep@1.0.0") {
		t.Errorf("vuln description = %q, want it to mention the package/version", vuln.Description)
	}

	misconf := findings[1]
	if misconf.ID != "DS002" || misconf.Severity != domain.SeverityHigh || misconf.OWASPCategory != "A05:2021-Security Misconfiguration" {
		t.Errorf("misconfig finding = %+v, unexpected fields", misconf)
	}
	if misconf.Line != 3 {
		t.Errorf("misconfig line = %d, want 3", misconf.Line)
	}
}

func TestParseTrivyReport_NoFindings_ReturnsEmptyNotError(t *testing.T) {
	findings, err := parseTrivyReport([]byte(`{"Results": []}`))
	if err != nil {
		t.Fatalf("parseTrivyReport: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none for a clean scan", findings)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"CRITICAL": domain.SeverityCritical,
		"HIGH":     domain.SeverityHigh,
		"MEDIUM":   domain.SeverityMedium,
		"LOW":      domain.SeverityLow,
		"UNKNOWN":  domain.SeverityLow,
		"garbage":  domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeSeverity(input); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}
