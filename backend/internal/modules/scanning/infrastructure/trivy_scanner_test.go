package infrastructure

import (
	"strings"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só o parsing do JSON de saída do trivy — nenhum
// chama o binário trivy de verdade (ver git_clone_test.go para a
// validação de alvo/SSRF compartilhada, e trivy_scanner.go para a
// verificação de ponta a ponta feita manualmente contra um repositório
// público real, registrada no roadmap).

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

func TestNormalizeTrivySeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"CRITICAL": domain.SeverityCritical,
		"HIGH":     domain.SeverityHigh,
		"MEDIUM":   domain.SeverityMedium,
		"LOW":      domain.SeverityLow,
		"UNKNOWN":  domain.SeverityLow,
		"garbage":  domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeTrivySeverity(input); got != want {
			t.Errorf("normalizeTrivySeverity(%q) = %q, want %q", input, got, want)
		}
	}
}
