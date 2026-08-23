package infrastructure

import (
	"encoding/json"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// Estes testes cobrem só o parsing do JSON de saída do semgrep — nenhum
// chama o binário semgrep de verdade. As fixtures abaixo espelham a
// saída real observada rodando `semgrep scan --config p/owasp-top-ten
// --json` contra um projeto Python deliberadamente vulnerável
// (OWASP/PyGoat), incluindo a inconsistência real de tipo do campo
// "owasp" entre regras da comunidade (lista vs. string única).

func TestParseSemgrepReport_ListAndStringOWASPMetadata(t *testing.T) {
	raw := []byte(`{
		"results": [
			{
				"check_id": "python.django.security.injection.command.subprocess-injection.subprocess-injection",
				"path": "/scan/challenge/views.py",
				"start": {"line": 81},
				"extra": {
					"message": "Detected subprocess function with process ID unsanitized input",
					"severity": "ERROR",
					"metadata": {"owasp": ["A01:2017 - Injection", "A03:2021 - Injection"]}
				}
			},
			{
				"check_id": "python.flask.security.audit.debug-enabled.debug-enabled",
				"path": "/scan/app.py",
				"start": {"line": 123},
				"extra": {
					"message": "Detected Flask app with debug=True",
					"severity": "WARNING",
					"metadata": {"owasp": "A06:2017 - Security Misconfiguration"}
				}
			},
			{
				"check_id": "generic.secrets.security.detected-generic-secret",
				"path": "/scan/config.py",
				"start": {"line": 5},
				"extra": {
					"message": "hardcoded secret",
					"severity": "INFO",
					"metadata": {}
				}
			}
		]
	}`)

	findings, err := parseSemgrepReport(raw, "/scan")
	if err != nil {
		t.Fatalf("parseSemgrepReport: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}

	injection := findings[0]
	if injection.Severity != domain.SeverityHigh {
		t.Errorf("ERROR severity = %q, want HIGH", injection.Severity)
	}
	if injection.OWASPCategory != "A01:2017 - Injection" {
		t.Errorf("OWASPCategory (list) = %q, want the first list entry", injection.OWASPCategory)
	}
	if injection.File != "challenge/views.py" {
		t.Errorf("File = %q, want the path relative to the scan dir", injection.File)
	}
	if injection.Line != 81 {
		t.Errorf("Line = %d, want 81", injection.Line)
	}

	misconfig := findings[1]
	if misconfig.Severity != domain.SeverityMedium {
		t.Errorf("WARNING severity = %q, want MEDIUM", misconfig.Severity)
	}
	if misconfig.OWASPCategory != "A06:2017 - Security Misconfiguration" {
		t.Errorf("OWASPCategory (single string) = %q, want the string value", misconfig.OWASPCategory)
	}

	noMetadata := findings[2]
	if noMetadata.Severity != domain.SeverityLow {
		t.Errorf("INFO severity = %q, want LOW", noMetadata.Severity)
	}
	if noMetadata.OWASPCategory != "" {
		t.Errorf("OWASPCategory (absent) = %q, want empty", noMetadata.OWASPCategory)
	}
}

func TestParseSemgrepReport_NoFindings_ReturnsEmptyNotError(t *testing.T) {
	findings, err := parseSemgrepReport([]byte(`{"results": []}`), "/scan")
	if err != nil {
		t.Fatalf("parseSemgrepReport: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none for a clean scan", findings)
	}
}

func TestFirstOWASPCategory(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"list with entries", `["A03:2021 - Injection", "A05:2025 - Injection"]`, "A03:2021 - Injection"},
		{"single string", `"A06:2017 - Security Misconfiguration"`, "A06:2017 - Security Misconfiguration"},
		{"empty list", `[]`, ""},
		{"absent", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firstOWASPCategory(json.RawMessage(tc.raw))
			if got != tc.want {
				t.Errorf("firstOWASPCategory(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeSemgrepSeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"ERROR":   domain.SeverityHigh,
		"WARNING": domain.SeverityMedium,
		"INFO":    domain.SeverityLow,
		"garbage": domain.SeverityLow,
	}
	for input, want := range cases {
		if got := normalizeSemgrepSeverity(input); got != want {
			t.Errorf("normalizeSemgrepSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRelativeToScanDir(t *testing.T) {
	cases := []struct{ path, scanDir, want string }{
		{"/scan/app.py", "/scan", "app.py"},
		{"/scan/sub/dir/app.py", "/scan", "sub/dir/app.py"},
		{"app.py", "/scan", "app.py"}, // já relativo — nada a fazer
	}
	for _, tc := range cases {
		if got := relativeToScanDir(tc.path, tc.scanDir); got != tc.want {
			t.Errorf("relativeToScanDir(%q, %q) = %q, want %q", tc.path, tc.scanDir, got, tc.want)
		}
	}
}
