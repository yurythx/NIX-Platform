package infrastructure

import (
	"fmt"
	"net"
	"testing"
)

// Estes testes cobrem só a lógica pura compartilhada por todo scanner
// baseado em clonar um repositório (validação de alvo, defesa de SSRF) —
// nenhum deles chama os binários git/trivy/semgrep de verdade, então
// rodam em qualquer ambiente, inclusive CI sem nenhum deles instalado.

func TestParseGitTarget_RejectsNonHTTPS(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git",
		"--upload-pack=/bin/sh",
		"",
		"http://example.com/repo.git", // http simples, não https
	}
	for _, target := range cases {
		if _, _, err := parseGitTarget(target); err == nil {
			t.Errorf("parseGitTarget(%q) = nil error, want rejection", target)
		}
	}
}

func TestParseGitTarget_AcceptsHTTPSWithOptionalRef(t *testing.T) {
	repoURL, ref, err := parseGitTarget("https://github.com/yurythx/nix-platform.git#main")
	if err != nil {
		t.Fatalf("parseGitTarget: %v", err)
	}
	if repoURL != "https://github.com/yurythx/nix-platform.git" {
		t.Errorf("repoURL = %q, want the URL without the ref suffix", repoURL)
	}
	if ref != "main" {
		t.Errorf("ref = %q, want %q", ref, "main")
	}

	repoURL, ref, err = parseGitTarget("https://github.com/yurythx/nix-platform.git")
	if err != nil {
		t.Fatalf("parseGitTarget (no ref): %v", err)
	}
	if ref != "" {
		t.Errorf("ref = %q, want empty when the target has no #ref suffix", ref)
	}
	if repoURL != "https://github.com/yurythx/nix-platform.git" {
		t.Errorf("repoURL = %q, want the full target", repoURL)
	}
}

func TestParseGitTarget_RejectsMaliciousRef(t *testing.T) {
	cases := []string{
		"--upload-pack=/bin/sh",
		"main; rm -rf /",
		"main space",
	}
	for _, ref := range cases {
		if _, _, err := parseGitTarget("https://github.com/org/repo.git#" + ref); err == nil {
			t.Errorf("parseGitTarget with ref %q = nil error, want rejection", ref)
		}
	}
}

// stubLookup instala uma resposta de DNS falsa para um único hostname
// durante o teste, restaurando o lookupIP real (net.LookupIP) no
// t.Cleanup — nenhum teste aqui depende de resolução de DNS de verdade
// nem de um hostname continuar resolvendo pro mesmo IP para sempre.
func stubLookup(t *testing.T, host string, ips []net.IP, err error) {
	t.Helper()
	original := lookupIP
	lookupIP = func(h string) ([]net.IP, error) {
		if h != host {
			t.Fatalf("unexpected lookup for host %q, want %q", h, host)
		}
		return ips, err
	}
	t.Cleanup(func() { lookupIP = original })
}

func TestValidateHost_RejectsPrivateAndReservedTargets(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
	}{
		{"loopback", net.ParseIP("127.0.0.1")},
		{"private class A", net.ParseIP("10.0.0.5")},
		{"private class B", net.ParseIP("172.16.0.5")},
		{"private class C", net.ParseIP("192.168.1.5")},
		{"link-local", net.ParseIP("169.254.169.254")}, // ex.: endpoint de metadados de nuvem
		{"unspecified", net.ParseIP("0.0.0.0")},
		{"IPv6 loopback", net.ParseIP("::1")},
		{"IPv6 unique local", net.ParseIP("fd00::1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubLookup(t, "internal.example.com", []net.IP{tc.ip}, nil)
			if err := validateHost("https://internal.example.com/repo.git"); err == nil {
				t.Errorf("validateHost with a %s address = nil error, want rejection", tc.name)
			}
		})
	}
}

func TestValidateHost_AcceptsPublicTarget(t *testing.T) {
	stubLookup(t, "github.com", []net.IP{net.ParseIP("140.82.112.3")}, nil)
	if err := validateHost("https://github.com/org/repo.git"); err != nil {
		t.Errorf("validateHost with a public address: %v, want no error", err)
	}
}

func TestValidateHost_ResolutionFailure_IsRejected(t *testing.T) {
	stubLookup(t, "does-not-resolve.example.com", nil, fmt.Errorf("no such host"))
	if err := validateHost("https://does-not-resolve.example.com/repo.git"); err == nil {
		t.Error("validateHost with a failed DNS lookup = nil error, want rejection")
	}
}

// Formatos reproduzidos de verdade contra os binários reais (não
// inventados): "git clone" contra um repositório inexistente sempre
// imprime "Cloning into '...'..." na primeira linha mesmo ao falhar, com
// o motivo real numa linha seguinte — o bug que extractErrorLine existe
// pra corrigir (firstLine reportava só a primeira linha inútil). trivy e
// semgrep, na falha de scan em si (não de clone), já imprimem uma única
// linha só — extractErrorLine precisa continuar funcionando igual pra
// esses casos.
func TestExtractErrorLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "git clone: motivo real na segunda linha, não na primeira",
			in:   "Cloning into '/tmp/nix-scan-4127283254'...\nfatal: could not read Username for 'https://github.com': terminal prompts disabled\n",
			want: "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
		},
		{
			name: "trivy: já vem numa linha só",
			in:   "2026-08-24T08:16:32-04:00\tFATAL\tFatal error\trun error: fs scan error: scan error: scan failed: failed analysis: analyze with traversal: walk dir error: unknown error with /this/path/does/not/exist: lstat /this/path/does/not/exist: no such file or directory\n",
			want: "2026-08-24T08:16:32-04:00\tFATAL\tFatal error\trun error: fs scan error: scan error: scan failed: failed analysis: analyze with traversal: walk dir error: unknown error with /this/path/does/not/exist: lstat /this/path/does/not/exist: no such file or directory",
		},
		{
			name: "semgrep: já vem numa linha só",
			in:   "[ERROR] Invalid scanning root: /this/path/does/not/exist\n",
			want: "[ERROR] Invalid scanning root: /this/path/does/not/exist",
		},
		{
			name: "sonar-scanner: já vem numa linha só",
			in:   "ERROR Failed to query server version: java.net.ConnectException\n",
			want: "ERROR Failed to query server version: java.net.ConnectException",
		},
		{
			name: "sem linha com fatal:/error:, cai pra última linha não vazia",
			in:   "some progress line\nanother progress line\nthe actual reason it broke\n",
			want: "the actual reason it broke",
		},
		{
			name: "stderr vazio",
			in:   "",
			want: "unknown error",
		},
		{
			name: "só espaço em branco",
			in:   "   \n\n  ",
			want: "unknown error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractErrorLine(tc.in); got != tc.want {
				t.Errorf("extractErrorLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
