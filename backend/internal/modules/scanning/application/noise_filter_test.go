package application

import (
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

func TestMatchesNoisePattern_SubstringPatterns(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		pattern string
		want    bool
	}{
		{"diretório de teste em qualquer profundidade", "backend/internal/scanning/tests/fixture.go", "/tests/", true},
		{"não bate quando o segmento não existe", "backend/internal/scanning/service.go", "/tests/", false},
		{"nome de arquivo exato", "config/.env.example", ".env.example", true},
		{"substring simples sem barra", "app/fixtures/seed.json", "/fixtures/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesNoisePattern(tc.file, tc.pattern); got != tc.want {
				t.Errorf("matchesNoisePattern(%q, %q) = %v, want %v", tc.file, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMatchesNoisePattern_GlobPatterns(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		pattern string
		want    bool
	}{
		{"glob bate no nome do arquivo, qualquer diretório", "internal/scanning/handlers_test.go", "*_test.go", true},
		{"glob não bate num arquivo que não é de teste", "internal/scanning/handlers.go", "*_test.go", false},
		{"glob não estende pra fora do nome do arquivo (sem **)", "internal/scanning_test/handlers.go", "*_test.go", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesNoisePattern(tc.file, tc.pattern); got != tc.want {
				t.Errorf("matchesNoisePattern(%q, %q) = %v, want %v", tc.file, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMatchesNoisePattern_EmptyInputsNeverMatch(t *testing.T) {
	if matchesNoisePattern("", "/tests/") {
		t.Error("empty file should never match")
	}
	if matchesNoisePattern("app.go", "") {
		t.Error("empty pattern should never match")
	}
}

func TestFilterNoise_RemovesOnlyMatchingFindings(t *testing.T) {
	findings := []domain.PersistedFinding{
		{Finding: domain.Finding{File: "internal/handler_test.go", Description: "ruído"}},
		{Finding: domain.Finding{File: "internal/handler.go", Description: "real"}},
		{Finding: domain.Finding{File: "config/.env.example", Description: "ruído também"}},
	}

	got := filterNoise(findings, []string{"*_test.go", ".env.example"})

	if len(got) != 1 {
		t.Fatalf("filterNoise returned %d findings, want 1", len(got))
	}
	if got[0].Description != "real" {
		t.Errorf("surviving finding = %+v, want the one whose File matches no pattern", got[0])
	}
}

func TestFilterNoise_EmptyPatterns_FallsBackToDefaults(t *testing.T) {
	findings := []domain.PersistedFinding{
		{Finding: domain.Finding{File: "internal/handler_test.go"}},
	}

	got := filterNoise(findings, nil)

	if len(got) != 0 {
		t.Errorf("filterNoise(nil patterns) = %v, want the default patterns (which include *_test.go) to apply", got)
	}
}

func TestFilterNoise_FindingWithoutFile_NeverFiltered(t *testing.T) {
	// Um achado de DAST (ZAP) não é sobre um arquivo — File fica vazio, e
	// nunca deveria ser removido só porque um padrão de ruído existe.
	findings := []domain.PersistedFinding{
		{Finding: domain.Finding{File: "", Description: "alerta do ZAP"}},
	}

	got := filterNoise(findings, []string{"/tests/"})

	if len(got) != 1 {
		t.Errorf("filterNoise removed a finding with no File — should never match any path pattern")
	}
}
