// Testes de buildSarifLog e dos helpers puros de sarif_export.go — ao
// contrário de sarif_export_test.go (que exercita o handler HTTP inteiro
// contra um Postgres real via testPool, e por isso é pulado sem
// TEST_DATABASE_URL), estes não tocam banco nenhum: só constroem
// []domain.PersistedFinding na mão e chamam buildSarifLog direto. Sempre
// rodam, com ou sem Postgres disponível.
package transport

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

func TestSeverityToSarifLevel(t *testing.T) {
	cases := map[domain.Severity]string{
		domain.SeverityCritical: "error",
		domain.SeverityHigh:     "error",
		domain.SeverityMedium:   "warning",
		domain.SeverityLow:      "note",
	}
	for sev, want := range cases {
		if got := severityToSarifLevel(sev); got != want {
			t.Errorf("severityToSarifLevel(%s) = %q, want %q", sev, got, want)
		}
	}
}

func TestShortDescriptionText_TruncatesLongDescriptions(t *testing.T) {
	long := ""
	for i := 0; i < 200; i++ {
		long += "x"
	}
	got := shortDescriptionText(long)
	if len(got) >= len(long) {
		t.Errorf("shortDescriptionText did not truncate: len=%d", len(got))
	}
	short := "achado curto"
	if got := shortDescriptionText(short); got != short {
		t.Errorf("shortDescriptionText(%q) = %q, want unchanged", short, got)
	}
}

func newPersistedFinding(scanner string, f domain.Finding) domain.PersistedFinding {
	return domain.PersistedFinding{
		RecordID:           uuid.New(),
		ScanID:             uuid.New(),
		Scanner:            scanner,
		Target:             "https://example.com/repo.git",
		Finding:            f,
		FindingFingerprint: domain.Fingerprint(scanner, f.ID, f.File, f.Line),
		CreatedAt:          time.Now(),
	}
}

func TestBuildSarifLog_TopLevelShape(t *testing.T) {
	findings := []domain.PersistedFinding{
		newPersistedFinding("trivy", domain.Finding{ID: "CVE-1", Severity: domain.SeverityCritical, Description: "d1", File: "go.sum", Line: 5}),
	}
	log := buildSarifLog([]string{"trivy"}, findings)

	if log.Version != "2.1.0" {
		t.Errorf("Version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("Schema vazio, want a URI do schema oficial")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("Runs = %d, want 1", len(log.Runs))
	}
}

func TestBuildSarifLog_ScannerWithNoFindings_StillGetsAnEmptyRun(t *testing.T) {
	// gitleaks rodou (está em SucceededScanners) mas não achou nada — o
	// run precisa existir mesmo assim (results: []), senão um consumidor
	// de SARIF não consegue distinguir "rodou e não achou nada" de
	// "nunca rodou".
	log := buildSarifLog([]string{"trivy", "gitleaks"}, []domain.PersistedFinding{
		newPersistedFinding("trivy", domain.Finding{ID: "CVE-1", Severity: domain.SeverityHigh, Description: "d1", File: "a.go", Line: 1}),
	})

	if len(log.Runs) != 2 {
		t.Fatalf("Runs = %d, want 2", len(log.Runs))
	}
	var gitleaksRun *sarifRun
	for i := range log.Runs {
		if log.Runs[i].Tool.Driver.Name == "gitleaks" {
			gitleaksRun = &log.Runs[i]
		}
	}
	if gitleaksRun == nil {
		t.Fatal("nenhum run para gitleaks")
	}
	if gitleaksRun.Results == nil {
		t.Error("Results de um run vazio deve ser [] (não omitido), não nil — omitempty não se aplica aqui: queremos results presente e vazio no JSON")
	}
}

func TestBuildSarifLog_FindingWithoutLine_OmitsRegion(t *testing.T) {
	// Line == 0 (achado sem arquivo específico, ex.: DAST) nunca pode
	// virar startLine: 0 no JSON — o schema oficial exige minimum: 1.
	log := buildSarifLog([]string{"zap"}, []domain.PersistedFinding{
		newPersistedFinding("zap", domain.Finding{ID: "zap-xss-1", Severity: domain.SeverityMedium, Description: "XSS refletido"}),
	})

	result := log.Runs[0].Results[0]
	if len(result.Locations) != 0 {
		t.Errorf("Locations = %+v, want vazio (Finding sem File)", result.Locations)
	}
}

func TestBuildSarifLog_DuplicateFindingID_ProducesOneRuleManyResults(t *testing.T) {
	log := buildSarifLog([]string{"trivy"}, []domain.PersistedFinding{
		newPersistedFinding("trivy", domain.Finding{ID: "CVE-DUP", Severity: domain.SeverityCritical, Description: "d", File: "a.go", Line: 1}),
		newPersistedFinding("trivy", domain.Finding{ID: "CVE-DUP", Severity: domain.SeverityCritical, Description: "d", File: "b.go", Line: 2}),
	})

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("Rules = %d, want 1 (deduplicada por Finding.ID)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("Results = %d, want 2 (um por ocorrência)", len(run.Results))
	}
}

func TestBuildSarifLog_RunsSortedByScannerName(t *testing.T) {
	log := buildSarifLog([]string{"trivy", "gitleaks", "semgrep"}, nil)
	got := []string{log.Runs[0].Tool.Driver.Name, log.Runs[1].Tool.Driver.Name, log.Runs[2].Tool.Driver.Name}
	want := []string{"gitleaks", "semgrep", "trivy"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Runs[%d].Tool.Driver.Name = %q, want %q (ordem alfabética esperada: %v)", i, got[i], want[i], want)
		}
	}
}
