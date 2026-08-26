// Testes de findings.go (ListFindings/ListRecentFindings/ListProjectFindingsHistory).
// Fixtures/fakes compartilhados continuam em service_test.go (ver nota em scans_test.go).
package application

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

func TestListRecentFindings_IncludesFindingsFromMultipleScans(t *testing.T) {
	pool := testPool(t)
	// Nome de scanner distinto e improvável de colidir com achados de
	// outros testes rodando na mesma tabela compartilhada — a asserção
	// abaixo procura por ele especificamente em vez de comparar
	// contagem exata, porque scan_findings é uma tabela compartilhada
	// entre todo teste deste pacote (nenhum limpa depois de si) e
	// ListRecentPage, por natureza, não filtra por scan_id.
	const marker = "recent-findings-marker-scanner"
	scanner := &fakeScanner{name: marker, findings: []domain.Finding{
		{ID: "MARKER-1", Severity: domain.SeverityCritical, Description: "achado do teste de ListRecentFindings"},
	}}
	svc := newService(pool, scanner)
	ctx := context.Background()

	scanID, _, err := svc.RunScan(ctx, marker, "target", uuid.New(), nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	// CRITICAL some pro topo da ordenação (mais grave primeiro) — a
	// primeira página (pageSize no teto) já é o bastante pra pegar o
	// achado deste teste, mesmo com a suíte inteira compartilhando a
	// mesma tabela.
	recent, _, err := svc.ListRecentFindings(ctx, 1, pagination.AbsoluteMaxPageSize)
	if err != nil {
		t.Fatalf("ListRecentFindings: %v", err)
	}

	found := false
	for _, f := range recent {
		if f.ScanID == scanID && f.ID == "MARKER-1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListRecentFindings did not include the finding just created (scan_id=%s)", scanID)
	}
}

func TestListRecentFindings_ReturnsMetaWithTotalCount(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	recent, meta, err := svc.ListRecentFindings(context.Background(), 1, 5)
	if err != nil {
		t.Fatalf("ListRecentFindings: %v", err)
	}
	if len(recent) > 5 {
		t.Errorf("page size not respected: got %d rows, want at most 5", len(recent))
	}
	if meta.PageSize != 5 || meta.Page != 1 {
		t.Errorf("meta = %+v, want Page=1 PageSize=5", meta)
	}
	// TotalItems é sobre a tabela INTEIRA (compartilhada com toda a
	// suíte), não sobre esta página — só afirma que reflete PELO MENOS o
	// que esta página já devolveu, nunca menos (senão a paginação em si
	// estaria mentindo sobre quanto ainda falta).
	if meta.TotalItems < int64(len(recent)) {
		t.Errorf("meta.TotalItems = %d, want at least %d (the size of the page itself)", meta.TotalItems, len(recent))
	}
}

// TestListRecentFindings_PageBeyondTotal_ReturnsEmptyPageWithCorrectTotal
// prova o caso que motivou o comentário de ListRecentPage sobre
// count(*) OVER() nunca aparecer numa página vazia — uma página bem além
// do fim ainda devolve o TotalItems real, não zero.
func TestListRecentFindings_PageBeyondTotal_ReturnsEmptyPageWithCorrectTotal(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, metaFirstPage, err := svc.ListRecentFindings(context.Background(), 1, 1)
	if err != nil {
		t.Fatalf("ListRecentFindings (page 1): %v", err)
	}
	if metaFirstPage.TotalItems == 0 {
		t.Skip("no findings in the shared test database yet — nothing to prove a beyond-the-end page against")
	}

	recent, meta, err := svc.ListRecentFindings(context.Background(), 999_999, 1)
	if err != nil {
		t.Fatalf("ListRecentFindings (way beyond the end): %v", err)
	}
	if len(recent) != 0 {
		t.Errorf("recent = %d rows, want 0 for a page far beyond the total", len(recent))
	}
	if meta.TotalItems != metaFirstPage.TotalItems {
		t.Errorf("TotalItems on an empty page = %d, want it to still match the real total (%d), not 0", meta.TotalItems, metaFirstPage.TotalItems)
	}
}

func TestListRecentFindings_PageAndPageSizeClamping(t *testing.T) {
	cases := []struct {
		name           string
		page, pageSize int
		wantOffset     int
		wantLimit      int
	}{
		{"zero page and size use the defaults", 0, 0, 0, pagination.DefaultPageSize},
		{"negative page and size use the defaults", -5, -5, 0, pagination.DefaultPageSize},
		{"within range is passed through unchanged", 2, 10, 10, 10},
		{"page size above the cap is clamped", 1, 10_000, 0, pagination.AbsoluteMaxPageSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepositoryCapturingLimit{}
			svc := &Service{repo: repo, logger: testLogger()}

			if _, _, err := svc.ListRecentFindings(context.Background(), tc.page, tc.pageSize); err != nil {
				t.Fatalf("ListRecentFindings: %v", err)
			}
			if repo.gotOffset != tc.wantOffset || repo.gotLimit != tc.wantLimit {
				t.Errorf("repository received offset=%d limit=%d, want offset=%d limit=%d",
					repo.gotOffset, repo.gotLimit, tc.wantOffset, tc.wantLimit)
			}
		})
	}
}

// A partir daqui: Fase 10 — Projeto como entidade própria + upload .zip
// (ver docs/roadmap-secops-orchestrator.md, seção "Extensão").

func TestListProjectFindingsHistory_NeverScanned_ReturnsEmptyNotError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	project, err := svc.CreateProjectGit(ctx, "test-project-history-empty", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}

	history, err := svc.ListProjectFindingsHistory(ctx, project.ID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("history = %v, want none for a project that was never scanned", history)
	}
}

func TestListProjectFindingsHistory_UnknownProject_ReturnsEmptyNotError(t *testing.T) {
	// Diferente de GetProject, ListProjectFindingsHistory nunca precisa
	// de um NotFound: ListProjectScans (o que ela reaproveita) já trata
	// "nenhum scan encontrado pra esse projeto" como uma lista vazia
	// legítima, seja porque o projeto existe e nunca rodou, seja porque o
	// ID nem existe — as duas situações produzem a mesma resposta
	// honesta: nenhum histórico pra mostrar.
	pool := testPool(t)
	svc := newService(pool)

	history, err := svc.ListProjectFindingsHistory(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("history = %v, want none for an unknown project ID", history)
	}
}

func TestListProjectFindingsHistory_DeduplicatesAcrossRescans(t *testing.T) {
	pool := testPool(t)
	persistent := domain.Finding{
		ID: "CVE-2026-PERSISTENT", OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Severity: domain.SeverityHigh, Description: "ainda não corrigido", File: "go.sum", Line: 10,
	}
	fixedLater := domain.Finding{
		ID: "CVE-2026-FIXED", OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Severity: domain.SeverityCritical, Description: "corrigido depois do primeiro scan", File: "go.sum", Line: 20,
	}

	ctx := context.Background()
	corrID := uuid.New()

	// Scan 1: os dois achados presentes.
	scanner1 := &fakeScanner{name: "trivy", findings: []domain.Finding{persistent, fixedLater}}
	svc1 := newService(pool, scanner1)
	project, err := svc1.CreateProjectGit(ctx, "test-project-history-dedup", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}
	job1, err := svc1.CreateProjectScanJob(ctx, corrID, []string{"trivy"}, project.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob (1): %v", err)
	}
	if err := svc1.ProcessScanJob(ctx, job1.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob (1): %v", err)
	}

	// created_at tem precisão de timestamp — um sleep pequeno garante que
	// os dois scans não colidam no MESMO instante, pra FirstSeenAt/
	// LastSeenAt do achado persistente realmente poderem diferir.
	time.Sleep(10 * time.Millisecond)

	// Scan 2 (re-scan do MESMO projeto): só o achado persistente continua
	// — fixedLater foi corrigido, não aparece mais.
	scanner2 := &fakeScanner{name: "trivy", findings: []domain.Finding{persistent}}
	svc2 := newService(pool, scanner2)
	job2, err := svc2.CreateProjectScanJob(ctx, corrID, []string{"trivy"}, project.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob (2): %v", err)
	}
	if err := svc2.ProcessScanJob(ctx, job2.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob (2): %v", err)
	}

	history, err := svc2.ListProjectFindingsHistory(ctx, project.ID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %d entries, want 2 (one per DISTINCT fingerprint, not one per scan)", len(history))
	}

	byID := make(map[string]ProjectFindingHistory, 2)
	for _, h := range history {
		byID[h.Description] = h
	}

	got, ok := byID["ainda não corrigido"]
	if !ok {
		t.Fatal("missing the persistent finding in the history")
	}
	if got.ScanCount != 2 {
		t.Errorf("persistent finding ScanCount = %d, want 2 (appeared in both scans)", got.ScanCount)
	}
	if !got.StillPresent {
		t.Error("persistent finding StillPresent = false, want true (it's in the most recent scan)")
	}
	if !got.LastSeenAt.After(got.FirstSeenAt) {
		t.Errorf("persistent finding FirstSeenAt=%v LastSeenAt=%v, want LastSeenAt strictly after FirstSeenAt across two scans", got.FirstSeenAt, got.LastSeenAt)
	}

	gotFixed, ok := byID["corrigido depois do primeiro scan"]
	if !ok {
		t.Fatal("missing the fixed finding in the history")
	}
	if gotFixed.ScanCount != 1 {
		t.Errorf("fixed finding ScanCount = %d, want 1 (only appeared in the first scan)", gotFixed.ScanCount)
	}
	if gotFixed.StillPresent {
		t.Error("fixed finding StillPresent = true, want false — it's absent from the most recent scan")
	}
}

func TestListFindings_NoiseFilterFlag_DisabledByDefault_ShowsEverything(t *testing.T) {
	pool := testPool(t)
	svc := newServiceWithFlags(pool, fakeFlags{enabled: false}, []string{"*_test.go"}, &fakeScanner{
		name: "trivy",
		findings: []domain.Finding{
			{ID: "CVE-2026-NOISE-1", Severity: domain.SeverityLow, File: "internal/handler_test.go", Description: "seria filtrado se a flag estivesse ligada"},
		},
	})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 — o filtro de ruído está desligado por padrão, nada deveria sumir", len(findings))
	}
}

func TestListFindings_NoiseFilterFlag_Enabled_HidesMatchingFindings(t *testing.T) {
	pool := testPool(t)
	svc := newServiceWithFlags(pool, fakeFlags{enabled: true}, []string{"*_test.go"}, &fakeScanner{
		name: "trivy",
		findings: []domain.Finding{
			{ID: "CVE-2026-NOISE-2", Severity: domain.SeverityLow, File: "internal/handler_test.go", Description: "ruído"},
			{ID: "CVE-2026-NOISE-3", Severity: domain.SeverityLow, File: "internal/handler.go", Description: "real"},
		},
	})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].Description != "real" {
		t.Fatalf("findings = %+v, want only the non-test-file finding to survive", findings)
	}
}
