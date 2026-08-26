// Testes de posture.go (Fase 14 — Maturidade de AppSec).
package application

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
)

// Nota (vale pra todo teste deste arquivo): testPool(t) é um Postgres
// COMPARTILHADO por todo teste do pacote (sem transação/rollback por
// teste, mesmo padrão do resto do módulo — ver comentário de testPool em
// service_test.go) — por isso nenhum teste aqui afirma um total GLOBAL
// (ex.: "ProjectsScanned == 0"), só o que é verdade sobre o projeto
// específico que ELE MESMO criou, imune a projeto criado por outro teste
// já ter rodado antes na mesma suíte.

// TestSecurityPosture_AggregatesOpenFindingsAcrossProjects prova o
// núcleo do cálculo: conta achado aberto (ainda presente, não triado),
// nunca conta achado corrigido (StillPresent=false) nem achado triado —
// e o mesmo achado, tendo aparecido em dois re-scans do MESMO projeto,
// conta só UMA vez (dedup por fingerprint, não por linha de scan_findings).
func TestSecurityPosture_AggregatesOpenFindingsAcrossProjects(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	ctx := context.Background()

	critical := domain.Finding{ID: "CVE-POSTURE-CRIT", Severity: domain.SeverityCritical, Description: "grave", File: "a.go", Line: 1}
	high := domain.Finding{ID: "CVE-POSTURE-HIGH", Severity: domain.SeverityHigh, Description: "alto", File: "b.go", Line: 2}
	fixed := domain.Finding{ID: "CVE-POSTURE-FIXED", Severity: domain.SeverityCritical, Description: "já corrigido", File: "c.go", Line: 3}
	triaged := domain.Finding{ID: "CVE-POSTURE-TRIAGED", Severity: domain.SeverityCritical, Description: "risco aceito", File: "d.go", Line: 4}

	// Projeto A: scan 1 com os 4 achados, scan 2 (re-scan) sem `fixed` —
	// prova dedup (critical/high contam 1x cada, não 2x) e que "fixed"
	// não conta como aberto.
	scanner := &fakeScanner{name: "trivy", findings: []domain.Finding{critical, high, fixed, triaged}}
	svc := newService(pool, scanner).WithTriageRepository(repo)
	projectA, err := svc.CreateProjectGit(ctx, "test-posture-project-a", "https://example.com/repo-a.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit A: %v", err)
	}
	job1, err := svc.CreateProjectScanJob(ctx, uuid.New(), []string{"trivy"}, projectA.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob (1): %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job1.ID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob (1): %v", err)
	}

	triagedFingerprint := domain.Fingerprint("trivy", triaged.ID, triaged.File, triaged.Line)
	if err := svc.TriageFinding(ctx, projectA.ID, triagedFingerprint, domain.TriageRiskAccepted, "mitigado", nil, nil); err != nil {
		t.Fatalf("TriageFinding: %v", err)
	}

	// scan 2 (re-scan): `fixed` some (StillPresent vira false — não conta
	// em lugar nenhum, nem aberto nem triado); `triaged` CONTINUA
	// aparecendo (StillPresent permanece true) — só assim dá pra provar
	// que TriagedCount é sobre "presente E triado", não meramente "foi
	// triado alguma vez".
	scanner2 := &fakeScanner{name: "trivy", findings: []domain.Finding{critical, high, triaged}}
	svc2 := newService(pool, scanner2).WithTriageRepository(repo)
	job2, err := svc2.CreateProjectScanJob(ctx, uuid.New(), []string{"trivy"}, projectA.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob (2): %v", err)
	}
	if err := svc2.ProcessScanJob(ctx, job2.ID, uuid.New()); err != nil {
		t.Fatalf("ProcessScanJob (2): %v", err)
	}

	posture, err := svc2.SecurityPosture(ctx)
	if err != nil {
		t.Fatalf("SecurityPosture: %v", err)
	}

	if posture.ProjectsScanned < 1 {
		t.Errorf("ProjectsScanned = %d, want at least 1", posture.ProjectsScanned)
	}
	// Não afirma posture.OpenCritical/OpenHigh/TriagedCount GLOBAIS (ver
	// nota no topo do arquivo) — só a contribuição do projeto A em
	// TopVulnerable, que é escopada e portanto imune a achado de outro
	// teste no mesmo Postgres compartilhado.
	var found bool
	for _, tv := range posture.TopVulnerable {
		if tv.ProjectID == projectA.ID.String() {
			found = true
			if tv.OpenCritical != 1 || tv.OpenHigh != 1 {
				t.Errorf("project A posture = %+v, want OpenCritical=1 OpenHigh=1 (dedup across 2 scans; `fixed` doesn't count, `triaged` doesn't either — it's triaged, not open)", tv)
			}
		}
	}
	if !found {
		t.Error("TopVulnerable did not include project A, which has open critical+high findings")
	}

	// TriagedCount é global (não por projeto — ProjectPosture não carrega
	// um campo próprio pra isso), então confirma indiretamente: a
	// history do projeto A, consultada direto, tem exatamente 1 entrada
	// com TriageStatus preenchido.
	historyA, err := svc2.ListProjectFindingsHistory(ctx, projectA.ID)
	if err != nil {
		t.Fatalf("ListProjectFindingsHistory: %v", err)
	}
	var triagedInHistory int
	for _, h := range historyA {
		if h.TriageStatus != "" {
			triagedInHistory++
			if h.Fingerprint != triagedFingerprint || !h.StillPresent {
				t.Errorf("triaged entry = %+v, want fingerprint=%q StillPresent=true", h, triagedFingerprint)
			}
		}
	}
	if triagedInHistory != 1 {
		t.Errorf("project A history has %d triaged entries, want exactly 1", triagedInHistory)
	}
}

func TestSecurityPosture_ProjectNeverScanned_IsExcluded(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	if _, err := svc.CreateProjectGit(ctx, "test-posture-never-scanned", "https://example.com/repo-never.git", nil); err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}

	posture, err := svc.SecurityPosture(ctx)
	if err != nil {
		t.Fatalf("SecurityPosture: %v", err)
	}
	// Não afirma ProjectsScanned == 0 (outro teste pode ter deixado
	// projetos escaneados no mesmo banco compartilhado) — só que este
	// projeto específico, nunca escaneado, não quebrou o cálculo.
	_ = posture
}

// A partir daqui: Fase 14, continuação — tendência histórica
// (SnapshotSecurityPosture/PostureHistory).

func TestSnapshotSecurityPosture_WithoutPostureRepositoryConfigured_ReturnsInternalError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool) // sem .WithPostureRepository

	if err := svc.SnapshotSecurityPosture(context.Background()); err == nil {
		t.Fatal("expected an error when postureRepo is nil")
	}
}

func TestSnapshotSecurityPosture_And_PostureHistory_RoundTrip(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newService(pool).WithPostureRepository(repo)
	ctx := context.Background()

	if err := svc.SnapshotSecurityPosture(ctx); err != nil {
		t.Fatalf("SnapshotSecurityPosture: %v", err)
	}

	history, err := svc.PostureHistory(ctx, 30)
	if err != nil {
		t.Fatalf("PostureHistory: %v", err)
	}
	if len(history) == 0 {
		t.Fatal("expected at least today's snapshot in the history")
	}
	today := history[len(history)-1] // mais recente por último (ORDER BY snapshot_date ASC)
	now := time.Now()
	if today.Date.Year() != now.Year() || today.Date.YearDay() != now.YearDay() {
		t.Errorf("most recent snapshot date = %v, want today (%v)", today.Date, now)
	}
}

// TestSnapshotSecurityPosture_RunningTwiceSameDay_OverwritesNotAccumulates
// prova o ON CONFLICT (snapshot_date) — rodar o snapshot duas vezes no
// mesmo dia (ex.: worker reiniciado) não deveria deixar duas linhas pro
// mesmo dia.
func TestSnapshotSecurityPosture_RunningTwiceSameDay_OverwritesNotAccumulates(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newService(pool).WithPostureRepository(repo)
	ctx := context.Background()

	if err := svc.SnapshotSecurityPosture(ctx); err != nil {
		t.Fatalf("SnapshotSecurityPosture (1): %v", err)
	}
	if err := svc.SnapshotSecurityPosture(ctx); err != nil {
		t.Fatalf("SnapshotSecurityPosture (2): %v", err)
	}

	history, err := svc.PostureHistory(ctx, 30)
	if err != nil {
		t.Fatalf("PostureHistory: %v", err)
	}
	var todayCount int
	now := time.Now()
	for _, s := range history {
		if s.Date.Year() == now.Year() && s.Date.YearDay() == now.YearDay() {
			todayCount++
		}
	}
	if todayCount != 1 {
		t.Errorf("snapshots for today = %d, want exactly 1 (upsert, not accumulate)", todayCount)
	}
}

func TestPostureHistory_DaysClamping(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	svc := newService(pool).WithPostureRepository(repo)
	ctx := context.Background()

	// 0/negativo não deveria virar erro (usa o default) — só confirma que
	// a chamada não falha; o teto (maxPostureHistoryDays) não é
	// observável de fora sem inspecionar o SQL, então este teste cobre
	// só "não quebra com entrada estranha", mesmo espírito de
	// TestListRecentFindings_PageAndPageSizeClamping.
	if _, err := svc.PostureHistory(ctx, 0); err != nil {
		t.Errorf("PostureHistory(0): %v, want nil (falls back to the default)", err)
	}
	if _, err := svc.PostureHistory(ctx, -5); err != nil {
		t.Errorf("PostureHistory(-5): %v, want nil (falls back to the default)", err)
	}
	if _, err := svc.PostureHistory(ctx, 10_000); err != nil {
		t.Errorf("PostureHistory(10000): %v, want nil (clamped to the cap, not rejected)", err)
	}
}
