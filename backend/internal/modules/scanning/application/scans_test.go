// Testes de scans.go (RunScan/CreateScanJob/CreateProjectScanJob/
// GetScanStatus) — a entidade Scan em si, não a mecânica de rodar
// vários scanners em paralelo (ver scan_orchestration_test.go).
// Fixtures/fakes compartilhados continuam em service_test.go,
// visíveis daqui por estarem no mesmo pacote.
package application

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
)

func TestRunScan_UnknownScanner_ReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, _, err := svc.RunScan(context.Background(), "does-not-exist", "target", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered scanner")
	}
}

func TestRunScan_NoFindings_PersistsCompletionEventButNoRows(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "clean-scanner"}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	_, findings, err := svc.RunScan(ctx, "clean-scanner", "example.com", corrID, nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

func TestRunScan_WithFindings_PersistsFindingsAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	want := []domain.Finding{
		{ID: "CVE-2026-0001", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityCritical, Description: "dependência desatualizada com CVE conhecido", File: "go.sum", Line: 0},
		{ID: "semgrep:go.lang.security.audit.sql-injection", OWASPCategory: "A03:2021-Injection", Severity: domain.SeverityHigh, Description: "possível SQL injection", File: "repo.go", Line: 42},
	}
	scanner := &fakeScanner{name: "vuln-scanner", findings: want}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	scanID, got, err := svc.RunScan(ctx, "vuln-scanner", "backend/", corrID, nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %d, want %d", len(got), len(want))
	}

	var count int
	err = pool.QueryRow(ctx, `SELECT count(*) FROM scan_findings WHERE scan_id = $1`, scanID).Scan(&count)
	if err != nil {
		t.Fatalf("query scan_findings: %v", err)
	}
	if count != len(want) {
		t.Errorf("persisted rows = %d, want %d", count, len(want))
	}
	if !outboxEventExists(t, pool, scanID.String(), EventScanCompleted) {
		t.Error("expected a scanning.scan.completed outbox event")
	}
}

// TestRunScan_WithFindings_OutboxPayloadCarriesSeverityBreakdown (Fase
// 14 — Maturidade de AppSec): scanning.scan.completed passou a carregar
// critical_count/high_count, não só um findings_count sem distinção de
// gravidade — o NotificationCenter do frontend usa isto pra destacar um
// scan com achado grave em vez de tratar toda conclusão de scan igual.
func TestRunScan_WithFindings_OutboxPayloadCarriesSeverityBreakdown(t *testing.T) {
	pool := testPool(t)
	findings := []domain.Finding{
		{ID: "CVE-2026-0001", Severity: domain.SeverityCritical, Description: "grave"},
		{ID: "semgrep:sql-injection", Severity: domain.SeverityHigh, Description: "alto"},
		{ID: "semgrep:missing-header", Severity: domain.SeverityLow, Description: "baixo"},
	}
	scanner := &fakeScanner{name: "severity-breakdown-scanner", findings: findings}
	svc := newService(pool, scanner)
	ctx := context.Background()

	scanID, _, err := svc.RunScan(ctx, "severity-breakdown-scanner", "backend/", uuid.New(), nil)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	// outbox_events.payload é o envelope events.Event INTEIRO (id, type,
	// source, occurred_at, correlation_id, e só então "payload" com o
	// scanCompletedPayload de fato) — não o scanCompletedPayload direto,
	// daí o Unmarshal em duas camadas.
	var envelope struct {
		Payload struct {
			FindingsCount int `json:"findings_count"`
			CriticalCount int `json:"critical_count"`
			HighCount     int `json:"high_count"`
		} `json:"payload"`
	}
	err = pool.QueryRow(ctx,
		`SELECT payload FROM outbox_events WHERE aggregate_id = $1 AND event_type = $2`,
		scanID.String(), EventScanCompleted,
	).Scan(&envelope)
	if err != nil {
		t.Fatalf("query outbox payload: %v", err)
	}
	payload := envelope.Payload
	if payload.FindingsCount != 3 {
		t.Errorf("FindingsCount = %d, want 3", payload.FindingsCount)
	}
	if payload.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", payload.CriticalCount)
	}
	if payload.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1 (LOW is not counted in either bucket)", payload.HighCount)
	}
}

func TestRunScan_ScannerError_ReturnsErrorAndPersistsNothing(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "broken-scanner", err: fmt.Errorf("tool crashed")}
	svc := newService(pool, scanner)
	ctx := context.Background()

	before := countRows(t, pool, "broken-scanner")

	_, _, err := svc.RunScan(ctx, "broken-scanner", "target", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error when the scanner itself fails")
	}

	after := countRows(t, pool, "broken-scanner")
	if after != before {
		t.Errorf("rows for broken-scanner changed from %d to %d, want no persistence on scanner failure", before, after)
	}
}

func TestCreateScanJob_UnknownScanner_ReturnsNotFoundWithoutCreatingAJob(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"does-not-exist"}, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered scanner")
	}
}

func TestCreateScanJob_EmptyTarget_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"trivy"}, "", nil)
	if err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestCreateScanJob_CreatesJobAndOutboxEventAtomically(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})
	corrID := uuid.New()

	job, err := svc.CreateScanJob(context.Background(), corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if job.Status != jobs.StatusQueued {
		t.Errorf("Status = %s, want queued", job.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanRequested) {
		t.Error("expected a scanning.scan.requested outbox event")
	}
}

func TestCreateScanJob_EmptyScannerList_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), nil, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error for an empty scanner list")
	}
}

func TestCreateScanJob_OneUnknownAmongKnown_RejectsWithoutCreatingAJob(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "trivy"})

	_, err := svc.CreateScanJob(context.Background(), uuid.New(), []string{"trivy", "does-not-exist"}, "https://example.com/repo.git", nil)
	if err == nil {
		t.Fatal("expected an error when any scanner in the list is unregistered")
	}
}

// Reproduz o bug real encontrado ao consultar ListRecentScans contra os
// dados de verdade já persistidos neste ambiente: jobs.result gravado
// ANTES desta fase tinha failed_scanners como uma lista de NOMES
// (strings), não domain.ScannerFailure estruturado — decodificar isso
// com o formato novo quebrava com um erro de unmarshal, derrubando a
// consulta inteira por causa de UM job velho. Insere a linha direto via
// SQL (não MarkCompleted, que já grava o formato novo) pra reproduzir de
// verdade o formato antigo, não só simulá-lo.
func TestGetScanStatus_LegacyStringFailedScanners_DecodesWithoutError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	jobID := uuid.New()
	const q = `
		INSERT INTO jobs (id, type, status, attempts, payload, result, correlation_id, created_at, started_at, finished_at)
		VALUES ($1, $2, 'completed', 1,
			'{"scanners":["trivy","zap"],"target":"https://example.com/repo.git"}',
			'{"succeeded_scanners":["trivy"],"failed_scanners":["zap"]}',
			$3, now(), now(), now())
	`
	if _, err := pool.Exec(ctx, q, jobID, JobType, uuid.New()); err != nil {
		t.Fatalf("seed a legacy-format completed job: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE id = $1`, jobID)
	})

	status, err := svc.GetScanStatus(ctx, jobID)
	if err != nil {
		t.Fatalf("GetScanStatus on a legacy-format job: %v", err)
	}
	if len(status.SucceededScanners) != 1 || status.SucceededScanners[0] != "trivy" {
		t.Errorf("SucceededScanners = %v, want [trivy]", status.SucceededScanners)
	}
	if len(status.FailedScanners) != 1 || status.FailedScanners[0].Scanner != "zap" {
		t.Errorf("FailedScanners = %+v, want exactly one entry with Scanner=zap", status.FailedScanners)
	}
}

// Reproduz o crash real relatado pelo usuário ("não consegui nem acessar
// a página"): jobs de scan de ANTES da Fase 7 (Orquestração concorrente)
// guardavam o scanner pedido na chave singular "scanner" (um só, nunca
// mais de um), não a lista "scanners" de hoje — confirmado contra 3 jobs
// de verdade deste ambiente (payload tipo
// {"target":"...","scanner":"trivy"}, sem "scanners" nenhum). Sem
// nenhum fallback, RequestedScanners chegava nil, virava JSON `null`, e
// o frontend (que assume sempre lista, nunca null) quebrava com
// "TypeError: Cannot read properties of null (reading 'join')" — a
// PÁGINA INTEIRA de /seguranca parava de carregar por causa desses 3
// jobs antigos, não só o job individual.
func TestGetScanStatus_LegacySingularScannerPayload_FallsBackCorrectly(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	jobID := uuid.New()
	const q = `
		INSERT INTO jobs (id, type, status, attempts, payload, result, correlation_id, created_at, started_at, finished_at)
		VALUES ($1, $2, 'completed', 1,
			'{"target":"https://github.com/octocat/Hello-World.git","scanner":"trivy"}',
			'{"findings_count": 0}',
			$3, now(), now(), now())
	`
	if _, err := pool.Exec(ctx, q, jobID, JobType, uuid.New()); err != nil {
		t.Fatalf("seed a pre-Fase-7 legacy job: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE id = $1`, jobID)
	})

	status, err := svc.GetScanStatus(ctx, jobID)
	if err != nil {
		t.Fatalf("GetScanStatus on a pre-Fase-7 legacy job: %v", err)
	}
	if len(status.RequestedScanners) != 1 || status.RequestedScanners[0] != "trivy" {
		t.Errorf("RequestedScanners = %v, want [trivy] (from the legacy singular \"scanner\" key)", status.RequestedScanners)
	}
	// jobs.result deste job não tem succeeded_scanners/failed_scanners
	// nenhum (formato ainda mais antigo, só findings_count) — como o
	// job está completed e nenhuma falha foi registrada, a inferência
	// correta é que o scanner pedido teve sucesso, não uma lista vazia.
	if len(status.SucceededScanners) != 1 || status.SucceededScanners[0] != "trivy" {
		t.Errorf("SucceededScanners = %v, want [trivy] (inferred: completed + no recorded failure)", status.SucceededScanners)
	}
}

// A partir daqui: ListRecentFindings (Fase 9 — o feed "achados recentes
// por severidade" que a UI usa).

func TestCreateProjectScanJob_UnknownProject_ReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeLocalScanner{fakeScanner: fakeScanner{name: "trivy"}})

	_, err := svc.CreateProjectScanJob(context.Background(), uuid.New(), []string{"trivy"}, uuid.New(), nil)
	if err == nil {
		t.Fatal("expected an error for an unknown project ID")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeNotFound {
		t.Errorf("err = %v, want a NOT_FOUND apperrors.Error", err)
	}
}

// TestCreateProjectScanJob_UploadProject_RejectsScannerWithoutLocalSupport
// cobre a validação feita NA CRIAÇÃO do job (createScanJob), não só
// descoberta depois no worker: um projeto criado por upload nunca tem
// alvo git, então um scanner sem domain.LocalScanner (SonarQube exige
// git clone pra derivar a project key; ZAP ataca uma URL viva) é
// rejeitado aqui — fakeScanner (sem ExecuteLocal) representa esse caso.
func TestCreateProjectScanJob_UploadProject_RejectsScannerWithoutLocalSupport(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeScanner{name: "sonarqube"}, &fakeLocalScanner{fakeScanner: fakeScanner{name: "trivy"}})
	ctx := context.Background()

	project, err := svc.CreateProjectUpload(ctx, "test-project-reject-unsupported", []byte("pretend zip"), nil)
	if err != nil {
		t.Fatalf("CreateProjectUpload: %v", err)
	}

	_, err = svc.CreateProjectScanJob(ctx, uuid.New(), []string{"sonarqube"}, project.ID, nil)
	if err == nil {
		t.Fatal("expected an error for a scanner that does not support upload-based projects")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeValidation {
		t.Errorf("err = %v, want a VALIDATION_ERROR apperrors.Error", err)
	}

	// "trivy" (fakeLocalScanner, implementa LocalScanner) continua indo
	// em frente normalmente — a rejeição é POR SCANNER, nunca o projeto
	// upload inteiro fica bloqueado só porque outro scanner pedido junto
	// não suporta.
	if _, err := svc.CreateProjectScanJob(ctx, uuid.New(), []string{"trivy"}, project.ID, nil); err != nil {
		t.Errorf("CreateProjectScanJob with a LocalScanner-capable scanner: %v, want success", err)
	}
}
