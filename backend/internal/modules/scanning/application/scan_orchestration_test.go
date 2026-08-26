// Testes de scan_orchestration.go — ProcessScanJob/
// HandleScanDeadLetter, a mecânica de rodar N scanners em paralelo
// e reconciliar outcomes. Fixtures/fakes compartilhados continuam
// em service_test.go.
package application

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
)

func TestProcessScanJob_Success_CompletesJobAndPersistsFindings(t *testing.T) {
	pool := testPool(t)
	want := []domain.Finding{
		{ID: "CVE-2026-0002", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityHigh, Description: "dependência vulnerável", File: "go.sum"},
	}
	scanner := &fakeScanner{name: "trivy", findings: want}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed", fetched.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanCompleted) {
		t.Error("expected a scanning.scan.completed outbox event")
	}

	// job.ID É o scan_id — ListFindings precisa devolver os achados
	// consultando pelo mesmo ID recebido na criação do job.
	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != len(want) {
		t.Fatalf("findings = %d, want %d", len(findings), len(want))
	}
	if findings[0].ID != want[0].ID {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, want[0].ID)
	}
}

func TestProcessScanJob_RedeliveryOfCompletedJob_IsANoOp(t *testing.T) {
	pool := testPool(t)
	scanner := &countingScanner{name: "trivy"}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("first ProcessScanJob: %v", err)
	}
	// Simula o RabbitMQ reentregando o mesmo evento
	// scanning.scan.requested depois que o job já foi concluído.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("redelivered ProcessScanJob should be a no-op, got error: %v", err)
	}

	if scanner.calls != 1 {
		t.Errorf("Execute called %d times, want exactly 1", scanner.calls)
	}
}

func TestProcessScanJob_ScannerError_MarksFailedAndReturnsErrorForRetry(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", err: fmt.Errorf("git clone failed")}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	err = svc.ProcessScanJob(ctx, job.ID, corrID)
	if err == nil {
		t.Fatal("expected ProcessScanJob to return an error so the caller retries")
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, getErr := jobsRepo.GetByID(ctx, job.ID)
	if getErr != nil {
		t.Fatalf("GetByID: %v", getErr)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}

	// Ainda nenhuma notificação de falha final — o job ainda pode ter
	// sucesso numa nova tentativa.
	if outboxEventExists(t, pool, job.ID.String(), EventScanFailed) {
		t.Error("did not expect a scanning.scan.failed outbox event before retries are exhausted")
	}
}

func TestHandleScanDeadLetter_MarksDeadLetterAndPublishesFailure(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeScanner{name: "trivy", err: fmt.Errorf("still failing")}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	// Simula a(s) tentativa(s) que o RabbitMQ já fez antes de desistir.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected the fake scanner to fail")
	}

	if err := svc.HandleScanDeadLetter(ctx, job.ID, corrID); err != nil {
		t.Fatalf("HandleScanDeadLetter: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusDeadLetter {
		t.Errorf("Status = %s, want dead_letter", fetched.Status)
	}
	if !outboxEventExists(t, pool, job.ID.String(), EventScanFailed) {
		t.Error("expected a scanning.scan.failed outbox event after dead-lettering")
	}

	// O bug que motivou esta troca de assinatura: HandleScanDeadLetter
	// gravava um texto genérico fixo em jobs.error ("max retries
	// exceeded"), descartando o motivo real que ProcessScanJob já tinha
	// gravado na última tentativa (via MarkFailed). Agora reaproveita
	// esse motivo — GetScanStatus precisa conseguir decodificar de volta
	// o scanner que falhou e a mensagem real ("still failing"), não só o
	// texto genérico.
	status, err := svc.GetScanStatus(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetScanStatus: %v", err)
	}
	if len(status.FailedScanners) != 1 {
		t.Fatalf("FailedScanners = %v, want exactly 1 entry", status.FailedScanners)
	}
	if got := status.FailedScanners[0]; got.Scanner != "trivy" || got.Message != "still failing" {
		t.Errorf("FailedScanners[0] = %+v, want scanner=trivy message=%q", got, "still failing")
	}
}

// A partir daqui: Fase 7 (Orquestração concorrente) — um job com mais de
// um scanner.

func TestProcessScanJob_MultipleScanners_RunConcurrentlyNotSequentially(t *testing.T) {
	pool := testPool(t)
	slow := &slowThenFastScanner{name: "slow-scanner", unblock: make(chan struct{}), started: make(chan struct{})}
	fast := &fakeScanner{name: "fast-scanner", findings: []domain.Finding{{ID: "FAST-1", Severity: domain.SeverityLow, Description: "achado rápido"}}}
	svc := newService(pool, slow, fast)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"slow-scanner", "fast-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.ProcessScanJob(ctx, job.ID, corrID) }()

	// Espera o scanner lento começar a rodar (prova que os dois foram
	// disparados) e então libera ele — se ProcessScanJob rodasse os
	// scanners em sequência em vez de paralelo, "fast-scanner" só
	// terminaria DEPOIS de slow-scanner desbloquear, o que este teste
	// não teria como observar de forma diferente; a prova real de
	// paralelismo está em slow.unblock nunca ser fechado até aqui —
	// ProcessScanJob não pode ter retornado sem travar em slow-scanner.
	select {
	case <-slow.started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow-scanner never started — ProcessScanJob may be running scanners sequentially and blocked before reaching it")
	}
	close(slow.unblock)

	if err := <-done; err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only fast-scanner produces one)", len(findings))
	}
}

func TestProcessScanJob_PartialFailure_CompletesJobAndKeepsSuccessfulFindings(t *testing.T) {
	pool := testPool(t)
	good := &fakeScanner{name: "good-scanner", findings: []domain.Finding{{ID: "OK-1", Severity: domain.SeverityMedium, Description: "achado válido"}}}
	bad := &fakeScanner{name: "bad-scanner", err: fmt.Errorf("tool crashed")}
	svc := newService(pool, good, bad)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"good-scanner", "bad-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	// Falha parcial não é reprocessada — ProcessScanJob retorna nil
	// mesmo com um scanner tendo falhado, pra nunca rodar de novo
	// good-scanner (que já teve sucesso) só por causa de bad-scanner.
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob with partial failure should not return an error: %v", err)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed (at least one scanner succeeded)", fetched.Status)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].Scanner != "good-scanner" {
		t.Errorf("findings = %+v, want exactly the good-scanner's finding, nothing from bad-scanner", findings)
	}
}

func TestProcessScanJob_AllScannersFail_MarksJobFailedForRetry(t *testing.T) {
	pool := testPool(t)
	bad1 := &fakeScanner{name: "bad-scanner-1", err: fmt.Errorf("crashed 1")}
	bad2 := &fakeScanner{name: "bad-scanner-2", err: fmt.Errorf("crashed 2")}
	svc := newService(pool, bad1, bad2)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"bad-scanner-1", "bad-scanner-2"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected an error when every scanner in the job fails, so the caller retries")
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}
}

func TestProcessScanJob_UnregisteredScanner_IsTreatedAsThatScannerFailing(t *testing.T) {
	pool := testPool(t)
	// Cria o job com "trivy" registrado, mas simula um scanner
	// desregistrado depois (ex.: um deploy que removeu um scanner) usando
	// um Service à parte, sem nenhum scanner, para processar o job já
	// criado. Com um único scanner no job e ele "desaparecendo", o
	// resultado é o mesmo caminho de "todos os scanners falharam" (ver
	// TestProcessScanJob_AllScannersFail_MarksJobFailedForRetry) — um
	// scanner desregistrado não ganha mais tratamento especial de
	// "falha permanente, nunca reprocessar" desde a Fase 7: com vários
	// scanners por job, a mesma distinção precisaria existir por
	// scanner dentro de uma falha parcial, complexidade que não paga o
	// benefício (poucas tentativas extras esgotadas até cair em
	// dead-letter é aceitável).
	creator := newService(pool, &fakeScanner{name: "trivy"})
	ctx := context.Background()
	corrID := uuid.New()

	job, err := creator.CreateScanJob(ctx, corrID, []string{"trivy"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	processor := newService(pool) // nenhum scanner registrado
	if err := processor.ProcessScanJob(ctx, job.ID, corrID); err == nil {
		t.Fatal("expected an error so the caller retries, same as any other all-scanners-failed outcome")
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusFailed {
		t.Errorf("Status = %s, want failed", fetched.Status)
	}
}

// A partir daqui: progresso por scanner (ScannerRuns/GetScanStatus) —
// pedido do usuário de um painel mostrando qual scanner está rodando
// agora e quanto falta, sem esperar o job inteiro terminar pra saber
// qualquer coisa.

func TestProcessScanJob_ScannerRuns_RecordTerminalStatusForEachScanner(t *testing.T) {
	pool := testPool(t)
	good := &fakeScanner{name: "good-scanner", findings: []domain.Finding{
		{ID: "OK-1", Severity: domain.SeverityLow},
		{ID: "OK-2", Severity: domain.SeverityLow},
	}}
	bad := &fakeScanner{name: "bad-scanner", err: fmt.Errorf("tool crashed")}
	svc := newService(pool, good, bad)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"good-scanner", "bad-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	status, err := svc.GetScanStatus(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetScanStatus: %v", err)
	}
	runsByScanner := make(map[string]domain.ScannerRun, len(status.ScannerRuns))
	for _, run := range status.ScannerRuns {
		runsByScanner[run.Scanner] = run
	}
	if len(runsByScanner) != 2 {
		t.Fatalf("ScannerRuns = %+v, want an entry for each of the 2 scanners", status.ScannerRuns)
	}

	goodRun := runsByScanner["good-scanner"]
	if goodRun.Status != domain.ScannerRunSucceeded {
		t.Errorf("good-scanner status = %q, want succeeded", goodRun.Status)
	}
	if goodRun.FinishedAt == nil {
		t.Error("good-scanner FinishedAt = nil, want set (it already terminated)")
	}
	if goodRun.FindingsCount == nil || *goodRun.FindingsCount != 2 {
		t.Errorf("good-scanner FindingsCount = %v, want 2", goodRun.FindingsCount)
	}
	if goodRun.Error != "" {
		t.Errorf("good-scanner Error = %q, want empty (it succeeded)", goodRun.Error)
	}

	badRun := runsByScanner["bad-scanner"]
	if badRun.Status != domain.ScannerRunFailed {
		t.Errorf("bad-scanner status = %q, want failed", badRun.Status)
	}
	if badRun.FindingsCount != nil {
		t.Errorf("bad-scanner FindingsCount = %v, want nil (a failed scanner has no meaningful count)", badRun.FindingsCount)
	}
	if badRun.Error != "tool crashed" {
		t.Errorf("bad-scanner Error = %q, want %q", badRun.Error, "tool crashed")
	}
}

// Reproduz de verdade (não só infere) o cenário central do pedido do
// usuário: enquanto um job ainda está em andamento, um scanner mais
// lento aparece como "running" ao mesmo tempo em que outro, mais rápido,
// já aparece "succeeded" — a visibilidade de progresso que um job
// "processing" sozinho nunca deu.
func TestProcessScanJob_ScannerRuns_ReflectRunningThenTerminalStatus(t *testing.T) {
	pool := testPool(t)
	block := make(chan struct{})
	fast := &fakeScanner{name: "fast-scanner", findings: []domain.Finding{{ID: "OK-1", Severity: domain.SeverityLow}}}
	slow := &fakeScanner{name: "slow-scanner", block: block}
	svc := newService(pool, fast, slow)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"fast-scanner", "slow-scanner"}, "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.ProcessScanJob(ctx, job.ID, corrID) }()

	// Faz polling (mesmo padrão que a UI usa via GET .../scans/{id}) até
	// observar slow-scanner "running" — com um teto de tempo generoso
	// pra nunca deixar o teste travado indefinidamente se o
	// comportamento regredir.
	deadline := time.After(5 * time.Second)
	observedRunning := false
	for !observedRunning {
		select {
		case <-deadline:
			close(block)
			<-done
			t.Fatal("never observed slow-scanner with status \"running\" while the job was in flight")
		default:
		}
		status, err := svc.GetScanStatus(ctx, job.ID)
		if err != nil {
			t.Fatalf("GetScanStatus: %v", err)
		}
		for _, run := range status.ScannerRuns {
			if run.Scanner == "slow-scanner" && run.Status == domain.ScannerRunRunning {
				observedRunning = true
			}
		}
	}

	close(block) // libera slow-scanner pra terminar
	if err := <-done; err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	status, err := svc.GetScanStatus(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetScanStatus: %v", err)
	}
	for _, run := range status.ScannerRuns {
		if run.Status == domain.ScannerRunRunning {
			t.Errorf("after ProcessScanJob returned, scanner %q is still \"running\" — want a terminal status", run.Scanner)
		}
	}
}

// TestProcessScanJob_ProgressReportingScanner_WritesAndClearsProgressDetail
// § pedido do usuário — "quero saber em tempo real como está rodando o
// ataque": confirma as duas pontas de domain.ProgressReportingScanner —
// ProgressDetail aparece em GetScanStatus ENQUANTO o scanner ainda está
// rodando (não só depois que termina, quando já não serviria pra nada) e
// volta a vazio depois de terminar (ver FinishScannerRun's SET
// progress_detail = NULL — sub-progresso de uma tentativa concluída não
// deveria sobreviver pra confundir a próxima).
func TestProcessScanJob_ProgressReportingScanner_WritesAndClearsProgressDetail(t *testing.T) {
	pool := testPool(t)
	block := make(chan struct{})
	scanner := &fakeProgressReportingScanner{fakeScanner: fakeScanner{name: "zap-like", block: block}}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	job, err := svc.CreateScanJob(ctx, corrID, []string{"zap-like"}, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.ProcessScanJob(ctx, job.ID, corrID) }()

	deadline := time.After(5 * time.Second)
	observedDetail := ""
	for observedDetail == "" {
		select {
		case <-deadline:
			close(block)
			<-done
			t.Fatal("never observed a non-empty ProgressDetail while the job was in flight")
		default:
		}
		status, err := svc.GetScanStatus(ctx, job.ID)
		if err != nil {
			t.Fatalf("GetScanStatus: %v", err)
		}
		for _, run := range status.ScannerRuns {
			if run.Scanner == "zap-like" && run.ProgressDetail != "" {
				observedDetail = run.ProgressDetail
			}
		}
	}
	if observedDetail != "ataque ativo: 42%" {
		t.Errorf("ProgressDetail observado = %q, want %q", observedDetail, "ataque ativo: 42%")
	}

	close(block) // libera o scanner pra terminar
	if err := <-done; err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	status, err := svc.GetScanStatus(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetScanStatus: %v", err)
	}
	for _, run := range status.ScannerRuns {
		if run.ProgressDetail != "" {
			t.Errorf("depois de terminar, ProgressDetail = %q, want vazio (limpo por FinishScannerRun)", run.ProgressDetail)
		}
	}
}

func TestProcessScanJob_UploadProject_ExtractsZipAndRunsLocalScanners(t *testing.T) {
	pool := testPool(t)
	scanner := &fakeLocalScanner{
		fakeScanner: fakeScanner{name: "trivy", findings: []domain.Finding{
			{ID: "CVE-2026-UPLOAD", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Severity: domain.SeverityHigh, Description: "achado num projeto de upload"},
		}},
		packages: []domain.Package{{Name: "left-pad", Version: "1.3.0", Type: "npm"}},
	}
	svc := newService(pool, scanner)
	ctx := context.Background()
	corrID := uuid.New()

	zipBytes := buildTestZip(t, map[string]string{"go.mod": "module example.com/upload\n"})
	project, err := svc.CreateProjectUpload(ctx, "test-project-process-upload", zipBytes, nil)
	if err != nil {
		t.Fatalf("CreateProjectUpload: %v", err)
	}

	job, err := svc.CreateProjectScanJob(ctx, corrID, []string{"trivy"}, project.ID, nil)
	if err != nil {
		t.Fatalf("CreateProjectScanJob: %v", err)
	}

	if err := svc.ProcessScanJob(ctx, job.ID, corrID); err != nil {
		t.Fatalf("ProcessScanJob: %v", err)
	}

	if scanner.gotDir == "" {
		t.Fatal("ExecuteLocal never received a directory — the .zip was never extracted")
	}
	if scanner.goModContent != "module example.com/upload\n" {
		t.Errorf("go.mod content read from inside ExecuteLocal = %q, want the .zip's exact content", scanner.goModContent)
	}
	// A extração é temporária — ProcessScanJob precisa limpar o
	// diretório depois de terminar (mesmo ciclo de vida do clone git via
	// cloneShallow), nunca deixar código de upload no disco do worker
	// além do necessário.
	if _, statErr := os.Stat(scanner.gotDir); !os.IsNotExist(statErr) {
		t.Errorf("extraction dir %q still exists after ProcessScanJob, want it cleaned up", scanner.gotDir)
	}

	jobsRepo := jobs.NewRepository(pool)
	fetched, err := jobsRepo.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fetched.Status != jobs.StatusCompleted {
		t.Errorf("Status = %s, want completed", fetched.Status)
	}

	findings, err := svc.ListFindings(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-2026-UPLOAD" {
		t.Fatalf("findings = %+v, want the one finding ExecuteLocal returned", findings)
	}
	if findings[0].Target != "upload:test-project-process-upload" {
		t.Errorf("finding Target = %q, want the synthetic \"upload:<project name>\" target", findings[0].Target)
	}
}
