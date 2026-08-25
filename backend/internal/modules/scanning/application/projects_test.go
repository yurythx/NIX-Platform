// Testes de projects.go (CreateProjectGit/CreateProjectUpload/ListProjects/GetProject).
// Fixtures/fakes compartilhados continuam em service_test.go (ver nota em scans_test.go).
package application

import (
	"context"
	"testing"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

func TestCreateProjectGit_RequiresNameAndTarget(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	if _, err := svc.CreateProjectGit(ctx, "", "https://example.com/repo.git", nil); err == nil {
		t.Error("expected an error for an empty name")
	}
	if _, err := svc.CreateProjectGit(ctx, "test-project-empty-target", "", nil); err == nil {
		t.Error("expected an error for an empty target")
	}
}

func TestCreateProjectGit_And_ListProjects_RoundTrip(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	created, err := svc.CreateProjectGit(ctx, "test-project-roundtrip", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}
	if created.SourceType != domain.ProjectSourceGit {
		t.Errorf("SourceType = %q, want %q", created.SourceType, domain.ProjectSourceGit)
	}

	fetched, err := svc.GetProject(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if fetched.Name != "test-project-roundtrip" || fetched.Target != "https://example.com/repo.git" {
		t.Errorf("fetched project = %+v, unexpected fields", fetched)
	}

	projects, err := svc.ListProjects(ctx, 0)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	var found bool
	for _, p := range projects {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("ListProjects did not include the project just created")
	}
}

// TestCreateProject_RecordsAuditEntry cobre um achado de auditoria:
// CreateProjectGit/CreateProjectUpload não gravavam NENHUMA entrada em
// audit_logs, ao contrário de createScanJob (ActionScanRequested) — um
// upload guarda até 50MB de código de terceiros e uma URL git passa a
// ser re-escaneada a cada "Rodar de novo" sem confirmação nova, as duas
// merecem rastro de quem criou. Usa um audit.Writer de VERDADE (não nil,
// ao contrário de newService/newServiceWithFlags) pra provar que a linha
// é realmente persistida, não só que Record foi chamado. requestedBy
// fica nil (audit_logs.user_id é NULLABLE e tem FOREIGN KEY pra users —
// um uuid.New() aleatório, sem linha correspondente em users, faria o
// INSERT falhar por violação de FK, silenciosamente engolido pelo "_ ="
// de recordProjectCreated; testar quem criou de verdade exigiria semear
// uma linha em users antes, fora do escopo deste teste).
func TestCreateProject_RecordsAuditEntry(t *testing.T) {
	pool := testPool(t)
	repo := infrastructure.NewPostgresRepository(pool)
	jobsRepo := jobs.NewRepository(pool)
	outboxWriter := outbox.NewWriter("nix.test")
	zipExtractor := infrastructure.NewZipExtractor("", testLogger())
	auditWriter := audit.NewWriter(pool)
	svc := NewService(pool, repo, jobsRepo, outboxWriter, auditWriter, zipExtractor, nil, nil, testLogger())
	ctx := context.Background()

	created, err := svc.CreateProjectGit(ctx, "test-project-audit", "https://example.com/repo.git", nil)
	if err != nil {
		t.Fatalf("CreateProjectGit: %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE resource_type = 'project' AND resource_id = $1 AND action = $2`,
		created.ID.String(), audit.ActionProjectCreated,
	).Scan(&n); err != nil {
		t.Fatalf("count audit_logs: %v", err)
	}
	if n == 0 {
		t.Error("CreateProjectGit did not record an audit_logs entry")
	}
}

func TestGetProject_UnknownID_ReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)

	_, err := svc.GetProject(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error for an unknown project ID")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeNotFound {
		t.Errorf("err = %v, want a NOT_FOUND apperrors.Error", err)
	}
}

func TestCreateProjectUpload_RequiresNameAndBytesAndSizeLimit(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	if _, err := svc.CreateProjectUpload(ctx, "", []byte("pretend zip bytes"), nil); err == nil {
		t.Error("expected an error for an empty name")
	}
	if _, err := svc.CreateProjectUpload(ctx, "test-project-empty-zip", nil, nil); err == nil {
		t.Error("expected an error for empty zip bytes")
	}
	oversized := make([]byte, maxUploadZipBytes+1)
	if _, err := svc.CreateProjectUpload(ctx, "test-project-oversized-zip", oversized, nil); err == nil {
		t.Error("expected an error for a zip file over the size limit")
	}
}

func TestCreateProjectUpload_And_GetProject_RoundTrip(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool)
	ctx := context.Background()

	zipBytes := []byte("pretend zip bytes, never parsed at project-creation time")
	created, err := svc.CreateProjectUpload(ctx, "test-project-upload-roundtrip", zipBytes, nil)
	if err != nil {
		t.Fatalf("CreateProjectUpload: %v", err)
	}
	if created.SourceType != domain.ProjectSourceUpload {
		t.Errorf("SourceType = %q, want %q", created.SourceType, domain.ProjectSourceUpload)
	}
	if created.Target != "" {
		t.Errorf("Target = %q, want empty for an upload-based project", created.Target)
	}

	fetched, err := svc.GetProject(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if string(fetched.UploadZip) != string(zipBytes) {
		t.Errorf("UploadZip round-tripped = %q, want %q", fetched.UploadZip, zipBytes)
	}
}
