// Arquivo projects.go: a entidade Project (Fase 10 do roadmap de
// segurança) — criação via URL git ou upload de .zip, listagem e
// busca por id. Extraído de service.go (ver nota em scans.go) —
// mesmo pacote application, mesmo *Service.
package application

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
)

// maxUploadZipBytes limita o tamanho do PRÓPRIO arquivo .zip aceito ao
// criar um projeto por upload (Fase 10) — diferente de
// infrastructure.maxZipUncompressedBytes (o teto do conteúdo
// DESCOMPRIMIDO, aplicado só na hora de escanear). Este teto aqui protege
// a gravação em si: Project.UploadZip vive numa coluna BYTEA do Postgres,
// e um blob sem limite nenhum seria seu próprio problema de capacidade,
// bem antes de qualquer scan rodar.
const maxUploadZipBytes = 50 * 1024 * 1024 // 50MB

// CreateProjectGit cria um domain.Project (Fase 10) apontando pra um alvo
// git — mesma filosofia de validação "preguiçosa" que um scan avulso já
// usa: só confere que target não é vazio aqui; o formato completo
// (https://, host não-privado) só é validado de verdade na hora de
// escanear (git_clone.go's parseGitTarget/validateHost, dentro do
// worker) — nunca duplicado aqui, pra nunca divergir entre as duas
// validações.
func (s *Service) CreateProjectGit(ctx context.Context, name, target string, requestedBy *uuid.UUID) (*domain.Project, error) {
	if name == "" {
		return nil, apperrors.Validation("name is required")
	}
	if target == "" {
		return nil, apperrors.Validation("target is required")
	}

	p := domain.Project{ID: uuid.New(), Name: name, SourceType: domain.ProjectSourceGit, Target: target, CreatedAt: time.Now()}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, fmt.Errorf("scanning: create project: %w", err)
	}
	s.recordProjectCreated(ctx, p, requestedBy)
	return &p, nil
}

// recordProjectCreated grava a auditoria de um projeto novo (Fase 10) —
// achado de auditoria: CreateProjectGit/CreateProjectUpload não tinham
// nenhum registro, ao contrário de createScanJob (ActionScanRequested),
// mesmo criar um projeto por upload guardando até 50MB de código de
// terceiros. Best-effort (audit pode ser nil, mesmo princípio do resto
// do Service) — nunca falha a criação do projeto por conta disto.
func (s *Service) recordProjectCreated(ctx context.Context, p domain.Project, requestedBy *uuid.UUID) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Entry{
		UserID:       requestedBy,
		Action:       audit.ActionProjectCreated,
		ResourceType: "project",
		ResourceID:   p.ID.String(),
		Metadata:     map[string]any{"name": p.Name, "source_type": string(p.SourceType), "target": p.Target},
	})
}

// CreateProjectUpload cria um domain.Project (Fase 10) a partir dos bytes
// de um .zip — nunca extraído nem validado como zip aqui (isso só
// acontece de verdade na hora de escanear, ZipExtractor.ExtractZip,
// dentro do worker), mesmo princípio de CreateProjectGit acima: valida só
// o suficiente pra rejeitar entrada obviamente inválida cedo (vazio,
// grande demais), sem duplicar a validação de conteúdo que já vive em
// outro lugar.
func (s *Service) CreateProjectUpload(ctx context.Context, name string, zipBytes []byte, requestedBy *uuid.UUID) (*domain.Project, error) {
	if name == "" {
		return nil, apperrors.Validation("name is required")
	}
	if len(zipBytes) == 0 {
		return nil, apperrors.Validation("zip file is required")
	}
	if len(zipBytes) > maxUploadZipBytes {
		return nil, apperrors.Validation(fmt.Sprintf("zip file exceeds the %dMB limit", maxUploadZipBytes/(1024*1024)))
	}

	p := domain.Project{ID: uuid.New(), Name: name, SourceType: domain.ProjectSourceUpload, UploadZip: zipBytes, CreatedAt: time.Now()}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, fmt.Errorf("scanning: create project: %w", err)
	}
	s.recordProjectCreated(ctx, p, requestedBy)
	return &p, nil
}

// maxProjectsList é o teto de ListProjects — mesmo espírito de
// maxRecentScans/maxRecentFindings.
const maxProjectsList = 100

// ListProjects retorna os projetos mais recentes primeiro.
func (s *Service) ListProjects(ctx context.Context, limit int) ([]domain.Project, error) {
	if limit <= 0 || limit > maxProjectsList {
		limit = maxProjectsList
	}
	projects, err := s.repo.ListProjects(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list projects: %w", err)
	}
	return projects, nil
}

// GetProject busca um projeto por ID.
func (s *Service) GetProject(ctx context.Context, id uuid.UUID) (domain.Project, error) {
	p, err := s.repo.GetProject(ctx, id)
	if err != nil {
		return domain.Project{}, err
	}
	return p, nil
}
