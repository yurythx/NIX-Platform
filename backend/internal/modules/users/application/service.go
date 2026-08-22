// Package application implementa os casos de uso do módulo users (§22):
// CreateUser (implicitamente, via SyncFromIdentity), GetCurrentUser,
// ListUsers.
package application

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/users/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
)

// SyncIdentityInput é o subconjunto da identidade de um chamador
// autenticado que o módulo users precisa. Definido aqui (não importado de
// internal/platform/auth) para que esta camada continue desacoplada da
// preocupação de transporte OIDC, conforme §21/§22 — o caso de uso não
// sabe (nem precisa saber) que a identidade veio de um token Keycloak.
type SyncIdentityInput struct {
	Subject  string
	Username string
	Email    string
}

// Service implementa os casos de uso do módulo users.
type Service struct {
	repo  domain.Repository
	audit *audit.Writer
}

func NewService(repo domain.Repository, auditWriter *audit.Writer) *Service {
	return &Service{repo: repo, audit: auditWriter}
}

// GetCurrentUser implementa "GetCurrentUser" (§22): faz upsert da linha de
// usuário a partir da identidade já verificada (criando-a no primeiro
// acesso) e a retorna. Chamado por GET /api/v1/me — é o mecanismo que
// mantém a tabela local de usuários sincronizada com o Keycloak sem um
// fluxo de cadastro separado: o primeiro login já cria a conta.
func (s *Service) GetCurrentUser(ctx context.Context, in SyncIdentityInput) (*domain.User, error) {
	if in.Subject == "" {
		return nil, apperrors.Unauthorized("missing subject")
	}

	result, err := s.repo.UpsertByKeycloakSubject(ctx, &domain.User{
		KeycloakSubject: in.Subject,
		Username:        in.Username,
		Email:           in.Email,
		Active:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("users: sync current user: %w", err)
	}

	// Só registra na auditoria quando a conta é criada de fato — logins
	// subsequentes do mesmo usuário apenas atualizam last_seen_at
	// silenciosamente, sem gerar uma entrada de auditoria a cada request.
	if result.Created && s.audit != nil {
		uid := result.User.ID
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:       &uid,
			Action:       audit.ActionUserCreated,
			ResourceType: "user",
			ResourceID:   uid.String(),
		})
	}

	return result.User, nil
}

// ListUsers implementa "ListUsers" (§22).
func (s *Service) ListUsers(ctx context.Context, p pagination.Params) ([]*domain.User, pagination.Meta, error) {
	users, total, err := s.repo.List(ctx, p)
	if err != nil {
		return nil, pagination.Meta{}, fmt.Errorf("users: list: %w", err)
	}
	return users, pagination.NewMeta(p, total), nil
}

// GetUser busca um único usuário pelo id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return u, nil
}
