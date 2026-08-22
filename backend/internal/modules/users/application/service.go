// Package application implements the users module's use cases (§22):
// CreateUser (implicitly, via SyncFromIdentity), GetCurrentUser, ListUsers.
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

// SyncIdentityInput is the subset of an authenticated caller's identity
// the users module needs. Defined here (not imported from
// internal/platform/auth) so this layer stays decoupled from the OIDC
// transport concern per §21/§22.
type SyncIdentityInput struct {
	Subject  string
	Username string
	Email    string
}

// Service implements the users module's use cases.
type Service struct {
	repo  domain.Repository
	audit *audit.Writer
}

func NewService(repo domain.Repository, auditWriter *audit.Writer) *Service {
	return &Service{repo: repo, audit: auditWriter}
}

// GetCurrentUser implements "GetCurrentUser" (§22): it upserts the user
// row from the verified identity (creating it on first sight) and returns
// it. Called by GET /api/v1/me.
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

// ListUsers implements "ListUsers" (§22).
func (s *Service) ListUsers(ctx context.Context, p pagination.Params) ([]*domain.User, pagination.Meta, error) {
	users, total, err := s.repo.List(ctx, p)
	if err != nil {
		return nil, pagination.Meta{}, fmt.Errorf("users: list: %w", err)
	}
	return users, pagination.NewMeta(p, total), nil
}

// GetUser fetches a single user by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return u, nil
}
