// Package application implements the integrations module's use cases
// (§22): ListIntegrations, GetIntegrationStatus, plus RecordCheckResult —
// a generic status-check service the diario_oficial and secops worker
// handlers call after running a test, so integration health tracking
// isn't duplicated per module.
package application

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yurythx/nix-platform/internal/modules/integrations/domain"
)

type Service struct {
	repo domain.Repository
}

func NewService(repo domain.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListIntegrations(ctx context.Context) ([]*domain.Integration, error) {
	return s.repo.List(ctx)
}

func (s *Service) GetIntegrationStatus(ctx context.Context, id uuid.UUID) (*domain.Integration, error) {
	return s.repo.GetByID(ctx, id)
}

// RecordCheckResult updates the named integration's status on tx and
// reports whether the status actually changed, so the caller can decide
// whether to also write an integration.status.changed outbox event on the
// same transaction.
func (s *Service) RecordCheckResult(ctx context.Context, tx pgx.Tx, key string, success bool, lastError string) (*domain.Integration, bool, error) {
	var errPtr *string
	if lastError != "" {
		errPtr = &lastError
	}

	updated, changed, err := s.repo.UpdateStatusTx(ctx, tx, key, success, errPtr)
	if err != nil {
		return nil, false, fmt.Errorf("integrations: record check result for %q: %w", key, err)
	}
	return updated, changed, nil
}
