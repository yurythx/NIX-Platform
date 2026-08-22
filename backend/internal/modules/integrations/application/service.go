// Package application implementa os casos de uso do módulo integrations
// (§22): ListIntegrations, GetIntegrationStatus, e RecordCheckResult — um
// serviço genérico de verificação de status que os workers de
// diario_oficial e secops chamam depois de rodar um teste, para que o
// rastreamento de saúde de integração não seja duplicado em cada módulo.
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

// RecordCheckResult atualiza o status da integração identificada por key
// em tx e reporta se o status de fato mudou, para que quem chama decida
// se também deve gravar um evento de outbox integration.status.changed
// na mesma transação. É chamado pelos workers de diario_oficial/secops
// logo depois de executarem um teste de conectividade (sucesso ou falha),
// nunca diretamente por um handler HTTP.
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
