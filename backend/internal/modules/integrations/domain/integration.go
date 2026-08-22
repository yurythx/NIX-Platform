// Package domain guarda a entidade e o contrato de repositório do módulo
// integrations (§74).
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Status é o último estado de saúde conhecido de uma integração (§42/§74).
type Status string

const (
	StatusUnknown  Status = "unknown"
	StatusOnline   Status = "online"
	StatusOffline  Status = "offline"
	StatusDegraded Status = "degraded"
	StatusDisabled Status = "disabled"
)

// Integration é um sistema externo configurado, do qual a plataforma pode
// consultar o status e, para alguns tipos, disparar uma execução de teste
// (ex.: Diário Oficial, VirusTotal).
type Integration struct {
	ID            uuid.UUID
	Key           string
	Name          string
	Type          string
	Enabled       bool
	Status        Status
	LastCheckAt   *time.Time
	LastSuccessAt *time.Time
	LastError     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Repository persiste as linhas de Integration.
type Repository interface {
	List(ctx context.Context) ([]*Integration, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Integration, error)
	GetByKey(ctx context.Context, key string) (*Integration, error)

	// UpdateStatusTx registra o resultado de uma verificação de
	// saúde/teste para a integração identificada por key, na transação de
	// quem chama, para que possa ser commitada atomicamente junto de um
	// evento de outbox quando o status realmente mudar (a routing key
	// integration.status.changed do §9). changed reporta exatamente isso
	// — só vale a pena publicar o evento quando o status observado é
	// diferente do que já estava gravado, evitando notificar o frontend
	// de "mudanças" que não mudaram nada.
	UpdateStatusTx(ctx context.Context, tx pgx.Tx, key string, success bool, lastError *string) (updated *Integration, changed bool, err error)
}
