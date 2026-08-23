// Package domain guarda a entidade e o contrato de repositório do módulo
// users. Não importa nada de HTTP, RabbitMQ, PostgreSQL ou Keycloak —
// essas dependências pertencem a transport/infrastructure, mantendo a
// regra de negócio isolada de detalhes de implementação.
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
)

// User é uma conta do NIX Platform. A maioria é espelhada do Keycloak a
// cada requisição autenticada (o Keycloak é a fonte da verdade da
// identidade; a linha local guarda só o que a própria plataforma precisa
// — §32, ex.: para referenciar o usuário em audit_logs ou exibir uma
// lista de usuários sem chamar o Keycloak a cada consulta). KeycloakSubject
// é nil para uma conta de login local (§ Sistema de Login Local) — essas
// não têm origem no Keycloak, então não faz sentido ter um "sub" dele.
type User struct {
	ID              uuid.UUID
	KeycloakSubject *string
	Username        string
	Email           string
	DisplayName     string
	Active          bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastSeenAt      *time.Time
}

// UpsertResult reporta se o Upsert criou uma linha nova, para que quem
// chama decida se um registro de auditoria user.created é necessário
// (só faz sentido registrar a criação, não toda atualização de
// last_seen_at a cada login).
type UpsertResult struct {
	User    *User
	Created bool
}

// Repository persiste as linhas de User.
type Repository interface {
	// UpsertByKeycloakSubject cria o usuário se esta for a primeira vez
	// que este subject do Keycloak é visto, ou atualiza
	// username/email/last_seen_at caso contrário — é assim que a conta
	// local "nasce" no primeiro login, sem um passo de cadastro separado.
	UpsertByKeycloakSubject(ctx context.Context, u *User) (UpsertResult, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	List(ctx context.Context, p pagination.Params) ([]*User, int64, error)
}
