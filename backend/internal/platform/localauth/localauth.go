// Package localauth implementa o login local por usuário/senha
// (§ Sistema de Login Local): um caminho de autenticação ADICIONAL ao
// Keycloak, nunca um substituto — pensado para desenvolvimento/teste, onde
// depender de um Keycloak sempre acessível é atrito, e como conta de
// emergência caso o Keycloak externo fique fora do ar. A verificação do
// token resultante mora em internal/platform/auth (que já sabia validar
// tokens do Keycloak); este pacote só cuida do lado "entrada": conferir a
// senha e emitir o token.
//
// Só existe uma tabela de usuários — a mesma que já espelha contas do
// Keycloak (migration 000011 tornou keycloak_subject opcional e adicionou
// password_hash/roles). Uma conta local é só uma linha de "users" sem
// keycloak_subject e com password_hash preenchido.
package localauth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Account é o subconjunto de uma linha de "users" necessário para
// autenticar um login local — nunca é serializado de volta ao cliente
// (PasswordHash em especial não pode vazar em resposta HTTP nenhuma).
type Account struct {
	ID           uuid.UUID
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	Roles        []string
	Active       bool
}

// Store persiste e consulta contas locais.
type Store interface {
	// GetByUsername busca uma conta local pelo username. Retorna
	// pgx.ErrNoRows (envolto) se não existir NENHUM usuário com esse
	// username, ou se existir mas for uma conta só-Keycloak
	// (password_hash NULL) — as duas situações são tratadas da mesma
	// forma pelo handler de login (credenciais inválidas), para não
	// revelar a um atacante qual delas ocorreu.
	GetByUsername(ctx context.Context, username string) (*Account, error)

	// TouchLastSeen atualiza last_seen_at após um login bem-sucedido — o
	// mesmo campo que o fluxo do Keycloak atualiza a cada upsert (ver
	// users.Repository.UpsertByKeycloakSubject), para que a lista de
	// usuários no dashboard reflita atividade recente independente de
	// qual caminho de login foi usado.
	TouchLastSeen(ctx context.Context, id uuid.UUID) error
}

// PostgresStore implementa Store sobre a tabela users compartilhada com o
// módulo users.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) GetByUsername(ctx context.Context, username string) (*Account, error) {
	const q = `
		SELECT id, username, email, display_name, password_hash, roles, active
		FROM users
		WHERE username = $1 AND password_hash IS NOT NULL
	`
	var a Account
	err := s.pool.QueryRow(ctx, q, username).Scan(
		&a.ID, &a.Username, &a.Email, &a.DisplayName, &a.PasswordHash, &a.Roles, &a.Active,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("localauth: get by username: %w", err)
	}
	return &a, nil
}

func (s *PostgresStore) TouchLastSeen(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE users SET last_seen_at = now() WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("localauth: touch last seen: %w", err)
	}
	return nil
}
