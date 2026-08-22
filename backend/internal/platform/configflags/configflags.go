// Package configflags implementa feature flags com alteração dinâmica em
// tempo de execução (§ Feature Flags & Configuração Dinâmica): um
// interruptor booleano por chave, persistido no Postgres, que qualquer
// caso de uso pode consultar antes de disparar uma chamada externa ou um
// agendamento — sem precisar reiniciar o processo (nem cmd/api nem
// cmd/worker) para ligar/desligar uma integração.
//
// Deliberadamente sem cache em memória: cada IsEnabled faz uma consulta
// direta ao Postgres, no mesmo espírito de
// internal/platform/ratelimit.PostgresLimiter — um SELECT por chave
// primária é barato, e evitar um cache elimina toda uma classe de bugs de
// "a flag foi trocada no admin mas essa réplica só vai perceber daqui a N
// segundos". Como as flags só são checadas antes de uma chamada de rede a
// um provedor externo (não em todo request HTTP), o custo extra de uma
// consulta ao Postgres é irrelevante frente à latência da própria chamada
// que ela está decidindo se deve ou não disparar.
package configflags

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// Flag é o estado persistido de uma feature flag.
type Flag struct {
	Key         string
	Enabled     bool
	Description string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// Store persiste e consulta feature flags. Os casos de uso dependem desta
// interface, não de *PostgresStore diretamente — o campo Flags de um
// Service pode ficar nil (ver diario_oficial/secops application.Service),
// e nesse caso a checagem é pulada e a funcionalidade correspondente é
// tratada como sempre habilitada; isso mantém os testes de aplicação
// existentes funcionando sem precisar semear flags para cada cenário.
type Store interface {
	// IsEnabled reporta se key está habilitada. Se a chave nunca foi
	// registrada (nenhuma linha em feature_flags), retorna defaultValue —
	// assim uma flag ainda não semeada nunca bloqueia silenciosamente uma
	// funcionalidade que o operador nem sabia que precisava registrar.
	IsEnabled(ctx context.Context, key string, defaultValue bool) (bool, error)

	// List retorna toda flag registrada, ordenada por chave — usado pelo
	// endpoint administrativo de listagem.
	List(ctx context.Context) ([]Flag, error)

	// Set cria ou atualiza uma flag. updatedBy é o subject do
	// administrador que fez a alteração (auditoria — ver transport.go).
	Set(ctx context.Context, key string, enabled bool, updatedBy string) (Flag, error)
}

// PostgresStore implementa Store sobre a tabela feature_flags (migration
// 000010).
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

// IsEnabled consulta o Postgres diretamente a cada chamada — sem cache,
// ver o comentário do pacote (Store.IsEnabled).
func (s *PostgresStore) IsEnabled(ctx context.Context, key string, defaultValue bool) (bool, error) {
	var enabled bool
	err := s.pool.QueryRow(ctx, `SELECT enabled FROM feature_flags WHERE key = $1`, key).Scan(&enabled)
	result := defaultValue
	switch {
	case err == nil:
		result = enabled
	case err == pgx.ErrNoRows:
		// Sem registro — usa o padrão do chamador, sem erro: uma flag
		// nunca criada não é uma condição excepcional.
	default:
		return false, fmt.Errorf("configflags: check %q: %w", key, err)
	}

	label := "disabled"
	if result {
		label = "enabled"
	}
	metrics.FeatureFlagChecksTotal.WithLabelValues(key, label).Inc()
	return result, nil
}

// List retorna toda flag registrada, ordenada por chave (ver Store.List).
func (s *PostgresStore) List(ctx context.Context) ([]Flag, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, enabled, description, updated_at, coalesce(updated_by, '') FROM feature_flags ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("configflags: list: %w", err)
	}
	defer rows.Close()

	var out []Flag
	for rows.Next() {
		var f Flag
		if err := rows.Scan(&f.Key, &f.Enabled, &f.Description, &f.UpdatedAt, &f.UpdatedBy); err != nil {
			return nil, fmt.Errorf("configflags: scan: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("configflags: iterate: %w", err)
	}
	return out, nil
}

// Set faz upsert de key: cria a flag na primeira alteração (com uma
// descrição vazia, caso ninguém a tenha semeado via migration) ou
// atualiza enabled/updated_by numa flag já existente.
func (s *PostgresStore) Set(ctx context.Context, key string, enabled bool, updatedBy string) (Flag, error) {
	const q = `
		INSERT INTO feature_flags (key, enabled, description, updated_at, updated_by)
		VALUES ($1, $2, '', now(), $3)
		ON CONFLICT (key) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			updated_at = now(),
			updated_by = EXCLUDED.updated_by
		RETURNING key, enabled, description, updated_at, coalesce(updated_by, '')
	`
	var f Flag
	err := s.pool.QueryRow(ctx, q, key, enabled, updatedBy).Scan(&f.Key, &f.Enabled, &f.Description, &f.UpdatedAt, &f.UpdatedBy)
	if err != nil {
		return Flag{}, fmt.Errorf("configflags: set %q: %w", key, err)
	}
	return f, nil
}
