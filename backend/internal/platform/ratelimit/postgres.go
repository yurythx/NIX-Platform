// Package ratelimit implements a rate limiter shared across every API
// replica, usando PostgreSQL como armazenamento comum — a plataforma não
// usa Redis por decisão arquitetural (§7), e como já existe um Postgres
// compartilhado por todos os processos, ele serve perfeitamente para isto
// também, sem introduzir mais uma peça de infraestrutura.
//
// Algoritmo: janela fixa (fixed window), não token bucket contínuo. A
// diferença prática: com janela fixa, um cliente pode em teoria enviar até
// 2x o limite configurado bem na fronteira entre duas janelas (um burst no
// fim de uma janela seguido de outro burst logo no início da próxima).
// Escolhido mesmo assim porque um único UPSERT é atomicamente seguro sob
// concorrência no Postgres sem precisar de transação/lock explícito — o
// que token bucket exigiria (ler o saldo de tokens, calcular reposição
// desde a última leitura, escrever de volta, tudo dentro de uma
// transação). Para o propósito de rate limiting de API (impedir abuso
// grosseiro, não uma vazão milimetricamente uniforme), essa imprecisão na
// borda da janela é um trade-off aceitável pela simplicidade e
// atomicidade sem lock.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresLimiter implements httpserver.Limiter, compartilhado por todas
// as réplicas da API através da tabela rate_limit_buckets.
type PostgresLimiter struct {
	pool          *pgxpool.Pool
	windowSeconds int
	maxRequests   int
}

// NewPostgresLimiter permite até maxRequests requisições por chave a cada
// janela de windowSeconds segundos.
func NewPostgresLimiter(pool *pgxpool.Pool, windowSeconds, maxRequests int) *PostgresLimiter {
	return &PostgresLimiter{pool: pool, windowSeconds: windowSeconds, maxRequests: maxRequests}
}

// Allow incrementa o contador da janela atual para key e reporta se o
// resultado ainda está dentro do limite. Um único UPSERT: se a janela
// mudou desde a última requisição desta chave, o contador reseta para 1;
// senão, soma 1 ao valor existente — sem race condition possível entre
// réplicas concorrentes, já que o Postgres serializa updates na mesma
// linha automaticamente.
func (l *PostgresLimiter) Allow(ctx context.Context, key string) (bool, error) {
	const q = `
		WITH window_calc AS (
			SELECT to_timestamp(floor(extract(epoch FROM now()) / $2::float8) * $2::float8) AS window_start
		)
		INSERT INTO rate_limit_buckets (key, window_start, count)
		SELECT $1, window_start, 1 FROM window_calc
		ON CONFLICT (key) DO UPDATE SET
			count = CASE
				WHEN rate_limit_buckets.window_start = EXCLUDED.window_start
				THEN rate_limit_buckets.count + 1
				ELSE 1
			END,
			window_start = EXCLUDED.window_start
		RETURNING count
	`

	var count int
	err := l.pool.QueryRow(ctx, q, key, l.windowSeconds).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ratelimit: check key %q: %w", key, err)
	}

	return count <= l.maxRequests, nil
}

// Cleanup apaga janelas antigas periodicamente, para que a tabela não
// cresça indefinidamente com chaves (usuários/IPs) que só apareceram uma
// vez e nunca mais voltaram. Registrado como um processor do worker.
func Cleanup(pool *pgxpool.Pool) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				_, err := pool.Exec(ctx, `DELETE FROM rate_limit_buckets WHERE window_start < now() - interval '1 hour'`)
				if err != nil {
					return fmt.Errorf("ratelimit: cleanup: %w", err)
				}
			}
		}
	}
}
