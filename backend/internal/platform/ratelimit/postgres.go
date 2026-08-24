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
//
// bucket namespaceia as linhas desta instância dentro da tabela
// COMPARTILHADA por toda instância de PostgresLimiter da aplicação —
// achado real de auditoria: antes de existir, dois limiters diferentes
// (ex.: ScanJob, janela de 60s, e TestJob, janela de 10s) escreviam na
// MESMA linha sempre que o "key" calculado por quem chama (tipicamente o
// subject do usuário autenticado) coincidia entre rotas — o que é o caso
// comum, já que scanning.RateLimitKey e diario_oficial.RateLimitKey
// devolvem literalmente o mesmo valor pro mesmo usuário. Cada limiter
// recalculava window_start com o SEU PRÓPRIO windowSeconds, quase nunca
// batendo com o que a última chamada (de um limiter DIFERENTE) tinha
// gravado — o contador resetava a cada troca de rota, e nenhum dos dois
// limites era de fato aplicado (um anulava o outro). bucket precisa ser
// um valor ESTÁTICO e ÚNICO por instância (ex.: "scan_job", "test_job")
// — nunca derivado de dado de requisição, que é o papel de key.
type PostgresLimiter struct {
	pool          *pgxpool.Pool
	windowSeconds int
	maxRequests   int
	bucket        string
}

// NewPostgresLimiter permite até maxRequests requisições por chave a cada
// janela de windowSeconds segundos, dentro do namespace bucket (ver o
// comentário do tipo acima — cada rota/ação que precisa de um limite
// independente passa um bucket próprio, mesmo que dois limiters
// terminem recebendo exatamente o mesmo "key" de quem chama).
func NewPostgresLimiter(pool *pgxpool.Pool, windowSeconds, maxRequests int, bucket string) *PostgresLimiter {
	return &PostgresLimiter{pool: pool, windowSeconds: windowSeconds, maxRequests: maxRequests, bucket: bucket}
}

// Allow incrementa o contador da janela atual para (bucket, key) e
// reporta se o resultado ainda está dentro do limite. Um único UPSERT: se
// a janela mudou desde a última requisição desta chave NESTE bucket, o
// contador reseta para 1; senão, soma 1 ao valor existente — sem race
// condition possível entre réplicas concorrentes, já que o Postgres
// serializa updates na mesma linha automaticamente.
func (l *PostgresLimiter) Allow(ctx context.Context, key string) (bool, error) {
	const q = `
		WITH window_calc AS (
			SELECT to_timestamp(floor(extract(epoch FROM now()) / $3::float8) * $3::float8) AS window_start
		)
		INSERT INTO rate_limit_buckets (bucket, key, window_start, count)
		SELECT $1, $2, window_start, 1 FROM window_calc
		ON CONFLICT (bucket, key) DO UPDATE SET
			count = CASE
				WHEN rate_limit_buckets.window_start = EXCLUDED.window_start
				THEN rate_limit_buckets.count + 1
				ELSE 1
			END,
			window_start = EXCLUDED.window_start
		RETURNING count
	`

	var count int
	err := l.pool.QueryRow(ctx, q, l.bucket, key, l.windowSeconds).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ratelimit: check bucket %q key %q: %w", l.bucket, key, err)
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
