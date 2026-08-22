package idempotency

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implementa Store sobre a tabela idempotency_keys
// (migration 000009). Como o restante do estado compartilhado da
// plataforma (rate limiting, tickets de WebSocket), é compartilhado por
// toda réplica da API via o mesmo Postgres — a plataforma não usa Redis
// por design (§7).
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

// Claim usa uma única instrução SQL (uma CTE de escrita seguida de um
// fallback de leitura) para que a decisão "esta chamada reivindicou a
// chave, ou alguém mais já a possui" seja atômica — sem essa garantia,
// duas requisições concorrentes com a mesma chave nova poderiam ambas
// executar o INSERT ... ON CONFLICT DO NOTHING e ler "não existia antes",
// achando cada uma que ganhou o direito de processar.
//
// A cláusula ON CONFLICT só atualiza a linha (reabrindo-a para
// "processing") quando o estado atual é 'failed' E o request_hash bate
// com o desta chamada — assim uma chave que falhou pode ser tentada de
// novo com o MESMO payload, mas reaproveitar a chave para um payload
// diferente nunca reescreve silenciosamente o registro; cai no branch de
// fallback abaixo, que devolve o registro existente tal como está para o
// middleware perceber a divergência de hash e rejeitar o reuso indevido.
func (s *PostgresStore) Claim(ctx context.Context, key, requestHash string) (*Record, bool, error) {
	const q = `
		WITH ins AS (
			INSERT INTO idempotency_keys (key, request_hash, status, created_at, updated_at)
			VALUES ($1, $2, 'processing', now(), now())
			ON CONFLICT (key) DO UPDATE SET
				request_hash = EXCLUDED.request_hash,
				status = 'processing',
				response_status = NULL,
				response_body = NULL,
				content_type = NULL,
				updated_at = now()
			WHERE idempotency_keys.status = 'failed' AND idempotency_keys.request_hash = EXCLUDED.request_hash
			RETURNING key, request_hash, status, response_status, response_body, content_type, true AS claimed
		)
		SELECT key, request_hash, status, response_status, response_body, content_type, claimed FROM ins
		UNION ALL
		SELECT key, request_hash, status, response_status, response_body, content_type, false AS claimed
		FROM idempotency_keys
		WHERE key = $1 AND NOT EXISTS (SELECT 1 FROM ins)
	`

	var (
		rec            Record
		responseStatus *int
		responseBody   []byte
		contentType    *string
		claimed        bool
	)
	err := s.pool.QueryRow(ctx, q, key, requestHash).Scan(
		&rec.Key, &rec.RequestHash, &rec.Status, &responseStatus, &responseBody, &contentType, &claimed,
	)
	if err != nil {
		return nil, false, fmt.Errorf("idempotency: claim key %q: %w", key, err)
	}
	if responseStatus != nil {
		rec.ResponseStatus = *responseStatus
	}
	rec.ResponseBody = responseBody
	if contentType != nil {
		rec.ContentType = *contentType
	}

	if claimed {
		return nil, true, nil
	}
	return &rec, false, nil
}

// Complete grava a resposta final de key e a marca "completed", tornando-a
// disponível para replay em chamadas futuras com a mesma chave (ver
// Store.Complete).
func (s *PostgresStore) Complete(ctx context.Context, key string, responseStatus int, responseBody []byte, contentType string) error {
	const q = `
		UPDATE idempotency_keys
		SET status = 'completed', response_status = $2, response_body = $3, content_type = $4, updated_at = now()
		WHERE key = $1
	`
	if _, err := s.pool.Exec(ctx, q, key, responseStatus, responseBody, contentType); err != nil {
		return fmt.Errorf("idempotency: complete key %q: %w", key, err)
	}
	return nil
}

// Fail marca key como "failed", liberando-a para uma nova tentativa
// completa com o mesmo request_hash (ver Store.Fail).
func (s *PostgresStore) Fail(ctx context.Context, key string) error {
	const q = `UPDATE idempotency_keys SET status = 'failed', updated_at = now() WHERE key = $1`
	if _, err := s.pool.Exec(ctx, q, key); err != nil {
		return fmt.Errorf("idempotency: fail key %q: %w", key, err)
	}
	return nil
}

// retention é por quanto tempo uma chave concluída/falha continua guardada
// depois de sua última atualização. Chaves de idempotência só precisam
// sobreviver pelo tempo em que um cliente razoavelmente tentaria de novo
// (segundos a minutos) — 24h já é generoso, e evita que a tabela cresça
// indefinidamente em um sistema de alto tráfego.
const retention = 24 * time.Hour

// Cleanup apaga periodicamente chaves de idempotência antigas, no mesmo
// espírito de internal/platform/ratelimit.Cleanup. Registrado como um
// processor do worker.
func Cleanup(pool *pgxpool.Pool) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				// make_interval(secs => $1) em vez de interpolar
				// retention.String() (ex.: "24h0m0s") num cast ::interval
				// — o formato de Duration.String() do Go coincide com o
				// que o parser de interval do Postgres aceita hoje, mas
				// depender disso seria frágil; segundos como float é
				// inequívoco.
				_, err := pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE updated_at < now() - make_interval(secs => $1)`, retention.Seconds())
				if err != nil {
					return fmt.Errorf("idempotency: cleanup: %w", err)
				}
			}
		}
	}
}
