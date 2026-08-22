// Package database configura o pool de conexões PostgreSQL compartilhado
// (pgx/v5 + pgxpool). Os módulos recebem um *pgxpool.Pool (ou uma interface
// mais estreita sobre ele) via injeção de dependência — nada neste pacote
// conhece os schemas de negócio.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// pgxTx é um alias local para que quem chama WithTx não precise importar o
// pacote pgx diretamente só para escrever o tipo da transação.
type pgxTx = pgx.Tx

// New constrói e valida um *pgxpool.Pool a partir da configuração de banco
// informada. Aplica os parâmetros de tamanho de pool/tempo de vida/ociosidade
// e faz um ping inicial, para que uma configuração errada falhe rápido no
// startup (fail fast) em vez de só na primeira query real da aplicação.
func New(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("database: parse pool config: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: initial ping failed: %w", err)
	}

	return pool, nil
}

// Ping é uma função de verificação (Check) de readiness, compatível com
// httpserver.Check — usada pelo endpoint /ready para reportar se o
// PostgreSQL está alcançável (§54).
func Ping(pool *pgxpool.Pool) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		return pool.Ping(ctx)
	}
}

// WithTx roda fn dentro de uma transação PostgreSQL, fazendo commit em caso
// de sucesso e rollback em caso de erro ou panic. Usado por casos de uso da
// camada de aplicação que precisam gravar dado de negócio e um evento de
// outbox atomicamente — a mesma transação garante que "o job foi criado" e
// "o evento que vai disparar o worker" nascem juntos ou não nascem nenhum
// dos dois (§16, o padrão Transactional Outbox).
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(ctx context.Context, tx pgxTx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	// Se fn (ou algo que ela chame) der panic, ainda assim tenta reverter
	// a transação antes de repropagar o panic — senão a conexão fica presa
	// numa transação aberta e "vazando" no pool.
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(ctx, tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("database: rollback failed: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit transaction: %w", err)
	}
	return nil
}

// DefaultTimeout é o timeout padrão por query aplicado por quem chama e não
// deriva um prazo mais específico a partir do contexto da requisição de
// entrada.
const DefaultTimeout = 5 * time.Second
