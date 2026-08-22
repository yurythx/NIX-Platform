-- +goose Up
-- Rate limiting distribuído (compartilhado entre todas as réplicas da
-- API), usando janela fixa: cada linha representa "quantas requisições a
-- chave `key` fez dentro da janela de tempo atual". Escolhido em vez de
-- token bucket puro porque um upsert de uma única linha é atômico no
-- Postgres sem precisar de transação/lock explícito — a implementação em
-- memória (usada quando não há necessidade de compartilhar entre
-- processos) continua existindo em internal/platform/httpserver como
-- fallback, mas cada processo tem seu próprio balde, então com múltiplas
-- réplicas da API o limite real vira N × limite configurado. Esta tabela
-- resolve isso: todas as réplicas leem/escrevem a mesma linha.
CREATE TABLE rate_limit_buckets (
    key          TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0
);

-- Usado pela limpeza periódica (internal/platform/ratelimit.Cleanup, uma
-- goroutine do worker) para descartar janelas antigas sem varrer a
-- tabela inteira.
CREATE INDEX idx_rate_limit_buckets_window_start ON rate_limit_buckets (window_start);

-- +goose Down
DROP TABLE IF EXISTS rate_limit_buckets;
