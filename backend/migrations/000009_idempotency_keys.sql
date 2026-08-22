-- +goose Up
-- Suporte a chaves de idempotência (§ Idempotency-Key Middleware): key é
-- "<subject do usuário>:<valor do header Idempotency-Key>", escopada por
-- usuário para que dois chamadores diferentes nunca colidam ao escolher,
-- por coincidência, o mesmo valor de chave. request_hash identifica qual
-- requisição (método+caminho+corpo) gerou o registro, para detectar reuso
-- indevido da mesma chave com um payload diferente. response_body/
-- content_type só são preenchidos quando status = 'completed' — é o que
-- o middleware reproduz (replay) em requisições repetidas.
CREATE TABLE idempotency_keys (
    key             TEXT PRIMARY KEY,
    request_hash    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'processing'
                        CONSTRAINT idempotency_keys_status_check
                        CHECK (status IN ('processing', 'completed', 'failed')),
    response_status INTEGER,
    response_body   BYTEA,
    content_type    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A limpeza periódica (internal/platform/idempotency.Cleanup) varre por
-- updated_at, então precisa de um índice para não fazer um full scan da
-- tabela a cada execução.
CREATE INDEX idx_idempotency_keys_updated_at ON idempotency_keys (updated_at);

-- +goose Down
DROP TABLE IF EXISTS idempotency_keys;
