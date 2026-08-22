-- +goose Up
-- payload guarda o envelope de evento padronizado completo (§17: id,
-- type, version, source, occurred_at, correlation_id, payload) exatamente
-- como será publicado no RabbitMQ — o publisher do outbox não reconstrói
-- o envelope, ele republica exatamente o que foi escrito aqui dentro da
-- mesma transação do dado de negócio (§16).
CREATE TABLE outbox_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL,
    aggregate_type  TEXT NOT NULL,
    aggregate_id    TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CONSTRAINT outbox_events_status_check
                        CHECK (status IN ('pending', 'published', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    last_error      TEXT
);

-- O publisher faz polling do tipo "me dê os eventos pendentes em ordem" —
-- um índice parcial mantém essa consulta barata independente de quantas
-- linhas já publicadas se acumularem.
CREATE INDEX idx_outbox_events_pending ON outbox_events (created_at) WHERE status = 'pending';
CREATE INDEX idx_outbox_events_aggregate ON outbox_events (aggregate_type, aggregate_id);
-- O correlation id vive dentro do payload do envelope; indexado aqui para
-- consultas de rastreamento ("mostre todo evento desta requisição") sem
-- desnormalizar uma coluna que a especificação não lista.
CREATE INDEX idx_outbox_events_correlation_id ON outbox_events (((payload ->> 'correlation_id')));

-- +goose Down
DROP TABLE IF EXISTS outbox_events;
