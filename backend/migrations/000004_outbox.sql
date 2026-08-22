-- +goose Up
-- payload stores the full standardized event envelope (§17: id, type,
-- version, source, occurred_at, correlation_id, payload) as it will be
-- published to RabbitMQ verbatim — the outbox publisher does not
-- reconstruct the envelope, it republishes exactly what was written here
-- inside the same transaction as the business data (§16).
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

-- The publisher polls "give me pending events in order" — a partial index
-- keeps that query cheap regardless of how many published rows accumulate.
CREATE INDEX idx_outbox_events_pending ON outbox_events (created_at) WHERE status = 'pending';
CREATE INDEX idx_outbox_events_aggregate ON outbox_events (aggregate_type, aggregate_id);
-- Correlation id lives inside the envelope payload; index it for tracing
-- queries ("show me every event for this request") without denormalizing
-- a column the spec doesn't list.
CREATE INDEX idx_outbox_events_correlation_id ON outbox_events (((payload ->> 'correlation_id')));

-- +goose Down
DROP TABLE IF EXISTS outbox_events;
