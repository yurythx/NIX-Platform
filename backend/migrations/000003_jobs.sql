-- +goose Up
CREATE TABLE jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CONSTRAINT jobs_status_check
                        CHECK (status IN ('queued', 'processing', 'completed', 'failed', 'dead_letter')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    result          JSONB,
    error           TEXT,
    correlation_id  UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX idx_jobs_type ON jobs (type);
CREATE INDEX idx_jobs_status ON jobs (status);
CREATE INDEX idx_jobs_correlation_id ON jobs (correlation_id);
CREATE INDEX idx_jobs_created_at ON jobs (created_at DESC);
-- As consultas de polling do worker / "jobs em andamento" do dashboard
-- filtram por (type, status) juntos na maioria das vezes.
CREATE INDEX idx_jobs_type_status ON jobs (type, status);

-- +goose Down
DROP TABLE IF EXISTS jobs;
