-- +goose Up
-- Audit trail for §49: login/logout, user.created/updated,
-- integration.test, integration.config.changed, job.created/completed/failed.
-- metadata must never contain passwords, tokens or secrets — enforced by
-- the application layer's audit writer, not by the schema.
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users (id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    correlation_id  UUID,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_correlation_id ON audit_logs (correlation_id);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
