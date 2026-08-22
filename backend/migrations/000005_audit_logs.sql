-- +goose Up
-- Trilha de auditoria para o §49: login/logout, user.created/updated,
-- integration.test, integration.config.changed, job.created/completed/failed.
-- metadata nunca deve conter senhas, tokens ou segredos — isto é imposto
-- pelo writer de auditoria na camada de aplicação, não pelo schema (o
-- banco em si aceitaria qualquer JSON). Ver também a migration 000008,
-- que torna esta tabela append-only (protegida contra UPDATE/DELETE/
-- TRUNCATE).
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
