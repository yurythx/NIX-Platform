-- +goose Up
CREATE TABLE integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key              TEXT NOT NULL,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    status           TEXT NOT NULL DEFAULT 'unknown'
                         CONSTRAINT integrations_status_check
                         CHECK (status IN ('unknown', 'online', 'offline', 'degraded', 'disabled')),
    last_check_at    TIMESTAMPTZ,
    last_success_at  TIMESTAMPTZ,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_integrations_key ON integrations (key);
CREATE INDEX idx_integrations_type ON integrations (type);

-- +goose StatementBegin
CREATE TRIGGER trg_integrations_set_updated_at
    BEFORE UPDATE ON integrations
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- Semeia as duas integrações para as quais este boilerplate já traz
-- suporte de transport/worker. Integrações adicionais (Shodan, AbuseIPDB,
-- ...) são adicionadas do mesmo jeito, sem precisar tocar neste schema
-- (§76).
INSERT INTO integrations (key, name, type) VALUES
    ('diario-oficial', 'Diário Oficial', 'diario_oficial'),
    ('virustotal', 'VirusTotal', 'secops');

-- +goose Down
DROP TABLE IF EXISTS integrations;
