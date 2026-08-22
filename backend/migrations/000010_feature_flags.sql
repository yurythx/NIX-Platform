-- +goose Up
-- Feature flags alteráveis em tempo de execução (§ Feature Flags &
-- Configuração Dinâmica), sem precisar reiniciar cmd/api nem cmd/worker.
-- Semeadas já habilitadas — uma flag desabilitada por padrão quebraria
-- silenciosamente uma integração que já funcionava antes desta migration
-- existir; o objetivo é dar um interruptor de emergência, não opt-in.
CREATE TABLE feature_flags (
    key         TEXT PRIMARY KEY,
    enabled     BOOLEAN NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT
);

INSERT INTO feature_flags (key, enabled, description) VALUES
    ('secops_virustotal_enabled', true, 'Habilita o teste de conectividade e as chamadas ao provedor VirusTotal (SecOps).'),
    ('diario_oficial_scraping_enabled', true, 'Habilita a verificação de conectividade com o Diário Oficial.');

-- +goose Down
DROP TABLE IF EXISTS feature_flags;
