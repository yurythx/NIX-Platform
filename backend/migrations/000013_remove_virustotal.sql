-- +goose Up
-- Remove a integração VirusTotal (§ decisão do produto: o módulo secops,
-- que só existia pra essa integração, foi removido do backend — ver o
-- commit que apaga internal/modules/secops/. Nunca edite as migrations
-- 000006/000010 que semearam essas linhas — elas documentam o que era
-- verdade naquele momento; esta migration nova documenta a mudança).
DELETE FROM integrations WHERE key = 'virustotal';
DELETE FROM feature_flags WHERE key = 'secops_virustotal_enabled';

-- +goose Down
INSERT INTO integrations (key, name, type) VALUES ('virustotal', 'VirusTotal', 'secops')
ON CONFLICT (key) DO NOTHING;
INSERT INTO feature_flags (key, enabled, description) VALUES
    ('secops_virustotal_enabled', true, 'Habilita o teste de conectividade e as chamadas ao provedor VirusTotal (SecOps).')
ON CONFLICT (key) DO NOTHING;
