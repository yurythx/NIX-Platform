-- +goose Up
-- Fase 11 (docs/roadmap-secops-orchestrator.md): Syft produz um
-- INVENTÁRIO (lista de pacotes/versões), não achados de segurança —
-- estruturalmente diferente de scan_findings (uma vulnerabilidade é
-- sempre acionável; um pacote não é um "erro"), por isso uma tabela
-- própria em vez de forçar isso dentro de scan_findings.
CREATE TABLE scan_packages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id    UUID NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    type       TEXT NOT NULL DEFAULT '', -- ex.: "go-module", "npm", "python"
    license    TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_packages_scan_id ON scan_packages (scan_id);

-- +goose Down
DROP TABLE IF EXISTS scan_packages;
