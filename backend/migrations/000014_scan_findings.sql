-- +goose Up
-- Fase 1 do roadmap de segurança (docs/roadmap-secops-orchestrator.md):
-- fundação do módulo scanning — nenhuma ferramenta externa ainda, só o
-- modelo de dados e a interface que toda ferramenta futura (Trivy,
-- Semgrep, TruffleHog, SonarQube, OWASP ZAP) vai preencher.
--
-- scan_id agrupa todo achado de uma mesma execução (uma chamada a
-- Service.RunScan) — sem isso não haveria como reconstruir "quais
-- achados vieram do mesmo scan", só uma lista solta de linhas.
CREATE TABLE scan_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL,
    scanner         TEXT NOT NULL,
    target          TEXT NOT NULL,
    owasp_category  TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL
                        CONSTRAINT scan_findings_severity_check
                        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    description     TEXT NOT NULL,
    file            TEXT NOT NULL DEFAULT '',
    line            INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_findings_scan_id ON scan_findings (scan_id);
CREATE INDEX idx_scan_findings_scanner ON scan_findings (scanner);

-- +goose Down
DROP TABLE IF EXISTS scan_findings;
