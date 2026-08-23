-- +goose Up
-- Corrige uma lacuna real do schema original (000014): scan_findings nunca
-- teve uma coluna para o ID do próprio achado (ex.: "CVE-2026-12345", ou
-- uma regra do scanner como "semgrep:go.lang.security.audit.sql-injection")
-- — domain.Finding.ID era montado em memória e descartado silenciosamente
-- antes de chegar ao INSERT. Nunca editar uma migration já aplicada:
-- corrige com uma nova.
ALTER TABLE scan_findings ADD COLUMN finding_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE scan_findings DROP COLUMN finding_id;
