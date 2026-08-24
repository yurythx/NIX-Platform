-- +goose Up
-- Fase 12 (docs/roadmap-secops-orchestrator.md): a proposta original
-- pedia um endpoint pra ler o arquivo do disco sob demanda na UI —
-- incompatível com a decisão de checkout efêmero (Fase 10): sem
-- persistência, não sobra arquivo depois que o scan termina. Adaptação:
-- captura um trecho de código (snippet) NO MOMENTO do scan, enquanto o
-- clone temporário ainda existe.
ALTER TABLE scan_findings ADD COLUMN snippet TEXT NOT NULL DEFAULT '';

-- fingerprint: SHA-256 de scanner+finding_id+file+line — identifica o
-- "mesmo" achado entre re-scans do mesmo projeto (Fase 10), pra uma UI
-- futura mostrar histórico ("apareceu pela primeira vez em X, ainda
-- presente em Y") em vez de listar a mesma vulnerabilidade uma vez por
-- scan sem relação nenhuma entre as linhas.
ALTER TABLE scan_findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_scan_findings_fingerprint ON scan_findings (fingerprint);

-- +goose Down
DROP INDEX IF EXISTS idx_scan_findings_fingerprint;
ALTER TABLE scan_findings DROP COLUMN IF EXISTS fingerprint;
ALTER TABLE scan_findings DROP COLUMN IF EXISTS snippet;
