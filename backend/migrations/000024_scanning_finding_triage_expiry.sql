-- +goose Up
-- Fase 14 (continuação — docs/roadmap-secops-orchestrator.md): a
-- triagem (migration 000023) não tinha prazo — "risco aceito" durava
-- pra sempre, sem cobrança nenhuma de revisão. Toda ferramenta séria
-- (GitHub Advanced Security, Snyk, GitLab Secure) tem um SLA por
-- severidade e reabre achado vencido sozinho; expires_at é o primeiro
-- passo pra isso — opcional (NULL = sem prazo, comportamento idêntico
-- a antes desta migration), preenchido só quando quem tria escolhe uma
-- data de revisão.
ALTER TABLE scanning_finding_triage ADD COLUMN expires_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE scanning_finding_triage DROP COLUMN IF EXISTS expires_at;
