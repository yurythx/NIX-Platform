-- +goose Up
-- Fase 14 (continuação — docs/roadmap-secops-orchestrator.md):
-- SecurityPosture (migration 000023's vizinha de fase) só respondia
-- "quantos problemas abertos existem AGORA" — nenhum jeito de saber se
-- o time está melhorando ou piorando ao longo do tempo, a primeira
-- pergunta que qualquer gestor de segurança faz. Uma linha por DIA
-- (snapshot_date é a PRIMARY KEY, não um id + índice por data): cada
-- dia tem no máximo UM valor "oficial" — se o snapshot rodar mais de
-- uma vez no mesmo dia (ex.: worker reiniciado), a última execução
-- simplesmente sobrescreve a de mais cedo (ver
-- infrastructure.SavePostureSnapshot's ON CONFLICT), nunca acumula
-- duas linhas pro mesmo dia.
CREATE TABLE scanning_posture_snapshots (
    snapshot_date     DATE PRIMARY KEY,
    open_critical     INT NOT NULL DEFAULT 0,
    open_high         INT NOT NULL DEFAULT 0,
    open_medium       INT NOT NULL DEFAULT 0,
    open_low          INT NOT NULL DEFAULT 0,
    triaged_count     INT NOT NULL DEFAULT 0,
    projects_scanned  INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS scanning_posture_snapshots;
