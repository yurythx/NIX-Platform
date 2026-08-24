-- +goose Up
-- Fase 10 (docs/roadmap-secops-orchestrator.md): "Projeto" como entidade
-- própria — metadado leve (nome, alvo, histórico), NUNCA o checkout em
-- si (decisão explícita do usuário: o worker escala horizontalmente via
-- RabbitMQ, persistir um checkout por projeto reintroduziria estado por
-- réplica). Um projeto git só guarda a URL (re-clona a cada scan, como
-- sempre); um projeto de upload guarda os BYTES do .zip que o usuário
-- mandou (bounded pelo tamanho do upload, não um checkout que cresce
-- sem limite) — extraído de novo a cada re-scan, nunca mantido
-- descompactado em disco entre execuções.
CREATE TABLE scanning_projects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    source_type  TEXT NOT NULL
                     CONSTRAINT scanning_projects_source_type_check
                     CHECK (source_type IN ('git', 'upload')),
    -- target: URL git (source_type='git'), vazio para 'upload'.
    target       TEXT NOT NULL DEFAULT '',
    -- upload_zip: bytes do .zip enviado (source_type='upload'), NULL
    -- para 'git'. Tamanho já limitado na camada HTTP antes de chegar
    -- aqui (ver transport/handlers.go) — não confiar só no BYTEA sem
    -- limite pra evitar um upload gigante inchando o Postgres.
    upload_zip   BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scanning_projects_created_at ON scanning_projects (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS scanning_projects;
