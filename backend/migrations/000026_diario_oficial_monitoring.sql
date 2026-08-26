-- +goose Up
-- MVP real de monitoramento do Diário Oficial (docs/roadmap-secops-
-- orchestrator.md, "Diário Oficial — monitoramento real via DJEN"):
-- até aqui, diario_oficial só fazia um teste de conectividade (GET numa
-- URL configurada, sem ler nada do diário) — o README chama isso
-- explicitamente de "módulo de referência" pro pipeline job → outbox →
-- worker → notificação, não um produto de monitoramento de verdade.
--
-- Pedido do usuário: "quero saber como as grandes empresas
-- especializadas fazem, quero aplicar as melhores implementações e as
-- melhores práticas" — comparado com Jusbrasil/Escavador/Turivius/
-- Codilo, o núcleo do produto é: cadastrar um termo (OAB, número de
-- processo, texto livre), buscar periodicamente no diário oficial de
-- verdade, e alertar quando uma publicação nova casar com o termo. A
-- fonte de dados real é o DJEN (Diário de Justiça Eletrônico Nacional,
-- mantido pelo CNJ, comunicaapi.pje.jus.br) — API pública gratuita que
-- cobre a maior parte dos tribunais brasileiros eletronicamente, a
-- mesma base que boa parte do mercado usa (ver
-- infrastructure/http_client.go's Search).

-- diario_oficial_monitored_terms: o que o usuário quer acompanhar. Pelo
-- menos um critério de busca é obrigatório (CHECK abaixo) — um termo
-- sem NENHUM critério nunca casaria com publicação nenhuma, então
-- cadastrar um assim seria um erro silencioso do usuário, não uma
-- configuração válida "vazia".
CREATE TABLE diario_oficial_monitored_terms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- label: nome de exibição escolhido pelo usuário (ex.: "Dr. Fulano —
    -- OAB/MG 419") — os campos de busca abaixo (oab_number, ...) não são
    -- amigáveis o bastante pra aparecer sozinhos numa lista.
    label           TEXT NOT NULL,
    -- oab_number/oab_uf: SEMPRE juntos (o mesmo número de OAB se repete
    -- entre estados) — o CHECK abaixo garante isso, nunca um sem o
    -- outro.
    oab_number      TEXT,
    oab_uf          TEXT,
    process_number  TEXT,
    free_text       TEXT,
    active          BOOLEAN NOT NULL DEFAULT true,
    -- created_by: nullable pelo mesmo motivo de scanning_projects/jobs
    -- não exigirem um usuário — nunca bloqueia a ação, só fica sem
    -- atribuição quando não há identidade autenticada disponível.
    created_by      UUID,
    -- last_synced_at: até onde o worker já buscou pra este termo — o
    -- ponto de partida do PRÓXIMO ciclo (ver application.
    -- syncSinceDate), pra nunca reprocessar o histórico inteiro do DJEN
    -- a cada tick. NULL = nunca sincronizado ainda (usa uma janela de
    -- lookback fixa na primeira vez, ver defaultLookbackWindow).
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT diario_oficial_monitored_terms_oab_pair_check
        CHECK ((oab_number IS NULL) = (oab_uf IS NULL)),
    CONSTRAINT diario_oficial_monitored_terms_has_criteria_check
        CHECK (
            (oab_number IS NOT NULL AND oab_uf IS NOT NULL)
            OR process_number IS NOT NULL
            OR free_text IS NOT NULL
        )
);

CREATE INDEX diario_oficial_monitored_terms_active_idx
    ON diario_oficial_monitored_terms (active)
    WHERE active;

-- diario_oficial_publications: uma publicação de verdade, já lida do
-- DJEN e persistida — a plataforma nunca busca no DJEN sob demanda pra
-- responder uma consulta do usuário; o worker busca periodicamente e
-- guarda aqui, então toda tela lê só do Postgres (rápido e disponível
-- mesmo se o DJEN estiver fora do ar naquele momento).
CREATE TABLE diario_oficial_publications (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- external_id: o "id" que o próprio DJEN atribui à comunicação — é a
    -- chave de deduplicação (UNIQUE abaixo): o mesmo termo buscado em
    -- ciclos sucessivos re-encontra publicações já vistas (a janela de
    -- busca sempre se sobrepõe um pouco de propósito, ver
    -- application.syncSinceDate), e um ON CONFLICT (external_id) DO
    -- NOTHING evita duplicar a publicação — nunca duplicar a
    -- NOTIFICAÇÃO por ela, ver diario_oficial_publication_matches
    -- abaixo.
    external_id            BIGINT NOT NULL UNIQUE,
    tribunal               TEXT NOT NULL,
    orgao                  TEXT NOT NULL,
    tipo_comunicacao       TEXT NOT NULL,
    texto                  TEXT NOT NULL,
    process_number         TEXT NOT NULL DEFAULT '',
    process_number_masked  TEXT NOT NULL DEFAULT '',
    availability_date      DATE NOT NULL,
    link                   TEXT NOT NULL DEFAULT '',
    -- raw_payload: o JSON completo que o DJEN devolveu pra esta
    -- comunicação, sem perda nenhuma — o texto/campos estruturados acima
    -- são só o que a UI precisa hoje; guardar o payload inteiro evita
    -- que uma decisão de modelagem de hoje (que campo extrair) exija uma
    -- nova ida ao DJEN amanhã pra recuperar um campo que ninguém previu
    -- precisar — o mesmo raciocínio que scan_findings.Snippet (Fase 12)
    -- já aplica, num escopo maior aqui porque uma publicação judicial é
    -- potencialmente relevante pra prazo processual, não só depuração.
    raw_payload            JSONB NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX diario_oficial_publications_availability_date_idx
    ON diario_oficial_publications (availability_date);
CREATE INDEX diario_oficial_publications_process_number_idx
    ON diario_oficial_publications (process_number)
    WHERE process_number <> '';

-- diario_oficial_publication_matches: QUAL termo casou com QUAL
-- publicação — n:n deliberado (a mesma publicação pode citar vários
-- advogados/partes monitorados por termos diferentes; o mesmo termo,
-- claro, casa com várias publicações ao longo do tempo). UNIQUE
-- (publication_id, monitored_term_id) é o que torna o INSERT do worker
-- idempotente entre ciclos (ON CONFLICT DO NOTHING) — sem isso, a
-- mesma publicação re-encontrada pela sobreposição de janela geraria
-- uma segunda notificação pro mesmo casamento.
--
-- FK com ON DELETE CASCADE pras duas pontas (diferente do resto da
-- plataforma, que evita FK entre TABELAS DE MÓDULOS DIFERENTES por
-- desacoplamento — ver migration 000014): publication/monitored_term/
-- match são as três tabelas do MESMO módulo, sem razão nenhuma pra
-- desacoplar entre si.
CREATE TABLE diario_oficial_publication_matches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    publication_id      UUID NOT NULL REFERENCES diario_oficial_publications(id) ON DELETE CASCADE,
    monitored_term_id   UUID NOT NULL REFERENCES diario_oficial_monitored_terms(id) ON DELETE CASCADE,
    matched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (publication_id, monitored_term_id)
);

CREATE INDEX diario_oficial_publication_matches_term_idx
    ON diario_oficial_publication_matches (monitored_term_id, matched_at DESC);

-- +goose Down
DROP TABLE IF EXISTS diario_oficial_publication_matches;
DROP TABLE IF EXISTS diario_oficial_publications;
DROP TABLE IF EXISTS diario_oficial_monitored_terms;
