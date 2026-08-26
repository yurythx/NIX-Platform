-- +goose Up
-- Fase 14 (docs/roadmap-secops-orchestrator.md, "Maturidade de AppSec"):
-- maior lacuna encontrada comparando esta plataforma com como GitHub
-- Advanced Security/Snyk/GitLab Secure tratam achado de segurança — até
-- aqui, um achado só tinha DOIS estados possíveis, os dois inferidos
-- automaticamente pelo re-scan (nunca escolhidos por um humano):
-- "still_present" (apareceu de novo) ou "não apareceu mais" (presumido
-- corrigido). Não existia como um humano dizer "isto é falso positivo,
-- pare de me mostrar" ou "sei do risco, aceito por ora" — o mesmo
-- falso positivo reaparecia pra sempre, todo re-scan.
--
-- Escopo deliberadamente por (project_id, fingerprint), não por achado
-- individual (scan_findings.id): a mesma decisão de design que
-- application.Service.ListProjectFindingsHistory já toma (Fase 12) —
-- "este problema", pro propósito de acompanhar ao longo do tempo, é o
-- fingerprint dentro de um projeto, não uma linha de uma execução
-- específica. Triar UMA vez precisa valer pra todo re-scan seguinte que
-- encontrar o mesmo fingerprint, não precisar ser refeita a cada scan.
--
-- project_id (não scan_id, não um achado avulso): só projetos
-- persistentes (Fase 10) têm identidade estável o bastante entre
-- re-scans pra uma triagem fazer sentido — um scan avulso (sem projeto)
-- não tem "próxima execução" garantida pra reaproveitar a decisão, e já
-- é assim que ListProjectFindingsHistory funciona hoje (só projetos têm
-- histórico). Sem FOREIGN KEY pra scanning_projects.id de propósito —
-- mesmo desacoplamento que scan_findings.scan_id já usa entre módulos
-- (ver migration 000014).
CREATE TABLE scanning_finding_triage (
    project_id     UUID NOT NULL,
    fingerprint    TEXT NOT NULL,
    -- status: os três desfechos reais que "não vou corrigir agora" pode
    -- assumir, na nomenclatura que GitHub/GitLab/DefectDojo já usam —
    -- não inventamos uma taxonomia própria pra isto.
    status         TEXT NOT NULL
                       CONSTRAINT scanning_finding_triage_status_check
                       CHECK (status IN ('false_positive', 'wont_fix', 'risk_accepted')),
    -- reason é OBRIGATÓRIO (NOT NULL, mas pode ser string vazia só se o
    -- backend permitir — não permite, ver application/triage.go):
    -- suprimir um achado sem justificativa registrada é exatamente o
    -- tipo de decisão que uma auditoria de segurança depois vai
    -- perguntar "por quê", e sem isto a resposta seria "não sabemos".
    reason         TEXT NOT NULL DEFAULT '',
    -- actor_user_id: nullable pelo mesmo motivo de jobs/scan_findings não
    -- exigirem um usuário (§ requestedBy opcional em CreateScanJob) —
    -- nunca bloqueia a ação, só fica sem atribuição quando não há
    -- identidade autenticada disponível.
    actor_user_id  UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, fingerprint)
);

-- +goose Down
DROP TABLE IF EXISTS scanning_finding_triage;
