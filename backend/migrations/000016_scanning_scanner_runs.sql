-- +goose Up
-- Progresso por scanner dentro de um job de scan (Fase 7 já roda todo
-- scanner pedido em paralelo — application.Service.runConcurrently) —
-- até aqui, um job ficava "processing" como uma caixa preta do início ao
-- fim: nenhuma linha em lugar nenhum dizia QUAL scanner já tinha
-- terminado enquanto os outros ainda rodavam. Pedido do usuário: um
-- painel visual mostrando qual scanner está rodando agora e quanto falta
-- — que exige saber o estado de CADA scanner individualmente, não só o
-- resultado agregado do job inteiro no final (esse continua vivendo em
-- jobs.result/jobs.error, sem mudança aqui).
--
-- Tabela própria do módulo scanning, não uma coluna a mais na tabela
-- jobs genérica (compartilhada com diario_oficial e todo job futuro) —
-- mesmo princípio já seguido no resto deste módulo (scan_findings
-- também é uma tabela própria, não uma coluna de jobs.result).
--
-- job_id não é FOREIGN KEY pra jobs.id de propósito: manter as duas
-- tabelas desacopladas, mesmo padrão de scan_findings.scan_id logo
-- acima — evita qualquer acoplamento de schema entre o genérico (jobs) e
-- o específico deste módulo.
CREATE TABLE scanning_scanner_runs (
    job_id          UUID NOT NULL,
    scanner         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running'
                        CONSTRAINT scanning_scanner_runs_status_check
                        CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    findings_count  INT,
    error           TEXT,
    PRIMARY KEY (job_id, scanner)
);

CREATE INDEX idx_scanning_scanner_runs_job_id ON scanning_scanner_runs (job_id);

-- +goose Down
DROP TABLE IF EXISTS scanning_scanner_runs;
