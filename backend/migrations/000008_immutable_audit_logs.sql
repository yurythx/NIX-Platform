-- +goose Up
-- Auditoria de verdade precisa ser "só acrescenta" (append-only): se
-- qualquer credencial com acesso de escrita ao banco também consegue
-- editar/apagar registros de auditoria, a trilha deixa de provar nada —
-- alguém que quisesse encobrir uma ação bastaria alterar a própria
-- entrada que a denunciaria. Estes gatilhos recusam qualquer UPDATE,
-- DELETE ou TRUNCATE na tabela audit_logs, não importa a role usada pela
-- aplicação.
--
-- Ressalva importante (documentar para quem for operar isto em produção):
-- um superusuário do Postgres (ou o dono da tabela, se diferente de quem
-- criou o gatilho) ainda pode remover o próprio gatilho antes de
-- alterar os dados, ou usar `ALTER TABLE ... DISABLE TRIGGER`. Isto
-- protege contra a aplicação e contra credenciais de operação do dia a
-- dia, não contra um administrador do banco mal-intencionado — para essa
-- garantia mais forte, é preciso um destino write-once fora do alcance
-- de qualquer credencial usada em produção (ex.: exportar continuamente
-- para um bucket com Object Lock, ou um WORM storage dedicado).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION prevent_audit_logs_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not allowed (attempted on id=%)',
        TG_OP,
        COALESCE(OLD.id, NEW.id);
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Trigger por LINHA: cobre UPDATE/DELETE feitos via DML normal (o caso
-- comum: alguém roda um UPDATE/DELETE apontado a uma ou mais linhas).
-- +goose StatementBegin
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_logs_mutation();
-- +goose StatementEnd

-- TRUNCATE é uma operação diferente de DELETE no Postgres — ela NÃO
-- passa por triggers "FOR EACH ROW" (só dispara triggers "FOR EACH
-- STATEMENT" registrados explicitamente para o evento TRUNCATE). Sem
-- este segundo gatilho, o trigger acima sozinho daria uma falsa sensação
-- de segurança: um TRUNCATE TABLE audit_logs apagaria a tabela inteira
-- de uma vez, contornando completamente a proteção por linha.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION prevent_audit_logs_truncate()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: TRUNCATE is not allowed';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER trg_audit_logs_immutable_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_audit_logs_truncate();
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS trg_audit_logs_immutable_truncate ON audit_logs;
DROP FUNCTION IF EXISTS prevent_audit_logs_truncate();
DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
DROP FUNCTION IF EXISTS prevent_audit_logs_mutation();
