-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- Função de trigger compartilhada: toda tabela com uma coluna updated_at
-- usa esta função para mantê-la atualizada em todo UPDATE, em vez de
-- depender do código da aplicação lembrar de setá-la manualmente.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS set_updated_at();
-- +goose StatementEnd
-- +goose StatementBegin
DROP EXTENSION IF EXISTS pgcrypto;
-- +goose StatementEnd
