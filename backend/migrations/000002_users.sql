-- +goose Up
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_subject TEXT NOT NULL,
    username         TEXT NOT NULL,
    email            TEXT NOT NULL,
    display_name     TEXT NOT NULL DEFAULT '',
    active           BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ
);

-- keycloak_subject identifica o usuário no IdP externo e precisa ser
-- único — esta é a chave de junção usada em toda requisição autenticada
-- (§32), o valor que liga a linha local ao "sub" do token do Keycloak.
CREATE UNIQUE INDEX idx_users_keycloak_subject ON users (keycloak_subject);
CREATE UNIQUE INDEX idx_users_email ON users (email);
CREATE UNIQUE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_active ON users (active);

-- +goose StatementBegin
CREATE TRIGGER trg_users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS users;
