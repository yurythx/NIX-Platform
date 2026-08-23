-- +goose Up
-- Autenticação local (§ Sistema de Login Local): um caminho de login por
-- usuário/senha PARALELO ao Keycloak, não um substituto — útil para
-- ambientes de desenvolvimento/teste onde manter um Keycloak sempre
-- acessível é um atrito, e como conta de emergência caso o Keycloak
-- externo fique fora do ar. keycloak_subject deixa de ser obrigatório
-- (um usuário local não tem um) e ganha password_hash (bcrypt) e roles
-- (só usada para usuários locais — usuários vindos do Keycloak sempre têm
-- suas roles extraídas do próprio token a cada requisição, nunca desta
-- coluna, para as duas fontes nunca poderem divergir silenciosamente).
--
-- +goose StatementBegin
ALTER TABLE users ALTER COLUMN keycloak_subject DROP NOT NULL;
-- +goose StatementEnd

ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN roles TEXT[] NOT NULL DEFAULT '{}';

-- Todo usuário precisa de pelo menos um jeito de provar quem é — nunca
-- uma linha sem Keycloak E sem senha local.
ALTER TABLE users ADD CONSTRAINT users_has_auth_method
    CHECK (keycloak_subject IS NOT NULL OR password_hash IS NOT NULL);

-- Usuário admin de teste pronto para uso imediato — username "admin",
-- senha "Admin123!" (hash bcrypt abaixo). Documentado no README; troque
-- ou remova esta linha antes de qualquer ambiente que não seja
-- desenvolvimento/teste local.
INSERT INTO users (id, keycloak_subject, username, email, display_name, active, password_hash, roles, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    NULL,
    'admin',
    'admin@nix.local',
    'Administrador (local)',
    true,
    '$2a$10$MRor989CIOutXMHhXjwda.2KVKz7LFUMZkBrnuUV.zBfoic209T5W',
    ARRAY['nix-admin', 'nix-user'],
    now(),
    now()
);

-- +goose Down
DELETE FROM users WHERE username = 'admin' AND keycloak_subject IS NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_has_auth_method;
ALTER TABLE users DROP COLUMN IF EXISTS roles;
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
-- +goose StatementBegin
ALTER TABLE users ALTER COLUMN keycloak_subject SET NOT NULL;
-- +goose StatementEnd
