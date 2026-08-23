-- +goose Up
-- Bloqueio de conta por tentativas (§ Sistema de Login Local — defesa em
-- profundidade além do rate limit por IP já aplicado à rota de login):
-- um IP sozinho não é um identificador confiável contra um atacante
-- distribuído (múltiplos IPs/proxies), mas o par usuário+senha é sempre a
-- mesma conta não importa de onde a tentativa vem. failed_login_attempts
-- conta tentativas de senha errada consecutivas; locked_until, quando no
-- futuro, bloqueia novas tentativas contra essa conta até expirar — ver
-- internal/platform/localauth (RegisterFailedAttempt/ResetFailedAttempts)
-- e docs/adr/003-local-auth-rsa-hardening.md.
ALTER TABLE users ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_attempts;
