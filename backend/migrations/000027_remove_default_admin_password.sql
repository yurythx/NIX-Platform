-- +goose Up
-- Achado de auditoria de segurança (revisão pedida pelo usuário — "aplique
-- todas as melhores práticas"): a migration 000011 semeava um usuário
-- admin/Admin123! com senha conhecida publicamente (documentada no
-- README, para dar início rápido sem configurar Keycloak). Um aviso no
-- README pra "trocar antes de produção" é disciplina humana, não um
-- controle técnico — quem esquece de ler/seguir o aviso (ou clona o
-- ambiente sem revisar o README primeiro) fica com uma conta nix-admin
-- de senha pública e conhecida.
--
-- Esta migration NEUTRALIZA essa linha — mas só SE a senha ainda for
-- EXATAMENTE o hash bcrypt do default documentado (nunca toca uma conta
-- que o operador já trocou, identificada pelo hash divergente).
--
-- Achado real rodando isto contra um ambiente com histórico de verdade
-- (não um banco de teste vazio, sem uso): a primeira versão desta
-- migration fazia DELETE FROM users — falha em qualquer ambiente onde
-- esse admin já logou pelo menos uma vez, porque audit_logs.user_id tem
-- ON DELETE SET NULL (migration 000005) e audit_logs é append-only
-- (migration 000008, bloqueia UPDATE/DELETE/TRUNCATE) — o DELETE em users
-- dispara um UPDATE em cascata sobre audit_logs, que o próprio gatilho de
-- imutabilidade recusa, revertendo a migration inteira. A correção troca
-- DELETE por UPDATE: active=false (o mesmo campo que Handlers.Login já
-- confere ANTES de comparar senha — bloqueia o login independente do
-- hash) + password_hash sobrescrito com crypt() de bytes aleatórios via
-- pgcrypto (extensão já habilitada desde a migration 000001; o formato
-- $2a$ que gen_salt('bf') produz é bcrypt de verdade, verificável por
-- golang.org/x/crypto/bcrypt sem tradução nenhuma — confirmado contra o
-- pacote real antes de escrever isto, não assumido). Preserva a linha
-- (e todo audit_logs.user_id que aponta pra ela) e nunca dispara o
-- gatilho de imutabilidade, porque nenhuma linha de audit_logs é tocada.
--
-- Pra recriar um admin local funcional (dev/teste), use `make seed-admin`
-- (cmd/seedadmin) — gera uma senha aleatória nova a cada execução,
-- reativa a conta (active=true), e imprime a senha uma única vez no
-- terminal, nunca grava em nenhum arquivo versionado. Ver README.md,
-- seção "Login local".
UPDATE users
SET active = false,
    password_hash = crypt(encode(gen_random_bytes(24), 'base64'), gen_salt('bf', 10)),
    updated_at = now()
WHERE username = 'admin'
  AND keycloak_subject IS NULL
  AND password_hash = '$2a$10$MRor989CIOutXMHhXjwda.2KVKz7LFUMZkBrnuUV.zBfoic209T5W';

-- +goose Down
-- Deliberadamente um no-op: restaurar o hash default conhecido
-- publicamente reintroduziria a vulnerabilidade que esta migration
-- corrige. Use `make seed-admin` para repor um admin local funcional.
SELECT 1;
