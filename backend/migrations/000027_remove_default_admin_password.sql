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
-- Esta migration REMOVE essa linha — mas só SE a senha ainda for
-- EXATAMENTE o hash bcrypt do default documentado (nunca toca uma conta
-- que o operador já trocou, identificada pelo hash divergente). Depois
-- desta migration, todo ambiente que aplicar migrations (dev, CI, e
-- qualquer produção que tenha rodado 000011 sem trocar a senha) perde o
-- acesso via a credencial pública conhecida — sem exceção por ambiente,
-- porque migrations rodam identicamente em todos.
--
-- Pra recriar um admin local (dev/teste), use `make seed-admin`
-- (cmd/seedadmin) — gera uma senha aleatória nova a cada execução e
-- imprime uma única vez no terminal, nunca grava em nenhum arquivo
-- versionado. Ver README.md, seção "Login local".
DELETE FROM users
WHERE username = 'admin'
  AND keycloak_subject IS NULL
  AND password_hash = '$2a$10$MRor989CIOutXMHhXjwda.2KVKz7LFUMZkBrnuUV.zBfoic209T5W';

-- +goose Down
-- Deliberadamente um no-op: recriar a conta com o hash default conhecido
-- publicamente reintroduziria a vulnerabilidade que esta migration
-- corrige. Use `make seed-admin` para recriar com senha aleatória.
SELECT 1;
