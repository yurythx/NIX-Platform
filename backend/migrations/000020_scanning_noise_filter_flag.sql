-- +goose Up
-- Fase 13 (docs/roadmap-secops-orchestrator.md) — filtro de ruído por
-- caminho (/tests/, /fixtures/, *_test.go, ...). Semeada DESLIGADA, ao
-- contrário das flags de 000010: um achado de segredo commitado dentro
-- de um arquivo de teste ainda É um segredo real (Gitleaks, por design,
-- não distingue "teste" de "produção") — mostrar tudo é o comportamento
-- seguro por padrão; filtrar é opt-in explícito de quem administra a
-- instância, nunca ligado sozinho.
INSERT INTO feature_flags (key, enabled, description) VALUES
    ('scanning_noise_filter_enabled', false, 'Oculta achados cujo caminho bate com SCANNING_NOISE_FILTER_PATTERNS (ex.: /tests/, *_test.go) das listagens. Desligada por padrão — um achado de segredo real dentro de um arquivo de teste nunca deveria sumir sozinho.');

-- +goose Down
DELETE FROM feature_flags WHERE key = 'scanning_noise_filter_enabled';
