-- +goose Up
-- Corrige um bug real encontrado em auditoria: rate_limit_buckets tinha
-- "key" (ex.: o subject do usuário autenticado) como chave primária
-- ÚNICA, compartilhada por TODO PostgresLimiter da aplicação — e cada
-- limiter tem seu PRÓPRIO windowSeconds (TestJob=10s, ScanJob=60s,
-- WSTicket=5s, LocalLogin=60s). Como o mesmo usuário autenticado gera o
-- MESMO "key" em rotas diferentes (scanning.RateLimitKey e
-- diario_oficial.RateLimitKey são literalmente idênticas — retornam só
-- identity.Subject), duas rotas com limiters diferentes escreviam na
-- MESMA linha com window_start calculado de duas formas diferentes: a
-- cada chamada, o window_start recém-calculado quase sempre diferia do
-- que a ÚLTIMA chamada (de um limiter com windowSeconds diferente)
-- tinha gravado, disparando o ramo "ELSE 1" do UPSERT — o contador
-- resetava a cada troca de rota, e nenhum dos dois limites era
-- realmente aplicado na prática (um efetivamente anulava o outro).
--
-- Truncar é seguro aqui: rate_limit_buckets guarda só estado efêmero de
-- janela — perder o histórico no pior caso libera algumas requisições
-- extras logo após o deploy, nunca um dado de negócio.
TRUNCATE TABLE rate_limit_buckets;

ALTER TABLE rate_limit_buckets DROP CONSTRAINT rate_limit_buckets_pkey;
ALTER TABLE rate_limit_buckets ADD COLUMN bucket TEXT NOT NULL DEFAULT '';
ALTER TABLE rate_limit_buckets ALTER COLUMN bucket DROP DEFAULT;
ALTER TABLE rate_limit_buckets ADD PRIMARY KEY (bucket, key);

-- +goose Down
ALTER TABLE rate_limit_buckets DROP CONSTRAINT rate_limit_buckets_pkey;
ALTER TABLE rate_limit_buckets DROP COLUMN bucket;
ALTER TABLE rate_limit_buckets ADD PRIMARY KEY (key);
