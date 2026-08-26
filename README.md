# NIX Platform

Uma plataforma corporativa modular que centraliza funcionalidades internas, integrações,
automações e notificações numa única aplicação extensível — construída como um **Monólito
Modular** (API Go + Worker Go + frontend Next.js, um único código-fonte, dois binários) com um
núcleo **orientado a eventos**: PostgreSQL para estado, RabbitMQ para processamento assíncrono, e
um Keycloak externo já existente para identidade.

Dois módulos de negócio reais rodam sobre esse núcleo hoje, cada um seguindo o mesmo pipeline
job → outbox → fila → worker → notificação — o mesmo que qualquer integração nova (ver
[`/integracoes`](#rotas-do-frontend)) reaproveita sem precisar de código de plataforma novo:

- **[`scanning`](#appsec-orquestrador-de-scanners)** — um orquestrador de AppSec: dispara 6
  scanners de segurança reais (Trivy, Semgrep, SonarQube, OWASP ZAP, Gitleaks, Syft) em paralelo
  contra um alvo, com triagem, postura de segurança agregada, exportação CSV/SARIF, e uma UI
  mestre-detalhe pros achados. Ver [`/seguranca`](#rotas-do-frontend).
- **[`diario_oficial`](#diário-oficial-monitoramento-jurídico)** — monitoramento real de
  publicações judiciais: cadastra um termo (OAB, número de processo, texto livre) e sincroniza
  automaticamente contra o **DJEN** (Diário de Justiça Eletrônico Nacional, mantido pelo CNJ), a
  mesma base pública que legaltechs como Jusbrasil/Escavador/Turivius usam. Ver
  [`/diario-oficial`](#rotas-do-frontend).

## Arquitetura em resumo

```
Keycloak (existente, externo) ──OIDC──▶ NIX Platform
                                          ├── Frontend Next.js (painel, cliente WebSocket)
                                          ├── API Go (REST, WebSocket, auth, gravação no outbox)
                                          ├── Worker Go (consumidores RabbitMQ, publicador do outbox)
                                          ├── PostgreSQL (dados, jobs, outbox, auditoria)
                                          └── RabbitMQ (exchange nix.events, filas + DLQs por módulo)
```

- **Next.js (App Router, TypeScript, Tailwind, React Compiler)** — o painel. Toda página busca seus
  dados iniciais num Server Component (direto contra a API Go, server-side); Client Components
  entram só onde há interação de verdade — formulários, toggles, e os poucos casos que genuinamente
  precisam revalidar depois do carregamento inicial (polling de status de scan, um painel aberto
  sob demanda), estes sobre SWR (`lib/api/swr.ts`) para dedupe/cache entre componentes. Todos os
  Client Components chamam a API Go apenas através de um proxy BFF de mesma origem
  (`/api/backend/*`), então o token de acesso OIDC nunca chega ao JavaScript executado no navegador.
  Atualizações em tempo real chegam por um WebSocket autenticado por ticket.
- **Go** — um único módulo (`backend/go.mod`), três pontos de entrada: `cmd/api` (HTTP + WebSocket),
  `cmd/worker` (consumidores RabbitMQ + publicador do outbox) e `cmd/secscan` (CLI standalone de
  scanning — `nix-secscan scan --repo .`, ver "Roadmap de segurança" abaixo). A regra de negócio
  mora em `internal/modules/<nome>/{domain,application,infrastructure,transport[,worker]}`, isolada
  da infraestrutura da plataforma em `internal/platform/*`.
- **PostgreSQL** — dados da aplicação, `jobs`, `outbox_events` (Outbox Transacional), `audit_logs`.
- **RabbitMQ** — exchange `nix.events` (topic), uma fila + uma dead-letter queue por módulo,
  publisher confirms, ack/nack manual, e retry com backoff controlado pela aplicação.
- **Keycloak** — uma instância externa **já existente**. Este projeto nunca provisiona o Keycloak —
  veja [Configuração do Keycloak](#configuração-do-keycloak) abaixo para o que ele espera de
  realm/client.

## Pré-requisitos

- Docker e Docker Compose
- Git
- Uma instância de Keycloak já existente, acessível tanto da sua máquina quanto dos containers

## Configuração do Keycloak

O NIX Platform autentica contra o realm do Keycloak já existente na sua organização. São
necessários **dois** clients OIDC nesse realm:

| Client | Tipo | Usado por |
|---|---|---|
| `nix-platform-api` | confidencial (ou público, bearer-only) | A API Go — valida os tokens de acesso localmente contra o JWKS do realm. |
| `nix-platform-web` | confidencial | O frontend Next.js — Authorization Code + PKCE via NextAuth. |

Passos (console de administração do Keycloak):

1. **Realm**: use um realm existente ou crie um (ex.: `nix`).
2. **Client `nix-platform-web`**:
   - Client authentication: **ligado** (confidencial).
   - Standard flow (Authorization Code): **ligado**. Direct access grants: desligado.
   - Valid redirect URIs: `http://localhost:3000/api/auth/callback/keycloak` (adicione também a
     URL de produção).
   - Valid post logout redirect URIs: `http://localhost:3000` — necessário para o logout completo
     (RP-Initiated Logout) funcionar; sem isso o Keycloak recusa o redirecionamento de volta após
     encerrar a sessão.
   - Web origins: `http://localhost:3000` (ou `+` para espelhar as redirect URIs).
   - Copie o **Client secret** gerado para `KEYCLOAK_FRONTEND_CLIENT_SECRET`.
3. **Client `nix-platform-api`**:
   - Client authentication: ligado (o backend nunca executa o fluxo OAuth sozinho, mas um client
     confidencial permite adicionar chamadas de introspection/service-account depois sem
     reconfigurar).
   - Copie o ID dele para `KEYCLOAK_CLIENT_ID` e para `KEYCLOAK_AUDIENCE` (por padrão os dois
     apontam para o mesmo client id, `nix-platform-api`).
4. **Mapeador de audience em `nix-platform-web` (passo fácil de esquecer, e sem o qual TODO
   token é rejeitado)**: por padrão, um token emitido para o client `nix-platform-web` carrega
   `aud: "account"` — não `nix-platform-api` — porque o Keycloak só inclui automaticamente o
   client que fez o login, mais o client `account` embutido. Como o backend valida
   `aud` contra `KEYCLOAK_AUDIENCE` (`nix-platform-api`), sem este passo **toda requisição
   autenticada falha** com "invalid or expired access token", mesmo com um token genuíno e
   fresco. Adicione um mapeador de protocolo em `nix-platform-web` → aba **Client scopes** →
   scope dedicado (ou diretamente em **Dedicated scopes** do client) → **Add mapper** → **By
   configuration** → **Audience**:
   - Included Client Audience: `nix-platform-api`.
   - Add to access token: ligado.
   - (Via `kcadm.sh`, equivalente:
     `create clients/<id-do-nix-platform-web>/protocol-mappers/models -r <realm> -s name=nix-platform-api-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper -s 'config={"included.client.audience":"nix-platform-api","access.token.claim":"true"}'`.)
   - Verifique decodificando um access token gerado (ex. em [jwt.io](https://jwt.io)): o campo
     `aud` deve conter `"nix-platform-api"`.
5. **Roles**: crie as roles de realm que o NIX Platform reconhece — `nix-user`, `nix-admin`,
   `nix-integration-manager`, `nix-auditor` — e atribua a usuários/grupos conforme apropriado.
6. **Endpoints OIDC**: tanto o backend quanto o frontend descobrem sozinhos tudo que precisam
   (`authorization_endpoint`, `jwks_uri`, endpoint de logout, etc.) a partir de
   `<KEYCLOAK_ISSUER_URL>/.well-known/openid-configuration` — só é preciso configurar
   `KEYCLOAK_ISSUER_URL` (ex.: `https://keycloak.example.com/realms/nix`), nunca as URLs de cada
   endpoint individualmente.

## Login local (adicional ao Keycloak)

Além do Keycloak, o NIX Platform tem um segundo caminho de autenticação **local**
(usuário/senha, sem depender de nenhum IdP externo) — pensado para o primeiro acesso
administrativo e para ambientes de teste/demo onde configurar um Keycloak seria fricção
desnecessária. Os dois caminhos coexistem: nenhum substitui o outro, e ambos terminam na mesma
sessão da aplicação.

- **Backend**: `POST /api/v1/auth/login` (rota pública, fora do grupo autenticado) recebe
  `{"username", "password"}`, valida contra `password_hash` (bcrypt) na tabela `users` e devolve
  um token assinado **RS256**, com um par de chaves RSA próprio deste subsistema — nunca a mesma
  chave/segredo usado pelo Keycloak ou por qualquer outra coisa da aplicação (ver ADR
  [003](docs/adr/003-local-auth-rsa-hardening.md)). Controlado por `LOCAL_AUTH_ENABLED`; com a
  flag desligada o endpoint responde 404. Tentativas malsucedidas (usuário inexistente, conta
  só-Keycloak, conta bloqueada, senha errada) sempre devolvem a mesma mensagem genérica e são
  auditadas em `audit_logs` — nenhuma delas revela qual condição falhou, nem por tempo de
  resposta. Uma conta é bloqueada por 15 minutos depois de 5 tentativas seguidas de senha errada
  (defesa em profundidade além do rate limit por IP já aplicado à rota).
- **Frontend**: a tela de login (`/login`) mostra o formulário de usuário/senha como opção
  principal e o SSO corporativo (Keycloak) como opção secundária abaixo — um segundo
  `CredentialsProvider` do NextAuth que chama o endpoint acima. As duas rotas produzem o mesmo
  tipo de sessão; o resto da aplicação não distingue qual caminho o usuário usou.
- Uma conta pode ter só Keycloak, só senha local, ou ambos — `keycloak_subject` e `password_hash`
  são independentes e ao menos um deles precisa estar preenchido.
- **Gerando a chave RSA** (necessária sempre que `LOCAL_AUTH_ENABLED=true`):
  ```bash
  mkdir -p secrets
  openssl genrsa -out secrets/local_auth_private_key.pem 2048
  chmod 644 secrets/local_auth_private_key.pem
  ```
  `secrets/` nunca é commitado (`.gitignore`) e é montado somente leitura em `backend-api`/
  `backend-worker` pelo `docker-compose.yml`. O `chmod` é necessário porque os dois containers
  rodam como um usuário não-root (`nix`, diferente do seu usuário no host) — sem permissão de
  leitura para "outros", o processo falha no startup com "permission denied" em vez de subir.
  Trocar a chave invalida imediatamente todo token local emitido antes da troca — aceitável dado
  o TTL curto (1h por padrão).

**Criando um administrador local** (auditoria de segurança — nenhuma senha pronta vem mais
semeada no banco; a migration `000011_local_auth.sql` chegou a criar `admin`/`Admin123!`, mas a
migration `000027_remove_default_admin_password.sql` a remove: um aviso em README pra "trocar
antes de produção" é disciplina humana, não um controle técnico, e uma senha pública e conhecida
não deveria existir em NENHUM ambiente por padrão, nem local):

```bash
make seed-admin
```

Cria (ou reseta a senha de) um usuário local `admin`/`nix-admin`+`nix-user` com uma senha
**aleatória gerada na hora**, impressa uma única vez no terminal — nunca gravada em nenhum
arquivo, log ou migration. Rodar de novo gera uma senha nova e destrava a conta, se estiver
bloqueada (`internal/platform/localauth`). Aceita `--username`/`--email`/`--display-name`/`--roles`
(ver `go run ./backend/cmd/seedadmin --help`) pra criar outras contas locais, não só `admin`.
Recusa sobrescrever uma conta já ligada ao Keycloak, mesmo que o username coincida.

## Configuração

```bash
cp .env.example .env
```

Preencha no mínimo: `DB_PASSWORD`, `RABBITMQ_DEFAULT_PASS`/`RABBITMQ_URL`, todos os valores
`KEYCLOAK_*` da seção acima, `NEXTAUTH_SECRET` (um valor aleatório de 32+ bytes —
`openssl rand -base64 32`). Se quiser o login local (veja [Login local](#login-local-adicional-ao-keycloak)
acima), gere a chave RSA como mostrado ali — `LOCAL_AUTH_PRIVATE_KEY_FILE` já vem apontando para
`/run/secrets/local_auth_private_key.pem` e `LOCAL_AUTH_ENABLED` já vem `true` por padrão. Toda
variável está documentada diretamente no `.env.example`. Segredos nunca são commitados — `.env` e
`secrets/` estão no `.gitignore`.

**Gestão de segredos em produção**: além de variáveis de ambiente diretas, todo valor sensível
(`DB_PASSWORD`, `RABBITMQ_URL`, `KEYCLOAK_CLIENT_SECRET`, `LOCAL_AUTH_PRIVATE_KEY`) também aceita uma
variável `<NOME>_FILE` apontando para um arquivo — o conteúdo do arquivo tem prioridade sobre a
variável direta. Esse é o padrão usado por Docker Secrets, Kubernetes Secrets montados como
volume, e pelo Vault Agent Sidecar Injector, então nenhum código específico de provedor é
necessário: basta montar o segredo como arquivo e apontar `<NOME>_FILE` para ele.

## Executando

```bash
docker compose up --build
```

Isso sobe `postgres`, `rabbitmq`, `backend-api`, `backend-worker` e `frontend` na rede interna
`nix_internal`. Nem o PostgreSQL nem o RabbitMQ são publicados externamente por padrão — veja o
`docker-compose.dev.yml` para abri-los durante depuração local:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Com os containers saudáveis:

- Frontend: http://localhost:3000
- Health da API: http://localhost:8000/health, readiness: http://localhost:8000/ready
- UI de gerenciamento do RabbitMQ (só no override de dev): http://localhost:15672

## Rotas do frontend

| Rota | Acesso | O que é |
|---|---|---|
| `/` | pública | Página inicial — filosofia da plataforma e os serviços/módulos disponíveis. |
| `/sobre` | pública | Sobre a plataforma: princípios de arquitetura e como é construída. |
| `/login` | pública | Login (usuário/senha local ou SSO via Keycloak — ver [Login local](#login-local-adicional-ao-keycloak)). |
| `/dashboard` | autenticada | Visão geral — status das integrações, postura de segurança agregada, atalhos. |
| `/integracoes` | autenticada | Lista toda integração configurada — cada uma leva pra sua página de detalhe. |
| `/integracoes/{key}` | autenticada | Página de detalhe genérica (rota dinâmica) de uma integração — status e teste de conectividade. `{key}` é o mesmo valor que a integração tem no backend (`diario-oficial`, e cada integração nova que for adicionada). |
| `/seguranca` | autenticada | Tela inicial de histórico: todo scan já disparado, ferramentas usadas, erro/warning por severidade. Botão "Novo scan" leva pra `/seguranca/novo`. |
| `/seguranca/novo` | autenticada | Saúde de cada scanner (antes de disparar), formulário de disparo (um ou mais dos 6 scanners) e projetos persistentes salvos. |
| `/seguranca/{scanId}` | autenticada | Detalhe de UMA execução — achados por ferramenta, exportação CSV/SARIF, inventário de pacotes (Syft). |
| `/seguranca/{scanId}/{scanner}` | autenticada | Achados mestre-detalhe de UM scanner dentro de um scan — navegação por teclado, link direto por achado, triagem. |
| `/diario-oficial` | autenticada | Saúde da fonte (DJEN), cadastro de termos monitorados (OAB/processo/texto livre) e o feed de publicações casadas — filtro por termo/tribunal/tipo, paginação. |
| `/configuracao` | autenticada | Aba "Sistema" — configuração dinâmica (feature flags, `nix-admin`). |
| `/configuracao/usuarios` | autenticada | Aba "Usuários" — diretório de usuários. |

`/dashboard`, `/integracoes`, `/seguranca`, `/diario-oficial` e `/configuracao` compartilham um
único grupo de rotas autenticado (`app/(protected)/`, sem segmento próprio na URL) — a checagem de
sessão e o shell visual (Sidebar/Topbar) são definidos uma única vez ali. Todo nome usado por essas
páginas em qualquer momento anterior de uma reestruturação (`/dashboard/users`,
`/dashboard/settings[/integrations/diario]`, `/dashboard/integrations[/diario]`,
`/configuracao/integracoes[/diario]`) redireciona permanentemente para os caminhos acima
(`frontend/next.config.ts`) — nenhum é removido dali quando o destino muda de novo, só atualizado
para o caminho canônico atual.

## Migrations

As migrations são SQL puro, gerenciadas pelo [Goose](https://github.com/pressly/goose), e
**nunca** rodam automaticamente na inicialização — execute-as explicitamente. `make migrate-*`
chama o binário `goose`, então instale-o uma vez:

```bash
go install github.com/pressly/goose/v3/cmd/goose@latest
```

```bash
make migrate-up
make migrate-status
make migrate-down
```

## Testes

```bash
make test          # backend (go test ./...) + frontend (vitest run)
```

Os testes do backend se dividem em dois grupos:

- **Testes unitários** (sempre rodam, sem precisar de infraestrutura): regras de domínio, casos
  de uso da aplicação com fakes, JWT/autorização, envelope de eventos, validadores.
- **Testes de integração contra serviços reais**: exercitam o código de mensageria, outbox, jobs,
  usuários e integrações contra um PostgreSQL e RabbitMQ de verdade — são pulados automaticamente
  a menos que `TEST_DATABASE_URL` / `TEST_RABBITMQ_URL` estejam definidas, então `go test ./...`
  continua passando sem infraestrutura. Para rodá-los localmente:

  ```bash
  TEST_DATABASE_URL="postgres://nix:change-me@localhost:5432/nix?sslmode=disable" \
  TEST_RABBITMQ_URL="amqp://nix:nix_password@localhost:5672/nix" \
  go test ./... -timeout 120s -p 1
  ```

  `-p 1` importa aqui: vários pacotes exercitam o *mesmo* banco de dados ao vivo em vez de usar
  mocks, e o paralelismo padrão do `go test` entre pacotes permite que linhas gravadas por um
  pacote vazem para as verificações de outro. O `make test` já passa essa flag.

  (Aponte essas variáveis para os containers do `docker-compose.dev.yml`, que publica 5432/5672.)

**E2E (Playwright)**: exercita a aplicação de ponta a ponta (login local, dashboard, logout
completo, páginas públicas) contra uma stack REAL, nunca mockada. Exige `docker compose up`
rodando primeiro (postgres/rabbitmq/backend-api/frontend, com `LOCAL_AUTH_ENABLED=true` — ver
[Login local](#login-local-adicional-ao-keycloak) acima) e `npx playwright install chromium` uma
vez. O teste de login (`e2e/auth.spec.ts`) precisa de uma conta local de verdade — crie uma com
`make seed-admin` (ver [Login local](#login-local-adicional-ao-keycloak)) e exporte a senha
impressa antes de rodar:

```bash
make seed-admin
# copie a senha impressa
E2E_ADMIN_PASSWORD='<senha impressa acima>' npm --prefix frontend run test:e2e
```

Sem `E2E_ADMIN_PASSWORD` definida, `auth.spec.ts` pula sozinho (com uma mensagem explicando o
porquê) em vez de falhar tentando logar com uma senha que não existe. O job `e2e` do CI
(`.github/workflows/ci.yml`) roda a mesma coisa do zero a cada PR — gera sua própria senha aleatória
via `make seed-admin`-equivalente, mascarada nos logs, nunca a mesma entre execuções — incluindo um
Keycloak descartável só pro backend completar o discovery OIDC no boot.

## RabbitMQ

- **Exchange**: `nix.events`, tipo `topic`, durável.
- **Routing keys**: `<contexto>.<entidade>.<ação>` — ex.: `diario_oficial.job.completed`,
  `scanning.scan.requested`, `notification.created`.
- **Filas** (cada uma durável, cada uma com sua própria DLQ — ver `internal/platform/messaging/topology.go`):

  | Fila | Routing keys associadas | DLQ |
  |---|---|---|
  | `nix.diario_oficial.worker` | `diario_oficial.job.created` | `nix.diario_oficial.dlq` |
  | `nix.scanning.worker` | `scanning.scan.requested` | `nix.scanning.dlq` |
  | `nix.notification.websocket` | `notification.created`, `diario_oficial.job.completed`, `diario_oficial.job.failed`, `diario_oficial.publication.matched`, `integration.status.changed`, `scanning.scan.completed`, `scanning.scan.failed` | `nix.notification.dlq` |

- **Consumidor**: ack manual — `internal/platform/messaging.Consumer` despacha cada entrega para
  sua própria goroutine (limitado por `RABBITMQ_PREFETCH_COUNT`).
- **Retry**: quando o handler falha, o consumidor aguarda um backoff calculado, depois republica
  uma cópia da mensagem com o contador de tentativas incrementado e confirma (ack) a original —
  em vez de depender do requeue nativo, que não consegue carregar um contador de tentativas
  atualizado.
- **DLQ**: uma vez que `RABBITMQ_MAX_RETRIES` se esgota, a mensagem é rejeitada (nack) sem
  requeue, o que o RabbitMQ roteia nativamente para a DLQ da própria fila (cada fila principal
  declara `x-dead-letter-exchange`/`-routing-key` apontando para ela).
- **Job órfão (achado real — um scan preso em "0% Rodando" por horas, o worker que o processava
  tinha morrido no meio do trabalho)**: se o worker que processa um job morre no meio do trabalho
  (crash, OOM, `docker compose restart`/reimplantação no meio de um job), a mensagem que disparou o
  processamento já foi confirmada (ack) muito antes de morrer — nenhuma redelivery chega nunca, e o
  job ficaria preso em "processing" pra sempre. `jobs.SweepStale` (`internal/platform/jobs/sweeper.go`,
  registrado como processor do worker) varre periodicamente (a cada 5min, primeira varredura
  imediata ao subir) todo job "processing" sem atividade há mais de `JOB_STALE_AFTER` (default
  45min — acima do maior timeout interno de qualquer scanner, `SCANNING_ZAP_SCAN_TIMEOUT`, 30min por
  padrão) e o dead-letra com o mesmo pipeline (evento de outbox, auditoria, notificação) que uma
  falha "normal" já teria — nunca "max retries exceeded" no motivo, sempre um texto explicando que
  foi órfão, não retry esgotado.
- **Publisher confirms**: toda publicação (`internal/platform/messaging.Publisher` e o publicador
  do outbox) bloqueia até o RabbitMQ confirmar que a mensagem foi aceita.
- **Outbox Transacional**: as escritas de negócio e o evento que elas disparam são inseridos na
  mesma transação PostgreSQL (`outbox_events`); um leitor separado
  (`internal/platform/outbox.Publisher`, rodando em `cmd/worker`) publica as linhas pendentes com
  `SELECT ... FOR UPDATE SKIP LOCKED` (seguro para múltiplas réplicas do worker) e só marca cada
  uma como `published` depois que o broker confirma.

## WebSocket

- **Autenticação**: navegadores não conseguem definir um cabeçalho `Authorization` no handshake de
  WebSocket, então a conexão é autenticada com um **ticket** de curta duração (30s) e uso único,
  em vez de um token na URL. `POST /api/v1/ws/ticket` (autenticado por JWT, com rate limiting)
  emite um; `GET /ws?ticket=...` o resgata e faz o upgrade.
- **Conexão**: o `lib/websocket/client.ts` do frontend busca um ticket novo a cada (re)conexão.
- **Eventos**: toda mensagem segue o envelope padrão
  (`{id, type, version, source, occurred_at, correlation_id, payload}`), validado com Zod no
  cliente antes de ser usado (`lib/validation/schemas.ts`) — uma mensagem malformada é descartada,
  nunca confiada cegamente.
- **Reconexão**: backoff exponencial limitado (até 30s) em qualquer fechamento/erro, mais o
  tratamento nativo de ping/pong do navegador para heartbeat — nunca um loop de reconexão
  agressivo. **Exceção deliberada (achado real — usuário reportou nunca ver progresso de scan em
  tempo real; o log mostrava `POST /ws/ticket` devolvendo 401 pra sempre, a cada ~30s)**: uma
  sessão genuinamente expirada (401 ao buscar um ticket novo, não um erro de rede/servidor)
  entra num estado terminal `"unauthorized"` em vez de continuar reconectando — retry nunca
  resolveria sozinho, só um login novo. A Topbar mostra "Sessão expirada — atualize a página" em
  vermelho nesse caso, distinto de "Reconectando…" (âmbar, transitório).

## Segurança

- **Content-Security-Policy com nonce**: `frontend/src/proxy.ts` gera um nonce novo a cada
  requisição, aplicado automaticamente pelo Next.js aos próprios scripts do framework — não é
  possível usar `style=""`/`<script>` inline sem nonce em nenhum componente (por isso os
  indicadores de status usam classes Tailwind geradas a partir de tokens de cor, nunca `style`
  inline).
- **Headers de segurança complementares** (`frontend/next.config.ts`, `headers()`): `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` desligando
  câmera/microfone/geolocalização/USB/pagamento (nenhum usado por este dashboard) e
  `Strict-Transport-Security` — cada um cobre algo que a CSP não cobre (`frame-ancestors 'none'` na
  CSP já substitui `X-Frame-Options` pra clickjacking, não repetido aqui).
- **Logout completo (RP-Initiated Logout)**: o botão "Sair" não apenas limpa a sessão local — ele
  também redireciona o navegador para o endpoint de logout do próprio Keycloak
  (`/api/auth/keycloak-logout-url` monta essa URL usando o `id_token` lido no servidor), então a
  sessão no provedor de identidade é encerrada de verdade, não só o cookie local.
- **Rate limiting distribuído**: `internal/platform/ratelimit.PostgresLimiter` usa uma janela fixa
  armazenada em `rate_limit_buckets` (Postgres), compartilhada por todas as réplicas da API — sem
  isso, cada réplica teria seu próprio contador em memória e o limite efetivo viraria N× o
  configurado. Não usa Redis, seguindo a decisão arquitetural original (§7): o Postgres que já
  existe é suficiente.
- **Auditoria imutável**: a tabela `audit_logs` tem gatilhos (migration `000008`) que recusam
  `UPDATE`, `DELETE` e `TRUNCATE` — uma trilha de auditoria que pode ser editada não prova nada.
  Isso protege contra a aplicação e contra credenciais de operação do dia a dia; não protege
  contra um superusuário do Postgres, que ainda pode desabilitar o gatilho antes de agir (ver
  comentário na migration para o que fazer nesse caso).
- **Gestão de segredos via arquivo**: ver a seção [Configuração](#configuração) acima.
- **Scanning contínuo** (`.github/`): Dependabot atualiza dependências semanalmente
  (`dependabot.yml`, com `cooldown` — uma versão nova só vira PR alguns dias depois de publicada,
  tempo pra uma release comprometida/sequestrada ser sinalizada pela comunidade antes de chegar
  aqui), gitleaks varre todo push/PR em busca de segredos vazados (`workflows/gitleaks.yml`),
  CodeQL faz análise estática de segurança em Go e TypeScript (`workflows/codeql.yml`), e o job
  `docker` do CI escaneia com Trivy as oito imagens já construídas (backend-api, backend-worker,
  frontend e os cinco sidecars de scanning — `trivy-scanner`/`gitleaks-scanner`/`syft-scanner`/
  `semgrep-scanner`/`sonar-scanner-cli`) em busca de CVEs conhecidas. Toda `uses:` de Action nos
  workflows é fixada por commit SHA (comentário com a versão ao lado), não por tag mutável — o
  Dependabot continua atualizando sozinho (reconhece o formato `@<sha> # vX.Y.Z`).
- **Criptografia em repouso**: é primariamente uma decisão de infraestrutura, não algo que o
  código da aplicação resolve sozinho. Em produção, use um provedor de PostgreSQL gerenciado com
  criptografia em repouso habilitada por padrão (Amazon RDS, Google Cloud SQL, Azure Database for
  PostgreSQL todos oferecem isso "de fábrica"), ou, para volumes locais/on-prem, um disco
  criptografado com LUKS por baixo do volume `postgres_data`. A extensão `pgcrypto` já está
  habilitada (migration `000001`) para o dia em que uma coluna específica precisar de
  criptografia em nível de aplicação — não foi aplicada preventivamente a nenhuma coluna hoje
  porque isso exigiria uma estratégia de busca determinística (hash) para manter índices/buscas
  funcionando, e nenhum campo atual (email corporativo, por exemplo) justifica essa complexidade
  extra sem um requisito concreto.

## AppSec (orquestrador de scanners)

[`docs/roadmap-secops-orchestrator.md`](docs/roadmap-secops-orchestrator.md) é o histórico completo
(cada fase, decisão e achado real, em ordem) — esta seção é o resumo do que está de pé hoje. O
módulo `scanning` (`POST /api/v1/scanning/scans` — aceita mais de um scanner por chamada, todos
rodando em PARALELO sob o mesmo `scan_id`) orquestra **6 scanners reais**, todos seguindo o mesmo
padrão Strategy/Adapter e o mesmo pipeline job → outbox → fila → worker → notificação de
`diario_oficial`:

- **Trivy** — clona o alvo via git e escaneia dependências/Dockerfiles.
- **Semgrep** — SAST (`p/owasp-top-ten`), mesmo mecanismo de clone.
- **Gitleaks** — segredos/credenciais vazadas no histórico do repositório.
- **Syft** — inventário de pacotes/SBOM (nunca acha vulnerabilidade sozinho — alimenta uma tela
  própria de inventário por scan).
- **SonarQube** — qualidade de código/bugs/vulnerabilidades via um servidor self-hosted
  (`docker-compose.yml`, serviços `sonarqube`/`sonarqube-db`); assíncrono em dois níveis (upload +
  processamento pela Compute Engine do servidor).
- **OWASP ZAP** — DAST: dispara um crawl seguido de ataques ativos de verdade (injeção, XSS, ...)
  contra uma URL rodando de verdade, via um daemon self-hosted (`docker-compose.yml`, serviço
  `zap`). Estruturalmente diferente dos outros cinco — não lê código-fonte, ataca um serviço vivo —
  por isso exige uma allowlist de hosts explícita (`SCANNING_ZAP_ALLOWED_HOSTS`, vazia por padrão:
  recusa todo alvo até um host de staging/homologação ser autorizado). **Nunca aponte para
  produção.**

Além dos 6 scanners em si, a plataforma gerencia o CICLO DE VIDA do achado, não só encontra:

- **Saúde antes de escanear** — `GET /scanning/scanners/health` checa os 6 scanners em paralelo
  (timeout de 5s cada) antes de disparar um scan novo (`/seguranca/novo`), pra nunca descobrir um
  sidecar fora do ar só depois de esperar o scan falhar.
- **Triagem** — um achado pode ser marcado `false_positive`/`wont_fix`/`risk_accepted` (motivo
  obrigatório, auditado), com expiração opcional — sem isso, o mesmo falso positivo reaparecia pra
  sempre a cada re-scan.
- **Postura de segurança** — achados ABERTOS agregados entre todo projeto persistente
  (`GET /scanning/posture`), mais tendência histórica diária (`GET /scanning/posture/history`) —
  visível no `/dashboard`.
- **Exportação CSV e SARIF** — CSV pra planilha/auditoria/ticket; SARIF 2.1.0 (validado contra o
  schema oficial) pro GitHub Code Scanning consumir nativamente, virando anotação direto no diff
  de um PR.
- **UI mestre-detalhe** — lista + painel de detalhe sempre visível (nunca um modal), navegação por
  teclado, link direto por achado (`?finding=<id>`), ordenação escolhida pelo usuário.

Além da API HTTP, `cmd/secscan` (`nix-secscan scan --repo . --scanners trivy,semgrep`, ou
`make secscan`) roda Trivy/Semgrep contra um repositório já no disco — sem precisar de
Postgres/RabbitMQ/Keycloak rodando — usado tanto localmente quanto num job adicional em `ci.yml`
(`secscan`, que não substitui nenhum dos jobs de scanning já existentes).

TruffleHog (Fase 2 do roadmap original) foi pulado por redundância com o Gitleaks já embutido.

## Diário Oficial (monitoramento jurídico)

Até certo ponto desta plataforma, `diario_oficial` era só um teste de conectividade — um `GET`
numa URL configurada, sem ler nada do diário de verdade. Hoje é um monitoramento real, no mesmo
espírito do que Jusbrasil/Escavador/Turivius/Codilo oferecem, construído sobre uma fonte pública de
verdade: o **DJEN** (Diário de Justiça Eletrônico Nacional, mantido pelo CNJ,
`comunicaapi.pje.jus.br`) — API gratuita que cobre eletronicamente a maior parte dos tribunais
brasileiros, já configurada como default (`DefaultDiarioOficialBaseURL`) sem exigir nenhuma
credencial de terceiro.

- **Termo monitorado** (`POST/GET/DELETE /diario-oficial/monitored-terms`) — OAB+UF, número de
  processo, ou texto livre (pelo menos um obrigatório). Cadastrado em [`/diario-oficial`](#rotas-do-frontend).
- **Sincronização automática** — o worker (`worker.DiarioOficialSyncLoop`) busca no DJEN a cada 6h
  (primeiro ciclo imediato ao subir), com uma janela de sobreposição de 24h e deduplicação real
  (`ON CONFLICT DO NOTHING` em publicação e em casamento termo↔publicação) — nunca duplica uma
  publicação nem renotifica o mesmo achado.
- **Notificação** — `diario_oficial.publication.matched` no mesmo pipeline de outbox/WebSocket que
  todo evento desta plataforma já usa, só publicado quando o casamento é REALMENTE novo.
- **Saúde da fonte** (`GET /diario-oficial/health`) — checagem síncrona (timeout de 5s) do DJEN,
  sem job/outbox — mesma UX de "saúde antes de escanear" do scanning.
- **Filtros e feed** (`GET /diario-oficial/publications`, `.../monitored-terms/{id}/publications`)
  — por termo (troca a origem da busca no backend), por tribunal/tipo de comunicação (client-side),
  com paginação "carregar mais".

Uma prefeitura (ou qualquer outro provedor) pode virar uma segunda fonte no futuro sem mudar a
arquitetura — `domain.Client` (`Check`/`Search`) é uma interface, o mesmo padrão Strategy/Adapter
que os 6 scanners de `scanning` já usam; só falta escrever o adapter contra a API real de cada
provedor específico, quando ela existir. Contagem regressiva de prazo processual (o que
Jusbrasil/Escavador também oferecem) fica fora de escopo até haver uma fonte confiável de
calendário forense por tribunal — calcular prazo errado é pior que não calcular.

## Observabilidade

- **Logs**: estruturados (`log/slog`), JSON em produção, texto em desenvolvimento, com
  `request_id`/`correlation_id`/`user_id` anexados sempre que disponíveis — nunca um segredo.
- **Métricas**: exposição Prometheus em `/metrics` tanto na API quanto no worker (o do worker fica
  num listener `WORKER_METRICS_PORT` separado, sem tráfego de negócio).
- **Tracing**: OpenTelemetry. Um no-op de verdade quando `OTEL_EXPORTER_OTLP_ENDPOINT` não está
  definida (nenhum coletor faz parte desta stack); quando definida, requisições HTTP,
  publicação/consumo no RabbitMQ e o publicador do outbox produzem spans, e o contexto de rastreio
  de um job flui da requisição HTTP que o criou até o worker que o processa.

## Documentação da API

Veja [`docs/openapi.yaml`](docs/openapi.yaml) — todo endpoint, schema, formato de erro, contrato
de paginação, e exemplo. Visualize com qualquer visualizador de OpenAPI (ex.:
`npx @redocly/cli preview-docs docs/openapi.yaml`).

## Estrutura do repositório

```
nix-platform/
├── backend/            Módulo Go: cmd/{api,worker}, internal/{platform,domain,modules,app}, migrations/
├── frontend/            App Next.js
├── docs/openapi.yaml     Referência da API
├── .github/               CI, Dependabot, scanning de segurança
├── docker-compose.yml     postgres, rabbitmq, backend-api, backend-worker, frontend
├── docker-compose.dev.yml Sobreposições só para desenvolvimento local (expõe portas de postgres/rabbitmq)
└── Makefile               dev/up/down/test/lint/migrate-*/...
```

## Estendendo a plataforma

Novos módulos de negócio seguem a mesma estrutura de quatro a cinco camadas dos já existentes
(`domain/`, `application/`, `infrastructure/`, `transport/`, opcionalmente `worker/`) e são
conectados em exatamente um lugar: `backend/internal/app/modules.go`. O padrão a seguir é o mesmo
que `diario_oficial` (um cliente HTTP próprio por trás de uma interface pequena, `domain.Client`,
com `Search` trocável por adapter quando uma segunda fonte de dados entrar — ver
[Diário Oficial](#diário-oficial-monitoramento-jurídico) acima) e `scanning` (6 implementações de
`domain.CodeScanner`, cada uma um adapter independente) já demonstram: reaproveitar outbox/circuit
breaker/feature flags/idempotência da plataforma sem precisar de nenhuma mudança nesses pacotes.
Ver [`docs/roadmap-secops-orchestrator.md`](docs/roadmap-secops-orchestrator.md) para o histórico
completo de decisões de design dos dois módulos.

Extrair um módulo para um serviço separado é deliberadamente não uma decisão inicial — o monólito
modular é o plano até que um módulo tenha um motivo concreto e real (escala independente, deploy
independente, um time dedicado) para ser separado.

## Licença

MIT — veja [LICENSE](LICENSE).
