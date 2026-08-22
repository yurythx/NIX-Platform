# NIX Platform

A corporate modular platform centralizing internal functionality, integrations, automation, and
notifications behind a single extensible application.

Built as a **Modular Monolith** (Go API + Go Worker + Next.js frontend, one codebase, two
binaries) with an **event-driven** core: PostgreSQL for state, RabbitMQ for asynchronous
processing, and an existing external Keycloak for identity. The initial modules are
**Diário Oficial** (a scheduled/on-demand external check) and **SecOps** (VirusTotal today,
pluggable for more providers), sharing the same job → outbox → queue → worker → notification
pipeline.

## Architecture at a glance

```
Keycloak (existing, external) ──OIDC──▶ NIX Platform
                                          ├── Next.js frontend (dashboard, WebSocket client)
                                          ├── Go API (REST, WebSocket, auth, outbox writer)
                                          ├── Go Worker (RabbitMQ consumers, outbox publisher)
                                          ├── PostgreSQL (data, jobs, outbox, audit)
                                          └── RabbitMQ (nix.events topic exchange, per-module
                                              queues + DLQs)
```

- **Next.js (App Router, TypeScript, Tailwind)** — the dashboard. Client Components call the
  Go API only through a same-origin BFF proxy (`/api/backend/*`), so the OIDC access token never
  reaches browser-executed JavaScript. Real-time updates arrive over a ticket-authenticated
  WebSocket.
- **Go** — one module (`backend/go.mod`), two entrypoints: `cmd/api` (HTTP + WebSocket) and
  `cmd/worker` (RabbitMQ consumers + the outbox publisher). Business logic lives in
  `internal/modules/<name>/{domain,application,infrastructure,transport[,worker]}`, isolated from
  the platform plumbing in `internal/platform/*`.
- **PostgreSQL** — application data, `jobs`, `outbox_events` (Transactional Outbox), `audit_logs`.
- **RabbitMQ** — the `nix.events` topic exchange, one queue + one dead-letter queue per module,
  publisher confirms, manual ack/nack, and application-controlled retry with backoff.
- **Keycloak** — an **existing** external instance. This project never provisions it — see
  [Keycloak setup](#keycloak-setup) below for the realm/client configuration it expects.

## Prerequisites

- Docker and Docker Compose
- Git
- An existing Keycloak instance reachable from both your machine and the containers

## Keycloak setup

NIX Platform authenticates against your organization's existing Keycloak realm. It needs **two**
OIDC clients in that realm:

| Client | Type | Used by |
|---|---|---|
| `nix-platform-api` | confidential (or public, bearer-only) | The Go API — validates access tokens locally against the realm's JWKS. |
| `nix-platform-web` | confidential | The Next.js frontend — Authorization Code + PKCE via NextAuth. |

Steps (Keycloak admin console):

1. **Realm**: use an existing realm or create one (e.g. `nix`).
2. **Client `nix-platform-web`**:
   - Client authentication: **on** (confidential).
   - Standard flow (Authorization Code): **on**. Direct access grants: off.
   - Valid redirect URIs: `http://localhost:3000/api/auth/callback/keycloak` (add your production
     URL too).
   - Valid post logout redirect URIs: `http://localhost:3000`.
   - Web origins: `http://localhost:3000` (or `+` to mirror redirect URIs).
   - Copy the generated **Client secret** into `KEYCLOAK_FRONTEND_CLIENT_SECRET`.
3. **Client `nix-platform-api`**:
   - Client authentication: on (the backend never runs the OAuth dance itself, but a confidential
     client lets you later add introspection/service-account calls without reconfiguring).
   - Copy its ID into `KEYCLOAK_CLIENT_ID`.
4. **Roles**: create the realm roles NIX Platform recognizes — `nix-user`, `nix-admin`,
   `nix-integration-manager`, `nix-auditor` — and assign them to users/groups as appropriate.
5. **OIDC endpoints**: the backend and frontend both discover everything they need
   (`authorization_endpoint`, `jwks_uri`, etc.) from
   `<KEYCLOAK_ISSUER_URL>/.well-known/openid-configuration` — you only need to set
   `KEYCLOAK_ISSUER_URL` (e.g. `https://keycloak.example.com/realms/nix`), never the individual
   endpoint URLs.

## Configuration

```bash
cp .env.example .env
```

Fill in at minimum: `DB_PASSWORD`, `RABBITMQ_DEFAULT_PASS`/`RABBITMQ_URL`, every `KEYCLOAK_*`
value from the section above, `NEXTAUTH_SECRET` (a random 32+ byte value —
`openssl rand -base64 32`), and, if you want the SecOps module to actually reach VirusTotal,
`VIRUSTOTAL_API_KEY`. Every variable is documented inline in `.env.example`. Secrets are never
committed — `.env` is gitignored.

## Running it

```bash
docker compose up --build
```

This starts `postgres`, `rabbitmq`, `backend-api`, `backend-worker`, and `frontend` on the
internal `nix_internal` network. Neither PostgreSQL nor RabbitMQ is published externally by
default — see `docker-compose.dev.yml` to open them for local debugging:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Once containers are healthy:

- Frontend: http://localhost:3000
- API health: http://localhost:8000/health, readiness: http://localhost:8000/ready
- RabbitMQ management UI (dev override only): http://localhost:15672

## Migrations

Migrations are plain SQL, managed by [Goose](https://github.com/pressly/goose), and are **never**
run automatically at startup — run them explicitly:

```bash
make migrate-up
make migrate-status
make migrate-down
```

## Tests

```bash
make test          # backend (go test ./...) + frontend (vitest run)
```

Backend tests fall into two groups:

- **Unit tests** (always run, no infrastructure needed): domain rules, application use cases with
  fakes, JWT/authorization, event envelope, validators.
- **Live-service integration tests**: exercise the real messaging, outbox, jobs, users, and
  integrations code against an actual PostgreSQL and RabbitMQ — they're skipped automatically
  unless `TEST_DATABASE_URL` / `TEST_RABBITMQ_URL` are set, so `go test ./...` stays green without
  infrastructure. To run them locally:

  ```bash
  TEST_DATABASE_URL="postgres://nix:change-me@localhost:5432/nix?sslmode=disable" \
  TEST_RABBITMQ_URL="amqp://nix:nix_password@localhost:5672/nix" \
  go test ./... -timeout 120s
  ```

  (Point these at the containers from `docker-compose.dev.yml`, which publishes 5432/5672.)

## RabbitMQ

- **Exchange**: `nix.events`, type `topic`, durable.
- **Routing keys**: `<context>.<entity>.<action>` — e.g. `diario_oficial.job.completed`,
  `integration.test.requested`, `notification.created`.
- **Queues** (each durable, each with its own DLQ):

  | Queue | Bound routing keys | DLQ |
  |---|---|---|
  | `nix.diario_oficial.worker` | `diario_oficial.job.created` | `nix.diario_oficial.dlq` |
  | `nix.integration.worker` | `integration.test.requested` (shared by every SecOps provider) | `nix.integration.dlq` |
  | `nix.notification.websocket` | `notification.created`, `diario_oficial.job.completed`, `diario_oficial.job.failed`, `integration.test.completed`, `integration.status.changed` | `nix.notification.dlq` |

- **Consumer**: manual ack — `internal/platform/messaging.Consumer` dispatches each delivery to
  its own goroutine (bounded by `RABBITMQ_PREFETCH_COUNT`).
- **Retry**: on handler failure, the consumer sleeps a computed backoff, then republishes an
  attempt-incremented copy of the message and acks the original, rather than relying on native
  requeue (which can't carry an updated attempt count).
- **DLQ**: once `RABBITMQ_MAX_RETRIES` is exhausted, the message is nacked without requeue, which
  RabbitMQ routes natively to the queue's own DLQ (each main queue declares
  `x-dead-letter-exchange`/`-routing-key` pointing at it).
- **Publisher confirms**: every publish (`internal/platform/messaging.Publisher` and the outbox
  publisher) blocks until RabbitMQ confirms the message was accepted.
- **Transactional Outbox**: business writes and their triggering event are inserted in the same
  PostgreSQL transaction (`outbox_events`); a separate poller
  (`internal/platform/outbox.Publisher`, running in `cmd/worker`) publishes pending rows with
  `SELECT ... FOR UPDATE SKIP LOCKED` (safe for multiple worker replicas) and marks each
  `published` only after the broker confirms it.

## WebSocket

- **Authentication**: browsers can't set an `Authorization` header on a WebSocket handshake, so
  the connection is authenticated with a short-lived (30s), single-use **ticket** instead of a
  token in the URL. `POST /api/v1/ws/ticket` (JWT-authenticated, rate-limited) issues one;
  `GET /ws?ticket=...` redeems it and upgrades.
- **Connection**: the frontend's `lib/websocket/client.ts` fetches a fresh ticket on every
  (re)connect.
- **Events**: every message is the standard envelope
  (`{id, type, version, source, occurred_at, correlation_id, payload}`), Zod-validated
  client-side before use (`lib/validation/schemas.ts`) — a malformed message is dropped, not
  trusted.
- **Reconnection**: bounded exponential backoff (capped at 30s) on any close/error, plus the
  browser's native ping/pong heartbeat handling — never a tight/aggressive retry loop.

## Observability

- **Logs**: structured (`log/slog`), JSON in production, text in development, with
  `request_id`/`correlation_id`/`user_id` attached wherever available — never a secret.
- **Metrics**: Prometheus exposition at `/metrics` on both the API and the worker (the worker's
  is on a separate, non-business `WORKER_METRICS_PORT` listener).
- **Tracing**: OpenTelemetry. A genuine no-op when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (no
  collector is part of this stack); when set, HTTP requests, RabbitMQ publish/consume, and the
  outbox publisher all produce spans, and a job's trace context flows from the HTTP request that
  created it through to the worker that processes it.

## API documentation

See [`docs/openapi.yaml`](docs/openapi.yaml) — every endpoint, schema, error shape, pagination
contract, and example. View it with any OpenAPI viewer (e.g.
`npx @redocly/cli preview-docs docs/openapi.yaml`).

## Repository layout

```
nix-platform/
├── backend/            Go module: cmd/{api,worker}, internal/{platform,domain,modules,app}, migrations/
├── frontend/            Next.js app
├── docs/openapi.yaml     API reference
├── .github/workflows/     CI
├── docker-compose.yml     postgres, rabbitmq, backend-api, backend-worker, frontend
├── docker-compose.dev.yml Local-only overrides (exposes postgres/rabbitmq ports)
└── Makefile               dev/up/down/test/lint/migrate-*/...
```

## Extending the platform

New business modules follow the same four-to-five-layer shape as the existing ones
(`domain/`, `application/`, `infrastructure/`, `transport/`, optionally `worker/`) and are wired
in exactly one place: `backend/internal/app/modules.go`. A new SecOps provider, for instance, is
just another `domain.SecurityProvider` implementation registered in that file's `providers` map —
no changes to the SecOps module itself, the RabbitMQ topology, or the Core.

Extraction to a separate service is deliberately not a starting decision — the modular monolith
is the plan until a module has a concrete, real reason (independent scaling, independent
deploys, a dedicated team) to be pulled out.

## License

MIT — see [LICENSE](LICENSE).
