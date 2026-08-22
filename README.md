# NIX Platform

Corporate modular platform centralizing internal functionality, integrations, automation and notifications behind a single extensible application.

Built as a **Modular Monolith** (Go API + Go Worker + Next.js frontend) with an **event-driven** core: PostgreSQL for state, RabbitMQ for asynchronous processing, and an existing external Keycloak for identity.

> **Status:** under active initial build-out. This section is intentionally minimal during early phases — see the roadmap below — and will be replaced with full setup/architecture/operations documentation once the platform (auth, messaging, WebSocket, modules, frontend, tests) is complete.

## Architecture at a glance

- **Backend** (`backend/`): Go modular monolith — `cmd/api` (REST + WebSocket) and `cmd/worker` (RabbitMQ consumers, outbox publisher, job processing) share one codebase and one set of module packages under `internal/modules/`.
- **Frontend** (`frontend/`): Next.js (App Router) + TypeScript, authenticating against Keycloak via OIDC.
- **PostgreSQL**: application data, jobs, outbox events, audit log.
- **RabbitMQ**: `nix.events` topic exchange, per-module queues + dead-letter queues, retry with backoff, publisher confirms, manual ack.
- **Keycloak**: existing external identity provider — this project never provisions Keycloak itself.

Full architecture rationale lives in the project's implementation plan; a detailed README (setup, Keycloak realm/client configuration, RabbitMQ topology, WebSocket protocol, testing, CI) lands once the corresponding phases are built.

## Quick start (once services are buildable)

```bash
cp .env.example .env      # fill in real Keycloak/DB/RabbitMQ values
docker compose up --build
make migrate-up
make test
```

## License

MIT — see [LICENSE](LICENSE).
