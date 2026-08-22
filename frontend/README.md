# NIX Platform — Frontend

Next.js (App Router) + TypeScript dashboard for the NIX Platform. See the
[repository root README](../README.md) for the full project overview,
Keycloak setup, and how to run the whole stack via Docker Compose.

## Local development

```bash
cp .env.example .env.local   # fill in Keycloak/backend values
npm install
npm run dev
```

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Production build (`.next/standalone`) |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Run the Vitest suite once |
| `npm run test:watch` | Vitest in watch mode |
| `npm run format` | Prettier, write mode |

## Layout

- `src/app` — routes (App Router): landing page, `/login`, `/dashboard/**`,
  the NextAuth route handler, and the `/api/backend/*` BFF proxy.
- `src/lib/auth` — NextAuth configuration (Keycloak, Authorization Code +
  PKCE, JWT session).
- `src/lib/api` — typed client for Client Components; always calls the
  same-origin BFF proxy so the access token never reaches browser JS.
- `src/lib/websocket` — reconnecting WebSocket client with backoff and
  heartbeat handling.
- `src/lib/validation` — Zod schemas validating every WebSocket payload
  before it's used.
- `src/components/ui` — the shared, business-logic-free component kit.
- `src/proxy.ts` — Next.js 16's `proxy.ts` (formerly `middleware.ts`)
  guarding `/dashboard/**`.
