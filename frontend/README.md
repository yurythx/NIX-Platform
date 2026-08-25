# NIX Platform — Frontend

Dashboard em Next.js (App Router) + TypeScript para o NIX Platform. Veja o
[README raiz do repositório](../README.md) para a visão geral completa do
projeto, a configuração do Keycloak e como rodar toda a stack via Docker
Compose.

## Desenvolvimento local

```bash
cp .env.example .env.local   # preencha os valores de Keycloak/backend
npm install
npm run dev
```

## Scripts

| Comando | Finalidade |
|---|---|
| `npm run dev` | Inicia o servidor de desenvolvimento |
| `npm run build` | Build de produção (`.next/standalone`) |
| `npm run analyze` | `next experimental-analyze` — UI interativa do bundle (Turbopack; passe `-- --output` pra só gravar em disco, sem servidor) |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Roda a suíte Vitest uma vez |
| `npm run test:watch` | Vitest em modo watch |
| `npm run format` | Prettier, modo write |

## Organização

- `src/app` — rotas (App Router): landing page, `/login`, `/dashboard/**`,
  o route handler do NextAuth e o proxy BFF `/api/backend/*`.
- `src/lib/auth` — configuração do NextAuth (Keycloak, Authorization Code +
  PKCE, sessão em JWT).
- `src/lib/api` — `client.ts`: cliente tipado para Client Components; sempre chama o proxy BFF na
  mesma origem, para que o access token nunca chegue ao JS do navegador. `swr.ts`/`SWRProvider.tsx`:
  integração com SWR (dedupe/cache/revalidação) para o pouco que ainda é `"use client"` +
  busca de dados depois do carregamento inicial — a maioria das páginas busca em Server Components,
  ver `src/app/**/page.tsx`.
- `src/lib/websocket` — cliente WebSocket com reconexão, backoff e
  heartbeat.
- `src/lib/validation` — schemas Zod que validam todo payload de WebSocket
  antes de ele ser usado.
- `src/components/ui` — o kit de componentes compartilhado, sem regra de
  negócio.
- `src/proxy.ts` — o `proxy.ts` do Next.js 16 (antigo `middleware.ts`),
  responsável por proteger `/dashboard/**` e por gerar o CSP com nonce em
  cada requisição.
