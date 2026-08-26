import { defineConfig, devices } from "@playwright/test";

// E2E (§ auditoria — nenhum framework existia até agora): exercita a
// aplicação de ponta a ponta contra uma stack REAL (frontend + backend +
// Postgres + RabbitMQ via docker compose, ver docs/e2e.md) — nunca mocka
// fetch/WebSocket como os testes de componente (vitest) já fazem. Sem
// isso, a única verificação de "o fluxo inteiro funciona" era manual,
// registrada como texto no roadmap ("verificado ao vivo") em vez de um
// teste que roda de novo sozinho.
//
// baseURL/PLAYWRIGHT_BASE_URL: aponta pro frontend já rodando (dev,
// build standalone, ou o serviço `frontend` do docker-compose.yml) — os
// testes nunca sobem o servidor sozinhos (webServer: undefined,
// deliberado), porque o fluxo real depende de backend-api/postgres/
// rabbitmq/Keycloak-ou-login-local já no ar, infraestrutura que só o
// docker-compose sabe montar corretamente (ver docs/e2e.md).
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
