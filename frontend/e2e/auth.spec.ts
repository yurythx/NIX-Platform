import { expect, test } from "@playwright/test";

// Login local (§ Sistema de Login Local) — o caminho de auth que não
// depende de nenhum Keycloak externo, por isso o único exercitável em
// CI/local sem provisionar um IdP. Usa o admin/Admin123! seedado pela
// migration 000011_local_auth.sql (documentado no README, "Login local")
// — nunca credenciais inventadas.
//
// Roda contra a stack REAL (docker compose up, ver docs/e2e.md) — sem
// isso, PLAYWRIGHT_BASE_URL não responde e todo teste aqui falha rápido
// e claramente (connection refused), nunca silenciosamente.
test.describe("Login local", () => {
  test("credenciais corretas: entra, vê o dashboard, e Sair encerra a sessão", async ({ page }) => {
    await page.goto("/login");

    await page.getByLabel("Usuário").fill("admin");
    await page.getByLabel("Senha", { exact: true }).fill("Admin123!");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();

    await expect(page).toHaveURL(/\/dashboard$/);
    // Sidebar (nav aria-label="Principal", ver Sidebar.tsx — não o
    // atalho "Ver integrações" que /dashboard também tem) — prova que a
    // sessão foi de fato estabelecida, não só que a URL mudou.
    await expect(
      page.getByRole("navigation", { name: "Principal" }).getByRole("link", { name: "Integrações" }),
    ).toBeVisible();

    // UserMenu → Sair (RP-Initiated Logout, §30) — mesmo fluxo real que
    // components/layout/UserMenu.test.tsx já cobre em isolamento (mock),
    // aqui contra o navegador/servidor de verdade.
    await page.getByRole("button", { name: /Menu do usuário/ }).click();
    await page.getByRole("menuitem", { name: "Sair" }).click();
    await expect(page).toHaveURL(/^http:\/\/[^/]+\/?$/, { timeout: 10_000 });

    // Sessão de fato encerrada — voltar pra uma rota protegida exige
    // login de novo, não fica "meio logado" preso em algum estado.
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login(\?.*)?$/);
  });

  test("credenciais erradas: mensagem genérica, nunca revela qual campo errou", async ({ page }) => {
    await page.goto("/login");

    await page.getByLabel("Usuário").fill("admin");
    await page.getByLabel("Senha", { exact: true }).fill("senha-errada-de-propósito");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();

    // Mesma mensagem genérica pra usuário inexistente, senha errada ou
    // conta bloqueada (§ Login local no README) — nunca "senha
    // incorreta" nem "usuário não encontrado", que revelariam qual
    // condição falhou.
    await expect(page.getByText("Usuário ou senha inválidos.")).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });
});
