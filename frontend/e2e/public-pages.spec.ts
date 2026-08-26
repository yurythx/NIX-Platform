import { expect, test } from "@playwright/test";

// Páginas públicas (§ Reestruturação de páginas) — as únicas duas rotas
// que não exigem sessão nenhuma. Nenhum mock de rede aqui: são páginas
// puramente estáticas server-side, sem chamada à API Go.
test.describe("Páginas públicas", () => {
  test("/ mostra a filosofia da plataforma e link pra /sobre", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByRole("link", { name: "Sobre a plataforma" })).toBeVisible();
  });

  test("/sobre carrega sem erro", async ({ page }) => {
    const response = await page.goto("/sobre");
    expect(response?.ok()).toBe(true);
  });

  // proxy.ts (§30) redireciona qualquer visita não autenticada às seções
  // protegidas pra /login ANTES da página sequer começar a renderizar —
  // este teste prova isso de ponta a ponta, contra o servidor real, não
  // só lendo o código-fonte do middleware.
  test("visitar /dashboard sem sessão redireciona pra /login", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login(\?.*)?$/);
  });

  test("robots.txt e sitemap.xml respondem", async ({ page }) => {
    const robots = await page.goto("/robots.txt");
    expect(robots?.ok()).toBe(true);
    expect(await robots?.text()).toContain("Sitemap:");

    const sitemap = await page.goto("/sitemap.xml");
    expect(sitemap?.ok()).toBe(true);
    expect(await sitemap?.text()).toContain("<urlset");
  });
});
