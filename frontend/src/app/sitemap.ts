import type { MetadataRoute } from "next";

// Sitemap mínimo, honesto: só as duas rotas públicas de verdade (/ e
// /sobre) têm metadados OG (ver page.tsx/sobre/page.tsx, § auditoria
// 2026-08) — tudo abaixo de /dashboard, /integracoes, /configuracao,
// /seguranca é autenticado e não pertence aqui (um crawler nunca
// consegue passar da tela de login mesmo assim).
//
// Sem NEXT_PUBLIC_SITE_URL dedicada nesta aplicação — reaproveita
// NEXTAUTH_URL, a mesma variável que já serve de base pra outras
// construções de URL absoluta no frontend (ver
// app/api/auth/keycloak-logout-url/route.ts), com o mesmo fallback pra
// desenvolvimento local.
const baseUrl = process.env.NEXTAUTH_URL ?? "http://localhost:3000";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: baseUrl, lastModified: new Date(), changeFrequency: "monthly", priority: 1 },
    { url: `${baseUrl}/sobre`, lastModified: new Date(), changeFrequency: "monthly", priority: 0.8 },
  ];
}
