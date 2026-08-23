import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Minimal self-contained server output for the Docker runtime stage
  // (backend/../frontend/Dockerfile copies .next/standalone) — §58.
  output: "standalone",

  // § Reestruturação de páginas: /dashboard/integrations foi consolidada
  // em /dashboard/settings (integrações + feature flags no mesmo lugar).
  // Redireciona qualquer link/favorito antigo em vez de simplesmente
  // devolver 404.
  async redirects() {
    return [
      {
        source: "/dashboard/integrations",
        destination: "/dashboard/settings",
        permanent: true,
      },
      {
        source: "/dashboard/integrations/diario",
        destination: "/dashboard/settings/integrations/diario",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
