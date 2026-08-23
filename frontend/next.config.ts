import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Minimal self-contained server output for the Docker runtime stage
  // (backend/../frontend/Dockerfile copies .next/standalone) — §58.
  output: "standalone",

  // § Reestruturação de rotas: /dashboard passou a servir só a visão
  // geral; Usuários, Integrações e Configuração dinâmica se mudaram para
  // /configuracao/**. Redireciona todo caminho antigo (inclusive o nome
  // intermediário /dashboard/settings, que essas mesmas páginas usaram
  // por uma sessão antes deste nome final) em vez de devolver 404 pra
  // qualquer link/favorito existente.
  async redirects() {
    return [
      { source: "/dashboard/users", destination: "/configuracao/usuarios", permanent: true },
      { source: "/dashboard/settings", destination: "/configuracao", permanent: true },
      {
        source: "/dashboard/settings/integrations/diario",
        destination: "/configuracao/integracoes/diario",
        permanent: true,
      },
      {
        source: "/dashboard/integrations",
        destination: "/configuracao/integracoes",
        permanent: true,
      },
      {
        source: "/dashboard/integrations/diario",
        destination: "/configuracao/integracoes/diario",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
