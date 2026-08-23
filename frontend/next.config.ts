import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Minimal self-contained server output for the Docker runtime stage
  // (backend/../frontend/Dockerfile copies .next/standalone) — §58.
  output: "standalone",

  // § Reestruturação de rotas: histórico completo dos nomes que estas
  // páginas já tiveram, cada um redirecionando pro caminho canônico
  // ATUAL (nunca removido daqui, só atualizado quando o destino final
  // muda de novo — assim nenhum link/favorito antigo, de nenhuma época,
  // devolve 404). Estado atual: /dashboard só a visão geral; Usuários e
  // Configuração dinâmica em /configuracao/**; Integrações tem menu
  // próprio em /integracoes/** (não é mais uma aba de /configuracao).
  async redirects() {
    return [
      { source: "/dashboard/users", destination: "/configuracao/usuarios", permanent: true },
      { source: "/dashboard/settings", destination: "/configuracao", permanent: true },
      {
        source: "/dashboard/settings/integrations/diario",
        destination: "/integracoes/diario-oficial",
        permanent: true,
      },
      { source: "/dashboard/integrations", destination: "/integracoes", permanent: true },
      {
        source: "/dashboard/integrations/diario",
        destination: "/integracoes/diario-oficial",
        permanent: true,
      },
      { source: "/configuracao/integracoes", destination: "/integracoes", permanent: true },
      {
        source: "/configuracao/integracoes/diario",
        destination: "/integracoes/diario-oficial",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
