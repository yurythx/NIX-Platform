import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Minimal self-contained server output for the Docker runtime stage
  // (backend/../frontend/Dockerfile copies .next/standalone) — §58.
  output: "standalone",

  // React Compiler: memoização automática (useMemo/useCallback/
  // React.memo deixam de ser manuais) — habilitado a esta altura porque
  // o código JÁ está em conformidade com as regras que o compiler exige
  // (eslint-plugin-react-hooks nesta versão, ver AGENTS.md, já proíbe
  // ler/escrever ref.current durante o render e setState incondicional
  // em useEffect — as mesmas regras que o compiler em si valida).
  // Suportado com Turbopack nesta versão do Next.js (não é mais
  // experimental frágil), exige a devDependency
  // babel-plugin-react-compiler.
  reactCompiler: true,

  // Headers de segurança complementares à CSP com nonce (proxy.ts) — CSP
  // já cobre a superfície mais valiosa (script/style/frame-ancestors),
  // mas não é o mecanismo certo pra estes quatro, cada um resolvendo um
  // problema que CSP não cobre:
  // - X-Content-Type-Options: nosniff — impede o navegador de tentar
  //   "adivinhar" um Content-Type diferente do declarado pela resposta
  //   (o vetor clássico é servir algo como texto/imagem que na verdade é
  //   interpretado como script/HTML pelo MIME sniffing do navegador).
  // - Referrer-Policy — sem isso, navegar de uma página autenticada
  //   desta plataforma para um link externo vaza a URL completa (que
  //   pode conter um path com um id de recurso) no cabeçalho Referer da
  //   requisição pro site de destino; strict-origin-when-cross-origin
  //   ainda manda o referrer completo entre páginas do mesmo site
  //   (útil pra analytics interno, se algum dia existir) mas só a origem
  //   pra fora.
  // - Permissions-Policy — desliga explicitamente APIs de
  //   hardware/sensor que este dashboard nunca usa (câmera, microfone,
  //   geolocalização, USB, ...); um XSS que escapasse da CSP ainda
  //   esbarraria nisso antes de conseguir pedir acesso a qualquer uma
  //   delas.
  // - Strict-Transport-Security — instrui o navegador a nunca tentar
  //   HTTP puro de novo com este host pelo próximo ano; enviado sempre
  //   (não só condicionado a produção) porque o navegador IGNORA este
  //   cabeçalho quando a resposta chega por uma conexão HTTP simples
  //   (dev local) — mandar sempre é inofensivo e evita esquecer de
  //   ligar em produção, mesmo raciocínio de upgrade-insecure-requests
  //   já estar sempre presente na CSP (proxy.ts), independente de
  //   isDev.
  //
  // frame-ancestors 'none' na CSP já cobre clickjacking (substitui
  // X-Frame-Options, obsoleto pra esse fim) — não repetido aqui.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()",
          },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        ],
      },
    ];
  },

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
