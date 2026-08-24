import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

// O Next.js 16 renomeou a convenção middleware.ts para proxy.ts (mesmo
// mecanismo, só o nome do arquivo/export mudou). Esta função tem duas
// responsabilidades:
//
// 1. Content-Security-Policy com nonce (item de segurança prioritário):
//    gera um nonce novo a cada requisição e o injeta tanto no cabeçalho
//    CSP quanto num cabeçalho interno x-nonce que o Next.js lê
//    automaticamente para carimbar os próprios scripts/estilos do
//    framework — nada no código da aplicação precisa passar o nonce
//    manualmente. Isso exige renderização dinâmica (não hidrata bem com
//    páginas estáticas em cache), aceitável aqui pois é um dashboard
//    interno, não um site de alto tráfego dependente de cache em CDN.
//
// 2. Proteção de rota: redireciona visitas não autenticadas a qualquer
//    seção protegida (PROTECTED_PREFIXES) para /login, sem deixar a
//    página nem começar a renderizar.
// Seções autenticadas (§ Reestruturação de rotas): as duas compartilham
// um único grupo de rotas no App Router (app/(protected)/), mas esse
// grupo não aparece na URL — proxy.ts só enxerga o caminho real, então
// precisa saber sobre as duas independentemente.
const PROTECTED_PREFIXES = ["/dashboard", "/integracoes", "/configuracao", "/seguranca"];

export async function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";

  // connect-src precisa liberar explicitamente a origem do WebSocket: o
  // navegador conecta DIRETO no backend Go (ws://.../ws?ticket=...), não
  // através do proxy BFF same-origin usado pelas chamadas REST.
  const wsOrigin = wsOriginFromPublicUrl(process.env.NEXT_PUBLIC_WS_URL);

  // unsafe-eval só em desenvolvimento: o React usa eval para reconstruir
  // stack traces do servidor no navegador durante o dev; não é usado em
  // produção nem pelo React nem pelo Next.js.
  const cspHeader = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""};
    style-src 'self' 'nonce-${nonce}'${isDev ? " 'unsafe-inline'" : ""};
    img-src 'self' blob: data:;
    font-src 'self';
    connect-src 'self'${wsOrigin ? ` ${wsOrigin}` : ""};
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `
    .replace(/\s{2,}/g, " ")
    .trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", cspHeader);

  const isProtectedRoute = PROTECTED_PREFIXES.some(
    (prefix) => request.nextUrl.pathname === prefix || request.nextUrl.pathname.startsWith(prefix + "/"),
  );
  if (isProtectedRoute) {
    const token = await getToken({ req: request });
    if (!token || token.error) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("callbackUrl", request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", cspHeader);
  return response;
}

// Extrai só "esquema://host:porta" de uma URL de WebSocket pública
// (ws://localhost:8000/ws -> ws://localhost:8000), formato que
// connect-src exige — um caminho (/ws) não é uma origem válida em CSP.
function wsOriginFromPublicUrl(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

export const config = {
  matcher: [
    // Roda em toda página HTML, exceto rotas de API, assets estáticos
    // do Next e favicon — essas nunca precisam de CSP de página nem de
    // verificação de sessão.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
