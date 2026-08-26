import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

import { BACKEND_INTERNAL_URL as BACKEND_URL } from "@/lib/api/backendUrl";

// Proxy BFF (Backend For Frontend): toda chamada de Client Component à
// API Go passa por aqui, em vez de carregar um bearer token no JavaScript
// executado no navegador. O access token real é lido no lado do servidor
// a partir do cookie de sessão criptografado e anexado aqui — ele nunca
// chega ao cliente (§30/§57). Páginas que buscam dados em Server
// Component (§ Migração pra Server Components) não passam por aqui — ver
// lib/api/server.ts, que fala com o backend direto, sem o hop de rede
// extra que uma chamada vinda do navegador precisa.

// proxy encaminha a requisição para GET /api/{path} ou POST /api/{path} na
// API Go, injetando o Authorization: Bearer e propagando/gerando o
// X-Request-ID (§50) para que a chamada seja correlacionável nos logs do
// backend mesmo tendo passado por este proxy intermediário.
//
// {path} já vem com o prefixo de versão incluído (ex.: chamadas do
// frontend usam apiClient.get("v1/integrations")) — este proxy NÃO deve
// prepender "v1/" de novo, senão o alvo vira /api/v1/v1/integrations e
// toda chamada volta 404 (bug real encontrado em produção: o dashboard
// inteiro ficava sem dados porque cada requisição batia nesse path
// duplicado).
async function proxy(req: NextRequest, path: string[]): Promise<NextResponse> {
  const token = await getToken({ req });
  if (!token || !token.accessToken || token.error) {
    return NextResponse.json(
      { data: null, error: { code: "UNAUTHORIZED", message: "autenticação necessária" } },
      { status: 401 },
    );
  }

  const targetUrl = new URL(`/api/${path.join("/")}`, BACKEND_URL);
  targetUrl.search = req.nextUrl.search;

  const requestId = req.headers.get("x-request-id") ?? crypto.randomUUID();

  const init: RequestInit = {
    method: req.method,
    headers: {
      Authorization: `Bearer ${token.accessToken}`,
      "Content-Type": req.headers.get("content-type") ?? "application/json",
      "X-Request-ID": requestId,
    },
    // GET/HEAD não podem carregar um corpo. arrayBuffer(), não text():
    // um corpo multipart/form-data com upload de arquivo (Fase 10 —
    // projeto criado por .zip) carrega bytes binários — .text() decodifica
    // como UTF-8 e corrompe qualquer byte que não seja uma sequência UTF-8
    // válida (troca por U+FFFD), inutilizando o .zip do outro lado.
    // arrayBuffer() encaminha os bytes exatamente como chegaram, correto
    // tanto pra esse caso quanto pro JSON de sempre (texto também
    // sobrevive ileso a um round-trip por bytes).
    body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.arrayBuffer(),
  };

  let backendResponse: Response;
  try {
    backendResponse = await fetch(targetUrl, init);
  } catch {
    return NextResponse.json(
      {
        data: null,
        error: { code: "DEPENDENCY_UNAVAILABLE", message: "a API está indisponível no momento" },
      },
      { status: 503 },
    );
  }

  const body = await backendResponse.text();
  const headers: Record<string, string> = {
    "Content-Type": backendResponse.headers.get("content-type") ?? "application/json",
    "X-Request-ID": requestId,
  };
  // Content-Disposition (Fase 14 — Maturidade de AppSec: exportação CSV,
  // GET .../findings.csv e .../findings-history.csv): sem propagar isto,
  // o navegador abre o CSV cru na aba em vez de baixar com o nome de
  // arquivo que o backend já escolheu (ver transport/csv_export.go) — o
  // único header, além de Content-Type, que algum endpoint hoje depende
  // de atravessar o proxy intacto.
  const contentDisposition = backendResponse.headers.get("content-disposition");
  if (contentDisposition) {
    headers["Content-Disposition"] = contentDisposition;
  }
  return new NextResponse(body, { status: backendResponse.status, headers });
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}

// PATCH: usado hoje só por Configurações > Feature flags
// (PATCH /api/v1/admin/feature-flags/{key}) — mesmo encaminhamento dos
// outros métodos, sem lógica própria.
export async function PATCH(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}

// PUT/DELETE (Fase 14 — Maturidade de AppSec): triar/reabrir um achado
// (PUT|DELETE /api/v1/scanning/projects/{projectID}/findings/{fingerprint}/triage)
// — mesmo encaminhamento, sem lógica própria.
export async function PUT(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}
