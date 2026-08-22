import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// Proxy BFF (Backend For Frontend): toda chamada de Client Component à
// API Go passa por aqui, em vez de carregar um bearer token no JavaScript
// executado no navegador. O access token real é lido no lado do servidor
// a partir do cookie de sessão criptografado e anexado aqui — ele nunca
// chega ao cliente (§30/§57).
const BACKEND_URL =
  process.env.BACKEND_INTERNAL_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// proxy encaminha a requisição para GET /api/v1/{path} ou POST /api/v1/{path}
// na API Go, injetando o Authorization: Bearer e propagando/gerando o
// X-Request-ID (§50) para que a chamada seja correlacionável nos logs do
// backend mesmo tendo passado por este proxy intermediário.
async function proxy(req: NextRequest, path: string[]): Promise<NextResponse> {
  const token = await getToken({ req });
  if (!token || !token.accessToken || token.error) {
    return NextResponse.json(
      { data: null, error: { code: "UNAUTHORIZED", message: "autenticação necessária" } },
      { status: 401 },
    );
  }

  const targetUrl = new URL(`/api/v1/${path.join("/")}`, BACKEND_URL);
  targetUrl.search = req.nextUrl.search;

  const requestId = req.headers.get("x-request-id") ?? crypto.randomUUID();

  const init: RequestInit = {
    method: req.method,
    headers: {
      Authorization: `Bearer ${token.accessToken}`,
      "Content-Type": req.headers.get("content-type") ?? "application/json",
      "X-Request-ID": requestId,
    },
    // GET/HEAD não podem carregar um corpo.
    body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.text(),
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
  return new NextResponse(body, {
    status: backendResponse.status,
    headers: {
      "Content-Type": backendResponse.headers.get("content-type") ?? "application/json",
      "X-Request-ID": requestId,
    },
  });
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxy(req, path);
}
