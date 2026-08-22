import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// BFF proxy: every Client Component call to the Go API goes through here
// instead of carrying a bearer token into browser-executed JavaScript.
// The real access token is read server-side from the encrypted session
// cookie and attached here — it never reaches the client (§30/§57).
const BACKEND_URL =
  process.env.BACKEND_INTERNAL_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function proxy(req: NextRequest, path: string[]): Promise<NextResponse> {
  const token = await getToken({ req });
  if (!token || !token.accessToken || token.error) {
    return NextResponse.json(
      { data: null, error: { code: "UNAUTHORIZED", message: "authentication required" } },
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
    // GET/HEAD must not carry a body.
    body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.text(),
  };

  let backendResponse: Response;
  try {
    backendResponse = await fetch(targetUrl, init);
  } catch {
    return NextResponse.json(
      {
        data: null,
        error: { code: "DEPENDENCY_UNAVAILABLE", message: "the API is currently unreachable" },
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
