import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

// Next.js 16 renamed the middleware.ts convention to proxy.ts (same
// mechanics, new file/export name) — this guards every /dashboard route,
// redirecting unauthenticated visitors to /login instead of leaking a
// blank/erroring page.
export async function proxy(request: NextRequest) {
  const token = await getToken({ req: request });

  if (!token || token.error) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", request.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
