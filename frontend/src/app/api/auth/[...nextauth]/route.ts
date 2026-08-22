import NextAuth from "next-auth";

import { authOptions } from "@/lib/auth/options";

// Route handler catch-all do NextAuth: trata /api/auth/signin,
// /api/auth/callback/keycloak, /api/auth/session etc. — toda a lógica de
// fato (provider Keycloak, estratégia de sessão, refresh de token) vive
// em lib/auth/options.ts.
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
