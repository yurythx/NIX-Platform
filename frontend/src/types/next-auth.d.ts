import "next-auth";
import "next-auth/jwt";

// Aumenta (module augmentation) os tipos padrão do next-auth com os campos
// específicos desta aplicação — sem isto, TypeScript não conheceria
// session.error nem os campos extras de token que lib/auth/options.ts
// grava (accessToken, refreshToken, idToken, etc.).
declare module "next-auth" {
  interface Session {
    // Definido como "RefreshAccessTokenError" quando a renovação do
    // access token falha (ver refreshAccessToken em lib/auth/options.ts)
    // — proxy.ts usa este campo para decidir redirecionar para /login.
    error?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    accessTokenExpires?: number;
    refreshToken?: string;
    // Necessário para o RP-Initiated Logout (ver
    // app/api/auth/keycloak-logout-url/route.ts) — é o id_token_hint que
    // o Keycloak exige para encerrar a sessão dele também.
    idToken?: string;
    error?: string;
  }
}
