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

  // O que authorize() do CredentialsProvider local retorna (ver
  // lib/auth/options.ts) — o campo extra accessToken/accessTokenExpires
  // é o que o callback jwt() copia para o token de sessão, no mesmo lugar
  // onde o fluxo Keycloak copia account.access_token.
  interface User {
    accessToken?: string;
    accessTokenExpires?: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    accessTokenExpires?: number;
    refreshToken?: string;
    // Necessário para o RP-Initiated Logout (ver
    // app/api/auth/keycloak-logout-url/route.ts) — é o id_token_hint que
    // o Keycloak exige para encerrar a sessão dele também. Ausente para
    // sessões do login local, que não têm um id_token do Keycloak — ver
    // fullSignOut() em components/layout/UserMenu.tsx.
    idToken?: string;
    error?: string;
  }
}
