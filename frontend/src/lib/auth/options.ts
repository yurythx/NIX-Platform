import type { NextAuthOptions, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";
import KeycloakProvider from "next-auth/providers/keycloak";

// Server-side only env — never prefixed NEXT_PUBLIC_, never sent to the
// browser (§30: secrets never in NEXT_PUBLIC_*).
const issuer = process.env.KEYCLOAK_ISSUER_URL;
const clientId = process.env.KEYCLOAK_FRONTEND_CLIENT_ID;
const clientSecret = process.env.KEYCLOAK_FRONTEND_CLIENT_SECRET;

if (!issuer || !clientId || !clientSecret) {
  // Fail fast (§62's principle applied to the frontend): a missing OIDC
  // client config should break startup, not silently serve an app no one
  // can log into.
  throw new Error(
    "Missing Keycloak frontend OIDC configuration: KEYCLOAK_ISSUER_URL, " +
      "KEYCLOAK_FRONTEND_CLIENT_ID and KEYCLOAK_FRONTEND_CLIENT_SECRET are all required.",
  );
}

interface KeycloakTokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  error?: string;
}

/** Refreshes an expired access token via Keycloak's token endpoint. */
async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    const response = await fetch(`${issuer}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId!,
        client_secret: clientSecret!,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken as string,
      }),
    });

    const refreshed: KeycloakTokenResponse = await response.json();
    if (!response.ok) {
      throw refreshed;
    }

    return {
      ...token,
      accessToken: refreshed.access_token,
      accessTokenExpires: Date.now() + refreshed.expires_in * 1000,
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
      error: undefined,
    };
  } catch (err) {
    console.error("Failed to refresh Keycloak access token", err);
    return { ...token, error: "RefreshAccessTokenError" };
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      issuer,
      clientId,
      clientSecret,
      // KeycloakProvider's default checks already include "pkce" and
      // "state" — Authorization Code + PKCE per §30, no extra config
      // needed.
    }),
  ],

  // JWT session strategy: the session is an encrypted, HttpOnly,
  // SameSite=Lax cookie, marked Secure automatically whenever NEXTAUTH_URL
  // is https:// (next-auth's default — §30) — never localStorage or
  // sessionStorage. The raw access token lives only in this
  // server-side-encrypted token, never in the `session` object exposed to
  // client components — see the session callback below.
  //
  // Deliberately using next-auth's default cookie name/options here
  // rather than a custom one: every server-side getToken() call (proxy.ts,
  // the backend BFF proxy) must agree on the exact cookie name it reads,
  // and a custom name is one more place that can silently drift out of
  // sync and break auth.
  session: { strategy: "jwt" },

  callbacks: {
    async jwt({ token, account }) {
      // Initial sign-in: persist the tokens Keycloak just issued.
      if (account) {
        return {
          ...token,
          accessToken: account.access_token,
          accessTokenExpires: account.expires_at ? account.expires_at * 1000 : undefined,
          refreshToken: account.refresh_token,
          idToken: account.id_token,
        };
      }

      // Still valid.
      if (token.accessTokenExpires && Date.now() < (token.accessTokenExpires as number)) {
        return token;
      }

      // Expired: refresh it.
      if (token.refreshToken) {
        return refreshAccessToken(token);
      }

      return token;
    },

    async session({ session, token }): Promise<Session> {
      // Deliberately NOT copying accessToken onto the session object:
      // client components never see the raw bearer token. Server
      // Components / Route Handlers that need it read it via
      // next-auth/jwt's getToken() (see lib/api/backend.ts) — the token
      // never crosses into browser-executed JavaScript.
      session.user = session.user ?? {};
      session.error = token.error as string | undefined;
      return session;
    },
  },

  pages: {
    signIn: "/login",
  },
};
