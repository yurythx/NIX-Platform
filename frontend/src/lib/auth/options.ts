import type { NextAuthOptions, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";
import CredentialsProvider from "next-auth/providers/credentials";
import KeycloakProvider from "next-auth/providers/keycloak";

// Env somente de servidor — nunca com prefixo NEXT_PUBLIC_, nunca enviada
// ao navegador (§30: segredos nunca em NEXT_PUBLIC_*).
const issuer = process.env.KEYCLOAK_ISSUER_URL;
const clientId = process.env.KEYCLOAK_FRONTEND_CLIENT_ID;
const clientSecret = process.env.KEYCLOAK_FRONTEND_CLIENT_SECRET;

if (!issuer || !clientId || !clientSecret) {
  // Fail fast (o mesmo princípio do §62 do backend, aplicado ao
  // frontend): uma configuração de cliente OIDC ausente deve quebrar o
  // startup, não servir silenciosamente uma aplicação em que ninguém
  // consegue logar.
  throw new Error(
    "Missing Keycloak frontend OIDC configuration: KEYCLOAK_ISSUER_URL, " +
      "KEYCLOAK_FRONTEND_CLIENT_ID and KEYCLOAK_FRONTEND_CLIENT_SECRET are all required.",
  );
}

// O mesmo endereço interno que o proxy BFF usa (ver
// app/api/backend/[...path]/route.ts) — o login local também é uma
// chamada server-to-server ao backend Go, nunca exposta ao navegador.
const backendInternalURL = process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8000";

interface KeycloakTokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  error?: string;
}

/** Renova um access token expirado através do endpoint de token do
 * Keycloak, usando o refresh_token guardado na sessão. Só se aplica a
 * sessões que vieram do Keycloak — o login local (ver
 * localLoginAuthorize) não tem conceito de refresh token, uma sessão
 * local expirada simplesmente exige logar de novo. */
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
    // Marca o erro na sessão em vez de lançar — o chamador (callback jwt)
    // segue com um token expirado + error="RefreshAccessTokenError", e é
    // esse campo que o middleware/proxy.ts usa para decidir redirecionar
    // para /login.
    console.error("Failed to refresh Keycloak access token", err);
    return { ...token, error: "RefreshAccessTokenError" };
  }
}

interface LocalLoginResponse {
  data: {
    access_token: string;
    expires_at: string;
    user: { id: string; username: string; email: string };
  } | null;
  error: { code: string; message: string } | null;
}

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      issuer,
      clientId,
      clientSecret,
      // As checks padrão do KeycloakProvider já incluem "pkce" e "state"
      // — Authorization Code + PKCE conforme §30, sem configuração extra
      // necessária.
    }),

    // Login local (§ Sistema de Login Local) — um caminho ADICIONAL ao
    // Keycloak, nunca um substituto. Chama o mesmo endpoint que qualquer
    // outro cliente HTTP chamaria (POST /api/v1/auth/login no backend
    // Go); este provider só faz a ponte entre o formulário de
    // usuário/senha e a sessão do NextAuth. Se LOCAL_AUTH_ENABLED=false
    // no backend, o endpoint responde 404 e authorize() retorna null —
    // o botão de login local continua aparecendo no frontend, mas
    // qualquer tentativa falha com a mensagem genérica de credenciais
    // inválidas (não vaza se o recurso está desligado ou se a senha
    // estava errada).
    CredentialsProvider({
      id: "local",
      name: "Local",
      credentials: {
        username: { label: "Usuário", type: "text" },
        password: { label: "Senha", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password) {
          return null;
        }

        let res: Response;
        try {
          res = await fetch(`${backendInternalURL}/api/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: credentials.username,
              password: credentials.password,
            }),
          });
        } catch (err) {
          console.error("Local login: backend unreachable", err);
          return null;
        }

        const body: LocalLoginResponse = await res.json();
        if (!res.ok || !body.data) {
          return null;
        }

        return {
          id: body.data.user.id,
          name: body.data.user.username,
          email: body.data.user.email,
          accessToken: body.data.access_token,
          accessTokenExpires: new Date(body.data.expires_at).getTime(),
        };
      },
    }),
  ],

  // Estratégia de sessão em JWT: a sessão é um cookie criptografado,
  // HttpOnly, SameSite=Lax, marcado Secure automaticamente sempre que
  // NEXTAUTH_URL é https:// (padrão do next-auth — §30) — nunca
  // localStorage ou sessionStorage. O access token bruto vive só dentro
  // deste token criptografado no lado do servidor, nunca no objeto
  // `session` exposto a Client Components — ver o callback session abaixo.
  //
  // Usando deliberadamente o nome/opções de cookie padrão do next-auth
  // aqui, em vez de um nome customizado: toda chamada de getToken() do
  // lado do servidor (proxy.ts, o proxy BFF do backend) precisa concordar
  // exatamente sobre qual nome de cookie ler, e um nome customizado é mais
  // um lugar onde as coisas podem silenciosamente sair de sincronia e
  // quebrar a autenticação.
  session: { strategy: "jwt" },

  callbacks: {
    async jwt({ token, account, user }) {
      // Primeiro login via Keycloak: persiste os tokens que ele acabou de
      // emitir (inclui refresh_token — sessões Keycloak se renovam
      // sozinhas via refreshAccessToken quando expiram).
      if (account?.provider === "keycloak") {
        return {
          ...token,
          accessToken: account.access_token,
          accessTokenExpires: account.expires_at ? account.expires_at * 1000 : undefined,
          refreshToken: account.refresh_token,
          idToken: account.id_token,
        };
      }

      // Primeiro login via credenciais locais: authorize() já validou a
      // senha e devolveu um token pronto do backend — não há
      // refresh_token neste caminho (ver o comentário de
      // refreshAccessToken), então quando accessTokenExpires passar a
      // sessão simplesmente expira e pede novo login.
      if (account?.provider === "local" && user) {
        return {
          ...token,
          accessToken: user.accessToken,
          accessTokenExpires: user.accessTokenExpires,
          refreshToken: undefined,
          idToken: undefined,
        };
      }

      // Ainda válido.
      if (token.accessTokenExpires && Date.now() < (token.accessTokenExpires as number)) {
        return token;
      }

      // Expirado: só o caminho Keycloak sabe se renovar sozinho.
      if (token.refreshToken) {
        return refreshAccessToken(token);
      }

      return { ...token, error: "RefreshAccessTokenError" };
    },

    async session({ session, token }): Promise<Session> {
      // Deliberadamente NÃO copia accessToken para o objeto session:
      // Client Components nunca veem o bearer token bruto. Server
      // Components / Route Handlers que precisam dele o leem via
      // next-auth/jwt's getToken() (ver o proxy BFF em
      // app/api/backend/[...path]/route.ts) — o token nunca cruza para o
      // JavaScript executado no navegador.
      session.user = session.user ?? {};
      session.error = token.error as string | undefined;
      return session;
    },
  },

  pages: {
    signIn: "/login",
  },
};
