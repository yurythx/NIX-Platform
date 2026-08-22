import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// Logout completo (RP-Initiated Logout, OIDC): sem isto, o botão "Sair"
// só limpa o cookie de sessão local do NextAuth — a sessão continua viva
// no próprio Keycloak, então qualquer aba/dispositivo que ainda tenha um
// refresh token válido, ou um "silent login" (prompt=none), reautentica
// o usuário sem pedir senha de novo. É preciso mandar o NAVEGADOR visitar
// o endpoint de logout do Keycloak (não dá pra fazer isso só no servidor
// — é o Keycloak quem precisa limpar os próprios cookies de sessão dele
// no domínio dele).
//
// Esta rota só monta e devolve a URL; quem efetivamente desloga do
// Keycloak é o navegador ao navegar até ela. É chamada ANTES de
// signOut() no client, porque depois que a sessão local for limpa não
// há mais como ler o id_token daqui.
export async function GET(req: NextRequest) {
  const issuer = process.env.KEYCLOAK_ISSUER_URL;
  const appUrl = process.env.NEXTAUTH_URL ?? req.nextUrl.origin;

  if (!issuer) {
    return NextResponse.json({ url: appUrl });
  }

  const token = await getToken({ req });
  if (!token?.idToken) {
    // Sem sessão (ou sem id_token guardado) — não há o que encerrar no
    // Keycloak; volta direto para a aplicação.
    return NextResponse.json({ url: appUrl });
  }

  const logoutUrl = new URL(`${issuer}/protocol/openid-connect/logout`);
  logoutUrl.searchParams.set("id_token_hint", token.idToken as string);
  logoutUrl.searchParams.set("post_logout_redirect_uri", appUrl);

  return NextResponse.json({ url: logoutUrl.toString() });
}
