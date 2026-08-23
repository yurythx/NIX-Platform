import { cookies, headers } from "next/headers";
import { getToken, type JWT } from "next-auth/jwt";
import type { NextRequest } from "next/server";

// getToken() (next-auth v4) decodifica o cookie de sessão criptografado
// diretamente — o mesmo mecanismo que src/proxy.ts e o proxy BFF
// (app/api/backend/[...path]/route.ts) já usam, só que os dois recebem um
// NextRequest de verdade (middleware/Route Handler). Um Server Component
// não tem acesso a um NextRequest — só às APIs de leitura de
// next/headers. Na prática getToken só lê cookies (pra achar o cookie de
// sessão) e cabeçalhos (fallback de alguns detalhes de ambiente); um
// objeto com essas duas coisas, no formato que ele espera, é o suficiente
// — daí o cast abaixo. Este é o único lugar do projeto que precisa desse
// cast; toda página/Server Component que precisa do token de sessão passa
// por aqui, não reimplementa isto.
export async function getServerToken(): Promise<JWT | null> {
  const [cookieStore, headerList] = await Promise.all([cookies(), headers()]);

  const req = {
    cookies: Object.fromEntries(cookieStore.getAll().map((c) => [c.name, c.value])),
    headers: Object.fromEntries(headerList.entries()),
  };

  return getToken({ req: req as unknown as NextRequest });
}
