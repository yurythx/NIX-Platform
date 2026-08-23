import "server-only";

import { getServerToken } from "@/lib/auth/serverToken";
import { ApiError } from "@/lib/api/client";
import { BACKEND_INTERNAL_URL } from "@/lib/api/backendUrl";

// Busca de dados em Server Component (§ Migração pra Server Components —
// auditoria 2026-08): antes desta mudança, TODA página autenticada
// buscava seus dados no cliente via useEffect, pagando uma cascata
// (HTML vazio -> hidratação -> fetch -> render) em toda navegação, e sem
// nenhum compartilhamento entre componentes que pedem os mesmos dados. Um
// Server Component já roda no servidor, então pode ir direto no backend —
// sem o hop extra pelo proxy BFF (app/api/backend/[...path]/route.ts, que
// existe especificamente pra manter o bearer token longe do navegador,
// uma preocupação que não existe aqui). Mesmo formato de envelope
// {data,error} e mesma classe ApiError que lib/api/client.ts já usa, pra
// quem chama tratar erro de um jeito só, não importa qual dos dois
// caminhos buscou os dados.
//
// "server-only" (import acima) faz o build falhar se este módulo algum
// dia for importado por engano de um Client Component — ele nunca deveria
// ser, já que lê o token de sessão diretamente.

interface Envelope<T> {
  data: T | null;
  error: { code: string; message: string } | null;
  meta?: unknown;
}

export async function serverApiGet<T>(path: string): Promise<{ data: T; meta?: unknown }> {
  const token = await getServerToken();
  if (!token || !token.accessToken || token.error) {
    throw new ApiError(401, "UNAUTHORIZED", "autenticação necessária");
  }

  const targetUrl = new URL(`/api/${path}`, BACKEND_INTERNAL_URL);

  let res: Response;
  try {
    res = await fetch(targetUrl, {
      headers: { Authorization: `Bearer ${token.accessToken}` },
      // Cada página decide sua própria estratégia de cache via
      // fetch/revalidate se precisar — o padrão aqui é sempre buscar
      // dados frescos, consistente com o que useEffect+fetch já fazia
      // (nenhuma página tinha cache antes desta migração).
      cache: "no-store",
    });
  } catch {
    throw new ApiError(503, "DEPENDENCY_UNAVAILABLE", "a API está indisponível no momento");
  }

  let json: Envelope<T>;
  try {
    json = await res.json();
  } catch {
    throw new ApiError(res.status, "INVALID_RESPONSE", "O servidor retornou uma resposta ilegível.");
  }

  if (!res.ok || json.error) {
    throw new ApiError(
      res.status,
      json.error?.code ?? "UNKNOWN_ERROR",
      json.error?.message ?? "Algo deu errado. Tente novamente.",
    );
  }

  return { data: json.data as T, meta: json.meta };
}
