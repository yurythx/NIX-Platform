// Cliente tipado para Client Components — sempre chama o proxy BFF na
// mesma origem (/api/backend/*), nunca a API Go diretamente, para que o
// bearer token nunca precise chegar ao JavaScript executado no navegador
// (§30).

interface ErrorBody {
  code: string;
  message: string;
}

interface Envelope<T> {
  data: T | null;
  error: ErrorBody | null;
  meta?: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<{ data: T; meta?: unknown }> {
  // Um corpo FormData (Fase 10 — postForm, upload de .zip) nunca ganha um
  // Content-Type fixo aqui: o browser precisa gerar esse header sozinho,
  // com o boundary multipart correto — um Content-Type: application/json
  // explícito (mesmo que "errado") NUNCA é sobrescrito pelo fetch, então
  // fixá-lo aqui quebraria toda requisição multipart.
  const isFormData = typeof FormData !== "undefined" && init?.body instanceof FormData;
  const res = await fetch(`/api/backend/${path}`, {
    ...init,
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers ?? {}),
    },
  });

  let json: Envelope<T>;
  try {
    json = await res.json();
  } catch {
    throw new ApiError(
      res.status,
      "INVALID_RESPONSE",
      "O servidor retornou uma resposta ilegível.",
    );
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

export const apiClient = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  // postForm: caminho separado de post() pra um corpo multipart/form-data
  // (Fase 10 — projeto criado por upload .zip) — nunca passa por
  // JSON.stringify, e nunca define Content-Type manualmente: o browser
  // precisa gerar esse header sozinho a partir do FormData, incluindo o
  // boundary multipart, que request() (Content-Type: application/json
  // fixo) sobrescreveria e quebraria a requisição inteira.
  postForm: <T>(path: string, form: FormData) =>
    request<T>(path, { method: "POST", body: form, headers: {} }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "PATCH",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  // put/delete (Fase 14 — Maturidade de AppSec): triar/reabrir um achado
  // (PUT/DELETE .../findings/{fingerprint}/triage) — os dois primeiros
  // usos destes verbos neste cliente; mesmo formato de corpo/erro que
  // post/patch já têm, nada específico de triagem aqui.
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "PUT",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};
