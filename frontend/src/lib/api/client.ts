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
  const res = await fetch(`/api/backend/${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
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
};
