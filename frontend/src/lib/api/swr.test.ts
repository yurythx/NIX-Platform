import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, swrFetcher } from "./swr";

function mockFetchOnce(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    }),
  );
}

// swrFetcher é só apiClient.get desembrulhado pro formato que useSWR
// espera (retorna T direto, não {data, meta}) — os testes aqui cobrem só
// essa costura; o comportamento de baixo nível (erro/envelope/postForm)
// já está coberto em client.test.ts.
describe("swrFetcher", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolve com o campo data do envelope, não o envelope inteiro", async () => {
    mockFetchOnce(200, { data: { job_id: "abc" }, error: null });
    await expect(swrFetcher<{ job_id: string }>("v1/scanning/scans/abc")).resolves.toEqual({
      job_id: "abc",
    });
  });

  it("propaga ApiError sem embrulhar num erro genérico do SWR", async () => {
    mockFetchOnce(404, { data: null, error: { code: "NOT_FOUND", message: "scan not found" } });
    await expect(swrFetcher("v1/scanning/scans/unknown")).rejects.toBeInstanceOf(ApiError);
  });
});
