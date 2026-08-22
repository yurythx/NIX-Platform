import { afterEach, describe, expect, it, vi } from "vitest";

import { apiClient, ApiError } from "./client";

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

describe("apiClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns data on a successful envelope", async () => {
    mockFetchOnce(200, { data: { id: "1" }, error: null });
    const { data } = await apiClient.get<{ id: string }>("v1/integrations");
    expect(data).toEqual({ id: "1" });
  });

  it("passes through meta alongside data", async () => {
    mockFetchOnce(200, { data: [], error: null, meta: { page: 1 } });
    const { meta } = await apiClient.get<unknown[]>("v1/users");
    expect(meta).toEqual({ page: 1 });
  });

  it("throws ApiError when the envelope carries an error", async () => {
    mockFetchOnce(422, { data: null, error: { code: "VALIDATION_ERROR", message: "bad input" } });
    await expect(apiClient.post("v1/integrations/diario-oficial/test")).rejects.toMatchObject({
      code: "VALIDATION_ERROR",
      message: "bad input",
      status: 422,
    });
  });

  it("throws ApiError when the response is ok but carries an error anyway", async () => {
    mockFetchOnce(200, { data: null, error: { code: "WEIRD", message: "should not happen" } });
    await expect(apiClient.get("v1/integrations")).rejects.toBeInstanceOf(ApiError);
  });

  it("throws a generic ApiError when the response body is not JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => {
          throw new Error("not json");
        },
      }),
    );
    await expect(apiClient.get("v1/integrations")).rejects.toBeInstanceOf(ApiError);
  });
});
