import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { FeatureFlag } from "@/types/api";

import { FeatureFlagsPanel } from "./FeatureFlagsPanel";

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

function makeFlag(overrides: Partial<FeatureFlag> = {}): FeatureFlag {
  return {
    key: "scanning_noise_filter_enabled",
    enabled: false,
    description: "Filtro de ruído",
    ...overrides,
  };
}

describe("FeatureFlagsPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("mostra uma mensagem quando não há nenhuma flag registrada", () => {
    render(
      <ToastProvider>
        <FeatureFlagsPanel initialFlags={[]} />
      </ToastProvider>,
    );
    expect(screen.getByText("Nenhuma feature flag registrada.")).toBeInTheDocument();
  });

  it("renderiza o estado inicial de cada flag vindo do servidor (nenhum fetch próprio)", () => {
    mockFetchOnce(200, { data: null, error: null }); // se chamado, o teste abaixo denuncia
    render(
      <ToastProvider>
        <FeatureFlagsPanel initialFlags={[makeFlag({ enabled: true })]} />
      </ToastProvider>,
    );
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "true");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("alternar liga otimista (antes da resposta) e persiste via PATCH", async () => {
    mockFetchOnce(200, {
      data: { key: "scanning_noise_filter_enabled", enabled: true },
      error: null,
    });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <FeatureFlagsPanel initialFlags={[makeFlag({ enabled: false })]} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("switch"));
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "true");

    const [path, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] ?? [];
    expect(path).toBe("/api/backend/v1/admin/feature-flags/scanning_noise_filter_enabled");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ enabled: true });
  });

  it("se o PATCH falhar, desfaz a mudança otimista e mostra um toast de erro", async () => {
    mockFetchOnce(422, {
      data: null,
      error: { code: "VALIDATION_ERROR", message: "flag desconhecida" },
    });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <FeatureFlagsPanel initialFlags={[makeFlag({ enabled: false })]} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("switch"));
    expect(
      await screen.findByText('Não foi possível alterar "scanning_noise_filter_enabled"'),
    ).toBeInTheDocument();
    expect(screen.getByText("flag desconhecida")).toBeInTheDocument();
    // Desfeito: volta pro estado original (desligado), não fica travado
    // "ligado" mentindo sobre o que o backend de fato tem gravado.
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");
  });
});
