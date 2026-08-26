import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SWRConfig } from "swr";

import { SourceHealthPanel } from "./SourceHealthPanel";

function mockFetchOnce(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, json: async () => body });
  vi.stubGlobal("fetch", fn);
  return fn;
}

// renderPanel: SWRConfig com provider isolado — mesma key fixa
// ("v1/diario-oficial/health") em todo teste, mesmo raciocínio de
// ScannerHealthPanel.test.tsx.
function renderPanel() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <SourceHealthPanel />
    </SWRConfig>,
  );
}

describe("SourceHealthPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("enquanto carrega, mostra 'Verificando…'", () => {
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise(() => {})));
    renderPanel();
    expect(screen.getByText("Verificando…")).toBeInTheDocument();
  });

  it("fonte saudável mostra o selo 'No ar'", async () => {
    mockFetchOnce(200, {
      data: { source: "djen", healthy: true, checked_at: "2026-08-26T00:00:00Z" },
      error: null,
    });
    renderPanel();

    expect(await screen.findByText(/DJEN/)).toBeInTheDocument();
    expect(screen.getByText("No ar")).toBeInTheDocument();
  });

  it("fonte fora do ar mostra o selo 'Fora do ar'", async () => {
    mockFetchOnce(200, {
      data: { source: "djen", healthy: false, message: "connection refused", checked_at: "2026-08-26T00:00:00Z" },
      error: null,
    });
    renderPanel();

    expect(await screen.findByText("Fora do ar")).toBeInTheDocument();
  });

  it("'Verificar de novo' revalida a consulta", async () => {
    const user = userEvent.setup();
    const fetchFn = mockFetchOnce(200, {
      data: { source: "djen", healthy: true, checked_at: "2026-08-26T00:00:00Z" },
      error: null,
    });
    renderPanel();
    await screen.findByText("No ar");

    const callsBefore = fetchFn.mock.calls.length;
    await user.click(screen.getByText("Verificar de novo"));

    await waitFor(() => expect(fetchFn.mock.calls.length).toBeGreaterThan(callsBefore));
  });
});
