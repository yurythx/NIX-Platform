import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SWRConfig } from "swr";

import { ScannerHealthPanel } from "./ScannerHealthPanel";

function mockFetchOnce(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, json: async () => body });
  vi.stubGlobal("fetch", fn);
  return fn;
}

// renderPanel: SWRConfig com provider isolado (um Map novo por render)
// — o painel sempre busca a MESMA key ("v1/scanning/scanners/health",
// sem parâmetro nenhum pra variar entre testes, ao contrário de
// ProjectFindingHistoryPanel/FindingsTable, que usam um projectId
// diferente por teste), então sem isolar o cache um teste anterior
// (inclusive um que nunca resolve, de propósito) vazaria estado SWR pro
// próximo.
function renderPanel() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <ScannerHealthPanel />
    </SWRConfig>,
  );
}

describe("ScannerHealthPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("enquanto carrega, mostra 'Verificando…'", () => {
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise(() => {})));
    renderPanel();
    expect(screen.getByText("Verificando…")).toBeInTheDocument();
  });

  it("lista cada ferramenta com o selo certo (No ar / Fora do ar)", async () => {
    mockFetchOnce(200, {
      data: [
        { scanner: "trivy", healthy: true, checked_at: "2026-08-26T00:00:00Z" },
        { scanner: "zap", healthy: false, message: "unreachable", checked_at: "2026-08-26T00:00:00Z" },
      ],
      error: null,
    });
    renderPanel();

    expect(await screen.findByText("Trivy")).toBeInTheDocument();
    expect(screen.getByText("No ar")).toBeInTheDocument();
    expect(screen.getByText("OWASP ZAP")).toBeInTheDocument();
    expect(screen.getByText("Fora do ar")).toBeInTheDocument();
  });

  it("uma falha na própria consulta mostra a mensagem de erro, não trava em 'Verificando…'", async () => {
    mockFetchOnce(500, { data: null, error: { code: "INTERNAL", message: "falha ao verificar" } });
    renderPanel();

    expect(await screen.findByText("falha ao verificar")).toBeInTheDocument();
  });

  it("'Verificar de novo' revalida a consulta", async () => {
    const user = userEvent.setup();
    const fetchFn = mockFetchOnce(200, {
      data: [{ scanner: "trivy", healthy: true, checked_at: "2026-08-26T00:00:00Z" }],
      error: null,
    });
    renderPanel();
    await screen.findByText("Trivy");

    const callsBefore = fetchFn.mock.calls.length;
    await user.click(screen.getByText("Verificar de novo"));

    await waitFor(() => expect(fetchFn.mock.calls.length).toBeGreaterThan(callsBefore));
  });
});
