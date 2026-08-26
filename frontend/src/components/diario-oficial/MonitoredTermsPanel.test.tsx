import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SWRConfig } from "swr";

import { ToastProvider } from "@/components/notifications/ToastProvider";

import { MonitoredTermsPanel } from "./MonitoredTermsPanel";

function mockFetchOnce(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, json: async () => body });
  vi.stubGlobal("fetch", fn);
  return fn;
}

function mockFetchSequence(...responses: { status: number; body: unknown }[]) {
  const fetchMock = vi.fn();
  for (const { status, body } of responses) {
    fetchMock.mockResolvedValueOnce({ ok: status >= 200 && status < 300, status, json: async () => body });
  }
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

// renderPanel: SWRConfig com provider isolado (um Map novo por render) —
// o painel busca sempre a MESMA key ("v1/diario-oficial/monitored-terms"),
// mesmo raciocínio de ScannerHealthPanel.test.tsx: sem isolar o cache,
// um teste anterior vazaria estado SWR pro próximo.
function renderPanel() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <ToastProvider>
        <MonitoredTermsPanel />
      </ToastProvider>
    </SWRConfig>,
  );
}

describe("MonitoredTermsPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sem termo nenhum, mostra o estado vazio", async () => {
    mockFetchOnce(200, { data: [], error: null });
    renderPanel();

    expect(await screen.findByText("Nenhum termo monitorado ainda")).toBeInTheDocument();
  });

  it("lista um termo cadastrado com o selo Ativo e a data de última sincronização", async () => {
    mockFetchOnce(200, {
      data: [
        {
          id: "t1",
          label: "Dr. Fulano — OAB/MG 419",
          oab_number: "419",
          oab_uf: "MG",
          active: true,
          last_synced_at: "2026-08-26T12:00:00Z",
          created_at: "2026-08-01T00:00:00Z",
        },
      ],
      error: null,
    });
    renderPanel();

    expect(await screen.findByText("Dr. Fulano — OAB/MG 419")).toBeInTheDocument();
    expect(screen.getByText("Ativo")).toBeInTheDocument();
    expect(screen.getByText(/OAB 419\/MG/)).toBeInTheDocument();
  });

  it("cadastra um termo por OAB e limpa o formulário", async () => {
    const user = userEvent.setup();
    const fetchMock = mockFetchSequence(
      { status: 200, body: { data: [], error: null } }, // carga inicial (GET)
      { status: 201, body: { data: { id: "t2", label: "novo termo", active: true, created_at: "2026-08-26T00:00:00Z" }, error: null } }, // POST
      { status: 200, body: { data: [{ id: "t2", label: "novo termo", active: true, created_at: "2026-08-26T00:00:00Z" }], error: null } }, // revalidação
    );
    renderPanel();
    await screen.findByText("Nenhum termo monitorado ainda");

    await user.type(screen.getByLabelText("Nome"), "novo termo");
    await user.type(screen.getByLabelText("Número da OAB"), "419");
    await user.type(screen.getByLabelText("UF"), "MG");
    await user.click(screen.getByRole("button", { name: "Monitorar" }));

    expect(await screen.findByText("Termo cadastrado")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2));

    const [, postInit] = fetchMock.mock.calls[1] ?? [];
    const sentBody = JSON.parse((postInit as RequestInit).body as string);
    expect(sentBody).toMatchObject({ label: "novo termo", oab_number: "419", oab_uf: "MG" });
  });

  it("remover um termo chama DELETE com o id certo", async () => {
    const user = userEvent.setup();
    const fetchMock = mockFetchSequence(
      { status: 200, body: { data: [{ id: "t3", label: "termo a remover", active: true, created_at: "2026-08-26T00:00:00Z" }], error: null } },
      { status: 200, body: { data: {}, error: null } }, // DELETE
      { status: 200, body: { data: [], error: null } }, // revalidação
    );
    renderPanel();
    await screen.findByText("termo a remover");

    await user.click(screen.getByRole("button", { name: "Remover" }));

    expect(await screen.findByText("Termo removido")).toBeInTheDocument();
    const [deleteUrl, deleteInit] = fetchMock.mock.calls[1] ?? [];
    expect(deleteUrl).toContain("diario-oficial/monitored-terms/t3");
    expect((deleteInit as RequestInit).method).toBe("DELETE");
  });
});
