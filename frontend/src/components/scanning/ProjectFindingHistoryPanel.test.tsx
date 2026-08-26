import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { ProjectFindingHistory } from "@/types/api";

import { ProjectFindingHistoryPanel } from "./ProjectFindingHistoryPanel";

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

function makeHistory(overrides: Partial<ProjectFindingHistory> = {}): ProjectFindingHistory {
  return {
    fingerprint: "fp-1",
    scanner: "trivy",
    owasp_category: "A06:2021-Vulnerable and Outdated Components",
    severity: "HIGH",
    description: "CVE-2026-1234 in some-package",
    file: "go.mod",
    line: 12,
    first_seen_at: "2026-08-12T00:00:00Z",
    last_seen_at: "2026-08-20T00:00:00Z",
    scan_count: 3,
    still_present: true,
    tool: { name: "Trivy", url: "" },
    triage_status: "",
    ...overrides,
  };
}

// Refeito sobre useApiQuery (SWR) em vez de useEffect+useState manual —
// estes três testes cobrem os mesmos três estados que o componente
// tratava antes (carregando/erro/dados), que não tinham nenhum teste até
// esta mudança. Cada teste usa um projectId DIFERENTE de propósito: o
// cache do SWR é um Map em nível de módulo, compartilhado entre testes
// do mesmo arquivo — reusar a mesma key faria o segundo/terceiro teste
// receber instantaneamente o valor em cache do primeiro (dentro da
// mesma janela de dedupingInterval) em vez de bater no fetch mockado
// daquele teste.
//
// ToastProvider envolve TODO render aqui (mesmo os três que não tocam em
// triagem) — Fase 14 acrescentou useToast() ao componente, então ele
// quebra sem o provider mesmo num caminho que nunca dispara um toast de
// verdade.
function renderPanel(projectId: string) {
  return render(
    <ToastProvider>
      <ProjectFindingHistoryPanel projectId={projectId} />
    </ToastProvider>,
  );
}

describe("ProjectFindingHistoryPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("mostra o EmptyState quando o histórico vem vazio", async () => {
    mockFetchOnce(200, { data: [], error: null });
    renderPanel("11111111-2222-3333-4444-555555555555");
    expect(await screen.findByText("Nenhum achado no histórico")).toBeInTheDocument();
  });

  it("lista o histórico com status 'Ainda presente'/'Corrigido' por achado", async () => {
    mockFetchOnce(200, {
      data: [makeHistory({ still_present: true }), makeHistory({ fingerprint: "fp-2", still_present: false })],
      error: null,
    });
    renderPanel("22222222-2222-3333-4444-555555555555");
    expect(await screen.findByText("Ainda presente")).toBeInTheDocument();
    expect(screen.getByText("Corrigido")).toBeInTheDocument();
  });

  it("mostra a mensagem de erro em vez de travar num 'carregando' pra sempre", async () => {
    mockFetchOnce(500, { data: null, error: { code: "INTERNAL", message: "falha ao consultar o histórico" } });
    renderPanel("33333333-2222-3333-4444-555555555555");
    expect(await screen.findByText("falha ao consultar o histórico")).toBeInTheDocument();
  });

  it("achado aberto mostra 'Triar…'; achado já triado mostra o motivo e 'Reabrir'", async () => {
    mockFetchOnce(200, {
      data: [
        makeHistory({ fingerprint: "fp-open" }),
        makeHistory({ fingerprint: "fp-triaged", triage_status: "risk_accepted", triage_reason: "mitigado por WAF" }),
      ],
      error: null,
    });
    renderPanel("44444444-2222-3333-4444-555555555555");

    expect(await screen.findByText("Triar…")).toBeInTheDocument();
    expect(screen.getByText("Risco aceito")).toBeInTheDocument();
    expect(screen.getByText("Reabrir")).toBeInTheDocument();
  });

  it("um link de exportação CSV aponta pro endpoint .csv do projeto, via o proxy BFF", async () => {
    mockFetchOnce(200, { data: [makeHistory()], error: null });
    renderPanel("55555555-2222-3333-4444-555555555555");

    const link = await screen.findByText("Exportar CSV →");
    expect(link).toHaveAttribute(
      "href",
      "/api/backend/v1/scanning/projects/55555555-2222-3333-4444-555555555555/findings-history.csv",
    );
  });

  it("triar exige motivo — submeter em branco não fecha o diálogo nem chama a API", async () => {
    const user = userEvent.setup();
    mockFetchOnce(200, { data: [makeHistory({ fingerprint: "fp-open" })], error: null });
    renderPanel("66666666-2222-3333-4444-555555555555");

    await user.click(await screen.findByText("Triar…"));
    expect(screen.getByText("Triar achado")).toBeInTheDocument();

    const fetchSpy = vi.mocked(fetch);
    const callsBefore = fetchSpy.mock.calls.length;
    await user.click(screen.getByRole("button", { name: "Salvar" }));

    expect(screen.getByText("Triar achado")).toBeInTheDocument(); // diálogo continua aberto
    expect(fetchSpy.mock.calls.length).toBe(callsBefore); // nenhuma requisição nova disparada
  });

  it("triar com motivo preenchido chama PUT .../triage e revalida a lista", async () => {
    const user = userEvent.setup();
    mockFetchOnce(200, { data: [makeHistory({ fingerprint: "fp-open" })], error: null });
    renderPanel("77777777-2222-3333-4444-555555555555");

    await user.click(await screen.findByText("Triar…"));
    await user.type(screen.getByPlaceholderText(/Por que este achado/), "aceito o risco por ora");
    await user.click(screen.getByRole("button", { name: "Salvar" }));

    await waitFor(() => {
      const fetchSpy = vi.mocked(fetch);
      const putCall = fetchSpy.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "PUT");
      expect(putCall).toBeDefined();
      expect(putCall?.[0]).toBe(
        "/api/backend/v1/scanning/projects/77777777-2222-3333-4444-555555555555/findings/fp-open/triage",
      );
    });
    await waitFor(() => expect(screen.queryByText("Triar achado")).not.toBeInTheDocument());
  });

  it("reabrir chama DELETE .../triage", async () => {
    const user = userEvent.setup();
    mockFetchOnce(200, {
      data: [makeHistory({ fingerprint: "fp-triaged", triage_status: "wont_fix", triage_reason: "aceito" })],
      error: null,
    });
    renderPanel("88888888-2222-3333-4444-555555555555");

    await user.click(await screen.findByText("Reabrir"));

    await waitFor(() => {
      const fetchSpy = vi.mocked(fetch);
      const deleteCall = fetchSpy.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "DELETE");
      expect(deleteCall).toBeDefined();
      expect(deleteCall?.[0]).toBe(
        "/api/backend/v1/scanning/projects/88888888-2222-3333-4444-555555555555/findings/fp-triaged/triage",
      );
    });
  });
});
