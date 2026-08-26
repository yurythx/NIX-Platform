import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";

import { TriageControls } from "./TriageControls";

function mockFetchOnce(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, json: async () => body }),
  );
}

// getBadgeText: o <dialog> de triagem sempre está no DOM, mesmo fechado
// (só vira display:none via CSS, não filtrado por getByText) — o
// <select> dentro dele tem um <option> pro mesmo texto que o selo de
// status já mostra (ex. "Não vou corrigir"), então um getByText plano
// ficaria ambíguo. Ignora qualquer match dentro de um <option>.
function getBadgeText(text: string) {
  return screen.getByText((content, element) => content === text && element?.tagName.toLowerCase() !== "option");
}

function renderControls(props: Partial<Parameters<typeof TriageControls>[0]> = {}) {
  const onChanged = vi.fn();
  const utils = render(
    <ToastProvider>
      <TriageControls
        projectId="11111111-2222-3333-4444-555555555555"
        fingerprint="fp-1"
        status=""
        onChanged={onChanged}
        {...props}
      />
    </ToastProvider>,
  );
  return { onChanged, ...utils };
}

// TriageControls: extraído de ProjectFindingHistoryPanel (revisão de
// exibição de resultados) — estes testes cobrem o componente sozinho,
// sem depender de nenhum dos dois lugares que o usam (a tabela do
// projeto e o painel de detalhe mestre-detalhe), que já têm sua própria
// cobertura de integração.
describe("TriageControls", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("achado aberto (status vazio) mostra 'Triar…'", () => {
    renderControls({ status: "" });
    expect(screen.getByText("Triar…")).toBeInTheDocument();
  });

  it("achado triado mostra o selo com o rótulo certo e 'Reabrir'", () => {
    renderControls({ status: "wont_fix", reason: "aceito por ora" });
    expect(getBadgeText("Não vou corrigir")).toBeInTheDocument();
    expect(screen.getByText("Reabrir")).toBeInTheDocument();
    expect(screen.queryByText("Triar…")).not.toBeInTheDocument();
  });

  it("triagem vencida mostra 'Vencida: <status>' e 'Renovar…'", () => {
    renderControls({ status: "risk_accepted", reason: "vencido", expired: true });
    expect(screen.getByText("Vencida: Risco aceito")).toBeInTheDocument();
    expect(screen.getByText("Renovar…")).toBeInTheDocument();
  });

  it("triar sem motivo mostra um toast de erro e não chama a API", async () => {
    const user = userEvent.setup();
    const { onChanged } = renderControls();

    await user.click(screen.getByText("Triar…"));
    await user.click(screen.getByRole("button", { name: "Salvar" }));

    expect(await screen.findByText("Motivo é obrigatório")).toBeInTheDocument();
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("triar com motivo chama PUT .../triage e onChanged", async () => {
    const user = userEvent.setup();
    mockFetchOnce(200, { data: { status: "risk_accepted" }, error: null });
    const { onChanged } = renderControls();

    await user.click(screen.getByText("Triar…"));
    await user.type(screen.getByPlaceholderText(/Por que este achado/), "risco aceito");
    await user.click(screen.getByRole("button", { name: "Salvar" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    const fetchSpy = vi.mocked(fetch);
    const putCall = fetchSpy.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "PUT");
    expect(putCall?.[0]).toBe(
      "/api/backend/v1/scanning/projects/11111111-2222-3333-4444-555555555555/findings/fp-1/triage",
    );
  });

  it("reabrir chama DELETE .../triage e onChanged", async () => {
    const user = userEvent.setup();
    mockFetchOnce(200, { data: { status: "" }, error: null });
    const { onChanged } = renderControls({ status: "false_positive", reason: "não é real" });

    await user.click(screen.getByText("Reabrir"));

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    const fetchSpy = vi.mocked(fetch);
    const deleteCall = fetchSpy.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "DELETE");
    expect(deleteCall?.[0]).toBe(
      "/api/backend/v1/scanning/projects/11111111-2222-3333-4444-555555555555/findings/fp-1/triage",
    );
  });

  it("uma falha ao triar mostra um toast de erro e mantém o diálogo aberto", async () => {
    const user = userEvent.setup();
    mockFetchOnce(500, { data: null, error: { code: "INTERNAL", message: "falha ao triar" } });
    renderControls();

    await user.click(screen.getByText("Triar…"));
    await user.type(screen.getByPlaceholderText(/Por que este achado/), "motivo qualquer");
    await user.click(screen.getByRole("button", { name: "Salvar" }));

    expect(await screen.findByText("falha ao triar")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Salvar" })).toBeInTheDocument();
  });

  it("'Renovar…' pré-preenche o diálogo com a decisão anterior", async () => {
    const user = userEvent.setup();
    renderControls({ status: "wont_fix", reason: "motivo original", expired: true });

    await user.click(screen.getByText("Renovar…"));

    expect(screen.getByDisplayValue("motivo original")).toBeInTheDocument();
    expect(screen.getByRole("combobox")).toHaveValue("wont_fix");
  });
});
