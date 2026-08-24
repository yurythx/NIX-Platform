import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";

import { TriggerScanForm } from "./TriggerScanForm";

function mockFetchOnce(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("TriggerScanForm", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("começa com trivy pré-selecionado e o alvo vazio", () => {
    render(
      <ToastProvider>
        <TriggerScanForm />
      </ToastProvider>,
    );
    expect(screen.getByRole("switch", { name: "Trivy" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("switch", { name: "OWASP ZAP" })).toHaveAttribute("aria-checked", "false");
    expect(screen.getByLabelText("Alvo")).toHaveValue("");
  });

  it("ao disparar com sucesso, envia os scanners selecionados e mostra um toast com o job_id", async () => {
    const fetchMock = mockFetchOnce(202, {
      data: { job_id: "12345678-abcd", status: "queued" },
      error: null,
    });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <TriggerScanForm />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("switch", { name: "Semgrep" }));
    await user.type(screen.getByLabelText("Alvo"), "https://github.com/org/repo.git");
    await user.click(screen.getByRole("button", { name: "Disparar scan" }));

    expect(await screen.findByText("Scan disparado")).toBeInTheDocument();
    expect(screen.getByText(/Job 12345678/)).toBeInTheDocument();

    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body as string);
    expect(body.scanners.sort()).toEqual(["semgrep", "trivy"]);
    expect(body.target).toBe("https://github.com/org/repo.git");
  });

  it("ao falhar, mostra um toast de erro em vez de travar o formulário", async () => {
    mockFetchOnce(400, {
      data: null,
      error: { code: "VALIDATION_ERROR", message: "target is required" },
    });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <TriggerScanForm />
      </ToastProvider>,
    );

    await user.type(screen.getByLabelText("Alvo"), "https://github.com/org/repo.git");
    await user.click(screen.getByRole("button", { name: "Disparar scan" }));

    expect(await screen.findByText("Não foi possível disparar o scan")).toBeInTheDocument();
    expect(screen.getByText("target is required")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disparar scan" })).not.toBeDisabled();
  });

  it("sem nenhum scanner selecionado, o botão de disparar fica desabilitado", async () => {
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <TriggerScanForm />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("switch", { name: "Trivy" })); // desmarca o único pré-selecionado
    expect(screen.getByRole("button", { name: "Disparar scan" })).toBeDisabled();
  });
});
