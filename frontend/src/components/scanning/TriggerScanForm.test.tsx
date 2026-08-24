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

// mockFetchSequence: uma resposta por chamada, na ordem — usado nos
// testes que disparam um scan (POST) e então acompanham o resultado via
// polling (GET .../scans/{id}), que mockFetchOnce não consegue expressar
// (ele devolve sempre o MESMO corpo pra toda chamada).
function mockFetchSequence(...responses: { status: number; body: unknown }[]) {
  const fetchMock = vi.fn();
  for (const { status, body } of responses) {
    fetchMock.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    });
  }
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
    const fetchMock = mockFetchSequence(
      { status: 202, body: { data: { job_id: "12345678-abcd", status: "queued" }, error: null } },
      {
        status: 200,
        body: {
          data: {
            job_id: "12345678-abcd",
            status: "completed",
            target: "https://github.com/org/repo.git",
            requested_scanners: ["trivy", "semgrep"],
            succeeded_scanners: ["trivy", "semgrep"],
            failed_scanners: [],
            attempts: 1,
            created_at: "2026-08-24T12:00:00Z",
          },
          error: null,
        },
      },
    );
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

  it("depois de concluído, mostra qual scanner falhou, o tipo do erro e como corrigir", async () => {
    mockFetchSequence(
      { status: 202, body: { data: { job_id: "abcdef12-3456", status: "queued" }, error: null } },
      {
        status: 200,
        body: {
          data: {
            job_id: "abcdef12-3456",
            status: "completed",
            target: "https://github.com/org/repo.git",
            requested_scanners: ["trivy", "zap"],
            succeeded_scanners: ["trivy"],
            failed_scanners: [
              {
                scanner: "zap",
                code: "VALIDATION_ERROR",
                message:
                  "scanning: zap: no hosts are allowlisted (SCANNING_ZAP_ALLOWED_HOSTS is empty) — refusing to scan any target",
                hint: "O ZAP só ataca hosts explicitamente autorizados. Adicione o host à variável de ambiente SCANNING_ZAP_ALLOWED_HOSTS do backend-worker e dispare o scan de novo.",
              },
            ],
            attempts: 1,
            created_at: "2026-08-24T12:00:00Z",
          },
          error: null,
        },
      },
    );
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <TriggerScanForm />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("switch", { name: "OWASP ZAP" }));
    await user.type(screen.getByLabelText("Alvo"), "https://github.com/org/repo.git");
    await user.click(screen.getByRole("button", { name: "Disparar scan" }));

    // Quem achou o erro (scanner), que tipo foi (code) e a mensagem real.
    expect(await screen.findByText("zap")).toBeInTheDocument();
    expect(screen.getByText("VALIDATION_ERROR")).toBeInTheDocument();
    expect(screen.getByText(/no hosts are allowlisted/)).toBeInTheDocument();
    // Como corrigir. (SCANNING_ZAP_ALLOWED_HOSTS sozinho ambiguaria com o
    // texto estático do CardDescription do próprio formulário, que já
    // menciona a mesma variável — o trecho abaixo só existe no hint.)
    expect(screen.getByText(/Adicione o host à variável de ambiente/)).toBeInTheDocument();
    // trivy teve sucesso — aparece separado, não junto da falha.
    expect(screen.getByText("trivy")).toBeInTheDocument();
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
