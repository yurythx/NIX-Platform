import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { Integration } from "@/types/api";

import { IntegrationCard } from "./IntegrationCard";

const integration: Integration = {
  id: "int-1",
  key: "virustotal",
  name: "VirusTotal",
  type: "secops",
  enabled: true,
  status: "online",
};

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

describe("IntegrationCard", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sem testPath, não mostra o botão de testar conexão", () => {
    render(
      <ToastProvider>
        <IntegrationCard integration={integration} />
      </ToastProvider>,
    );
    expect(screen.queryByRole("button", { name: "Testar conexão" })).not.toBeInTheDocument();
  });

  it("ao testar com sucesso, mostra um toast de job enfileirado e libera o botão de novo", async () => {
    mockFetchOnce(200, { data: { job_id: "12345678-abcd", status: "queued" }, error: null });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <IntegrationCard integration={integration} testPath="v1/integrations/secops/virustotal/test" />
      </ToastProvider>,
    );

    const button = screen.getByRole("button", { name: "Testar conexão" });
    await user.click(button);

    expect(await screen.findByText("Teste enfileirado")).toBeInTheDocument();
    expect(button).not.toBeDisabled();
  });

  it("ao falhar o teste, mostra um toast de erro em vez de travar o botão", async () => {
    mockFetchOnce(503, { data: null, error: { code: "CIRCUIT_OPEN", message: "provedor indisponível" } });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <IntegrationCard integration={integration} testPath="v1/integrations/secops/virustotal/test" />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Testar conexão" }));

    expect(await screen.findByText("Não foi possível iniciar o teste")).toBeInTheDocument();
    expect(screen.getByText("provedor indisponível")).toBeInTheDocument();
  });

  it("mostra a mensagem do último erro quando a integração já reportou um", () => {
    render(
      <ToastProvider>
        <IntegrationCard integration={{ ...integration, last_error: "timeout ao conectar" }} />
      </ToastProvider>,
    );
    expect(screen.getByText("timeout ao conectar")).toBeInTheDocument();
  });
});
