import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";

import { NewProjectForm } from "./NewProjectForm";

// NewProjectForm chama useRouter().refresh() após criar um projeto — sem
// um <AppRouterContext> real (só existe dentro de uma árvore do Next.js
// de verdade), o hook lança fora desse contexto. Mockado só o suficiente
// pra satisfazer a chamada, sem testar a navegação em si.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

function mockFetchOnce(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderForm() {
  const utils = render(
    <ToastProvider>
      <NewProjectForm />
    </ToastProvider>,
  );
  // jsdom não reconhece um <input type="file"> preenchido via
  // userEvent.upload() como satisfazendo `required` (o files é setado
  // corretamente, mas a checagem interna de validade do jsdom para esse
  // tipo de campo não acompanha) — sem isso, o clique no botão dispara a
  // validação HTML5 nativa e barra o submit ANTES do onSubmit do React
  // rodar, mesmo com um arquivo de verdade selecionado. Em um navegador
  // real isso não acontece; desligar a validação nativa aqui só contorna
  // essa lacuna do jsdom, a validação que o teste quer exercitar é a da
  // própria NewProjectForm (checagem de tamanho em handleSubmit).
  const form = utils.container.querySelector("form");
  if (form) form.noValidate = true;
  return utils;
}

describe("NewProjectForm", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("aba upload: arquivo acima de 50MB é rejeitado ANTES de enviar, sem chamar a API", async () => {
    const fetchMock = mockFetchOnce(201, { data: {}, error: null });
    const user = userEvent.setup();
    renderForm();

    await user.click(screen.getByRole("button", { name: "Upload .zip" }));
    await user.type(screen.getByLabelText("Nome"), "projeto-grande");

    // Arquivo "grande" sem precisar alocar 50MB de verdade no teste — só
    // o campo .size do File é lido pela validação, o conteúdo real nunca
    // importa aqui.
    const bigFile = new File(["x"], "grande.zip", { type: "application/zip" });
    Object.defineProperty(bigFile, "size", { value: 51 * 1024 * 1024 });
    const input = screen.getByLabelText("Arquivo .zip") as HTMLInputElement;
    await user.upload(input, bigFile);

    await user.click(screen.getByRole("button", { name: "Criar projeto" }));

    expect(await screen.findByText("Arquivo .zip muito grande")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("aba upload: arquivo dentro do limite é enviado normalmente", async () => {
    const fetchMock = mockFetchOnce(201, {
      data: { id: "p1", name: "projeto-ok", source_type: "upload", created_at: "2026-08-24T12:00:00Z" },
      error: null,
    });
    const user = userEvent.setup();
    renderForm();

    await user.click(screen.getByRole("button", { name: "Upload .zip" }));
    await user.type(screen.getByLabelText("Nome"), "projeto-ok");

    const smallFile = new File(["conteudo pequeno"], "ok.zip", { type: "application/zip" });
    const input = screen.getByLabelText("Arquivo .zip") as HTMLInputElement;
    await user.upload(input, smallFile);

    await user.click(screen.getByRole("button", { name: "Criar projeto" }));

    expect(await screen.findByText("Projeto criado")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("aba git: envia name/target como JSON, não multipart", async () => {
    const fetchMock = mockFetchOnce(201, {
      data: { id: "p2", name: "projeto-git", source_type: "git", target: "https://github.com/org/repo.git", created_at: "2026-08-24T12:00:00Z" },
      error: null,
    });
    const user = userEvent.setup();
    renderForm();

    await user.type(screen.getByLabelText("Nome"), "projeto-git");
    await user.type(screen.getByLabelText("Alvo"), "https://github.com/org/repo.git");
    await user.click(screen.getByRole("button", { name: "Criar projeto" }));

    expect(await screen.findByText("Projeto criado")).toBeInTheDocument();
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({
      name: "projeto-git",
      target: "https://github.com/org/repo.git",
    });
  });
});
