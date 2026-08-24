import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { ScanFinding } from "@/types/api";

import { FindingsTable } from "./FindingsTable";

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: "finding-1",
    scan_id: "scan-1",
    scanner: "trivy",
    target: "https://github.com/org/repo.git",
    finding_id: "CVE-2026-0001",
    owasp_category: "A06:2021-Vulnerable and Outdated Components",
    severity: "HIGH",
    description: "Descrição completa e bem detalhada do achado, sem truncar.",
    file: "go.sum",
    line: 12,
    fingerprint: "abc123fingerprint",
    created_at: "2026-08-24T12:00:00Z",
    tool: { name: "Trivy", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" },
    ...overrides,
  };
}

// renderTable: FindingsTable usa useToast() desde a Fase 13 ("Copiar
// prompt pra IA") — todo teste precisa de um ToastProvider ancestor,
// senão o hook lança ("useToast must be used within a ToastProvider").
function renderTable(props: Parameters<typeof FindingsTable>[0]) {
  return render(
    <ToastProvider>
      <FindingsTable {...props} />
    </ToastProvider>,
  );
}

describe("FindingsTable", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lista vazia mostra o EmptyState em vez de uma tabela sem linhas", () => {
    renderTable({ findings: [] });
    expect(screen.getByText("Nenhum achado ainda")).toBeInTheDocument();
  });

  it("clicar numa linha abre o Dialog com o achado por extenso, inclusive como corrigir", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    await user.click(screen.getByRole("button", { name: /Ver detalhes do achado CVE-2026-0001/ }));

    // A linha continua no DOM por trás do <dialog> nativo (ele só
    // sobrepõe visualmente, não desmonta o resto da página) — a mesma
    // descrição aparece nos dois lugares (linha truncada + Dialog por
    // extenso), então as asserções abaixo ficam escopadas a DENTRO do
    // dialog, não à página inteira.
    const dialog = screen.getByRole("dialog");
    expect(dialog).toBeInTheDocument();
    expect(
      within(dialog).getByText("Descrição completa e bem detalhada do achado, sem truncar."),
    ).toBeInTheDocument();
    // "Como corrigir" vem de remediationFor — não testa o texto exato
    // (isso é responsabilidade de remediation.test.ts), só que ALGUM
    // texto de orientação aparece.
    expect(within(dialog).getByText("Como corrigir")).toBeInTheDocument();
    // Dados da ferramenta — pedido do usuário.
    expect(within(dialog).getByText("Trivy")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Abrir na ferramenta →" })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    );
  });

  it("sem tool.url (a ferramenta não permite montar um link), não mostra o link, só o nome", async () => {
    const finding = makeFinding({ tool: { name: "OWASP ZAP" } });
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).getByText("OWASP ZAP")).toBeInTheDocument();
    expect(within(dialog).queryByRole("link", { name: "Abrir na ferramenta →" })).not.toBeInTheDocument();
  });

  it("teclar Enter numa linha focada também abre o detalhe (acessibilidade de teclado)", async () => {
    const finding = makeFinding({ finding_id: "CVE-2026-9999" });
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    screen.getByRole("button", { name: /Ver detalhes do achado CVE-2026-9999/ }).focus();
    await user.keyboard("{Enter}");

    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("showScanLink controla se o link de volta pro scan aparece no Dialog", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    const { rerender } = render(
      <ToastProvider>
        <FindingsTable findings={[finding]} showScanLink={false} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    expect(screen.queryByText("Ver o scan completo →")).not.toBeInTheDocument();

    rerender(
      <ToastProvider>
        <FindingsTable findings={[finding]} showScanLink />
      </ToastProvider>,
    );
    expect(screen.getByText("Ver o scan completo →")).toBeInTheDocument();
  });

  it("achado com snippet (Fase 12) mostra o trecho e destaca a linha do achado", async () => {
    const finding = makeFinding({
      line: 12,
      snippet: "10: func handler() {\n11:   data := input\n12:   exec(data)\n13: }\n14: ",
    });
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).getByText("Trecho do código")).toBeInTheDocument();
    expect(within(dialog).getByText("exec(data)")).toBeInTheDocument();
  });

  it("achado sem snippet (achado antigo, ou ferramenta sem linha específica) nunca mostra a seção", async () => {
    const finding = makeFinding({ snippet: undefined });
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).queryByText("Trecho do código")).not.toBeInTheDocument();
  });

  it("Copiar prompt pra IA (Fase 13) copia o markdown do achado pra área de transferência", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    // Object.defineProperty DEPOIS de userEvent.setup()/render() — não
    // antes: userEvent.setup() mexe no próprio navigator.clipboard
    // internamente (suporte a user.copy()/paste()), sobrescrevendo
    // qualquer stub definido antes dela. vi.stubGlobal("navigator",
    // {...navigator}) também não serve aqui: navigator é um host object
    // do jsdom, a maioria das propriedades vive no protótipo (não são
    // "own enumerable") — um spread copiaria quase nada de útil.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    await user.click(screen.getByRole("button", { name: "Copiar prompt pra IA" }));

    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied).toContain("CVE-2026-0001");
    expect(copied).toContain("Trivy");
    expect(await screen.findByText("Prompt copiado")).toBeInTheDocument();
  });

  it("Copiar prompt pra IA: falha na cópia mostra um toast de erro em vez de travar", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    const writeText = vi.fn().mockRejectedValue(new Error("clipboard indisponível"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    await user.click(screen.getByRole("button", { name: "Copiar prompt pra IA" }));

    expect(await screen.findByText("Não foi possível copiar")).toBeInTheDocument();
  });
});
