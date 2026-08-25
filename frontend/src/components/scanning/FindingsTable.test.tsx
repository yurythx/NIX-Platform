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

  it("filtro de severidade: clicar num selo esconde os achados de outra severidade", async () => {
    const critical = makeFinding({ id: "f-critical", finding_id: "CRIT-1", severity: "CRITICAL" });
    const low = makeFinding({ id: "f-low", finding_id: "LOW-1", severity: "LOW" });
    const user = userEvent.setup();
    renderTable({ findings: [critical, low] });

    expect(screen.getByRole("button", { name: /Ver detalhes do achado CRIT-1/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ver detalhes do achado LOW-1/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Filtrar por severidade CRITICAL (1)" }));

    expect(screen.getByRole("button", { name: /Ver detalhes do achado CRIT-1/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Ver detalhes do achado LOW-1/ })).not.toBeInTheDocument();
  });

  it("filtro de ferramenta: clicar num selo de scanner isola os achados dele", async () => {
    const fromTrivy = makeFinding({ id: "f-trivy", finding_id: "TRIVY-1", scanner: "trivy" });
    const fromGitleaks = makeFinding({ id: "f-gitleaks", finding_id: "LEAK-1", scanner: "gitleaks" });
    const user = userEvent.setup();
    renderTable({ findings: [fromTrivy, fromGitleaks] });

    await user.click(screen.getByRole("button", { name: "Gitleaks" }));

    expect(screen.queryByRole("button", { name: /Ver detalhes do achado TRIVY-1/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ver detalhes do achado LEAK-1/ })).toBeInTheDocument();
  });

  it("busca livre filtra por texto do finding_id/descrição/arquivo", async () => {
    const match = makeFinding({ id: "f-match", finding_id: "CVE-MATCH", file: "src/auth.ts" });
    const other = makeFinding({ id: "f-other", finding_id: "CVE-OTHER", file: "go.sum" });
    const user = userEvent.setup();
    renderTable({ findings: [match, other] });

    await user.type(screen.getByLabelText("Buscar achados"), "auth.ts");

    expect(screen.getByRole("button", { name: /Ver detalhes do achado CVE-MATCH/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Ver detalhes do achado CVE-OTHER/ })).not.toBeInTheDocument();
  });

  it("filtro sem nenhum resultado mostra o EmptyState de filtro, não o de lista vazia", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    renderTable({ findings: [finding] });

    await user.type(screen.getByLabelText("Buscar achados"), "termo que não existe em nada");

    expect(screen.getByText("Nenhum achado corresponde aos filtros")).toBeInTheDocument();
    expect(screen.queryByText("Nenhum achado ainda")).not.toBeInTheDocument();
  });

  it("Agrupar por alvo (só na visão agregada) reorganiza a lista por target", async () => {
    const findingA = makeFinding({ id: "f-a", finding_id: "A-1", target: "https://github.com/org/api.git" });
    const findingB = makeFinding({ id: "f-b", finding_id: "B-1", target: "https://github.com/org/web.git" });
    const user = userEvent.setup();
    renderTable({ findings: [findingA, findingB], showScanLink: true });

    await user.click(screen.getByLabelText("Agrupar por alvo"));

    expect(screen.getByText("https://github.com/org/api.git")).toBeInTheDocument();
    expect(screen.getByText("https://github.com/org/web.git")).toBeInTheDocument();
    // Achados dos dois alvos continuam clicáveis normalmente, só que
    // agora dentro de suas próprias seções.
    expect(screen.getByRole("button", { name: /Ver detalhes do achado A-1/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ver detalhes do achado B-1/ })).toBeInTheDocument();
  });

  it("na página de um scan específico (showScanLink=false), não oferece 'Agrupar por alvo'", () => {
    renderTable({ findings: [makeFinding()], showScanLink: false });
    expect(screen.queryByLabelText("Agrupar por alvo")).not.toBeInTheDocument();
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
