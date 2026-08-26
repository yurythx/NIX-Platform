import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { ScanFinding } from "@/types/api";

import { FindingsTable } from "./FindingsTable";

// detailPanel: o painel de detalhe (<section aria-label="Detalhe do
// achado">) — precisa escopar a ele sempre que o texto checado também
// pode aparecer na linha da lista (a descrição truncada da linha usa a
// MESMA string, só cortada visualmente por CSS, não por texto
// diferente), senão getByText/findByText falha por achar mais de um
// elemento.
function detailPanel() {
  return screen.getByRole("region", { name: "Detalhe do achado" });
}

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

// renderTable: FindingsTable usa useToast() — todo teste precisa de um
// ToastProvider ancestor, senão o hook lança ("useToast must be used
// within a ToastProvider").
function renderTable(props: Parameters<typeof FindingsTable>[0]) {
  return render(
    <ToastProvider>
      <FindingsTable {...props} />
    </ToastProvider>,
  );
}

// Revisão de exibição de resultados: FindingsTable deixou de ser uma
// tabela + Dialog modal e virou uma view MESTRE-DETALHE (lista + painel
// de detalhe lado a lado) — o painel de detalhe do PRIMEIRO achado já
// aparece sem precisar clicar em nada (seleção automática, mesmo
// princípio de qualquer app mestre-detalhe: nunca fica vazio à toa).
// Por isso a maioria dos testes abaixo não precisa mais de um
// user.click prévio pra "abrir o detalhe" — só quando o teste
// especificamente quer trocar de achado selecionado.
describe("FindingsTable", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    window.history.pushState({}, "", "/");
  });

  it("lista vazia mostra o EmptyState em vez de uma lista sem itens", () => {
    renderTable({ findings: [] });
    expect(screen.getByText("Nenhum achado ainda")).toBeInTheDocument();
  });

  it("com um achado só, o painel de detalhe já mostra ele sem precisar clicar (seleção automática)", async () => {
    renderTable({ findings: [makeFinding()] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(
      within(detailPanel()).getByText("Descrição completa e bem detalhada do achado, sem truncar."),
    ).toBeInTheDocument();
    expect(within(detailPanel()).getByText("Como corrigir")).toBeInTheDocument();
    expect(within(detailPanel()).getByText("Trivy")).toBeInTheDocument();
    expect(within(detailPanel()).getByRole("link", { name: "Abrir na ferramenta →" })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    );
  });

  it("clicar num outro achado da lista troca o que aparece no painel de detalhe", async () => {
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST", description: "primeiro achado" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND", description: "segundo achado" });
    const user = userEvent.setup();
    renderTable({ findings: [first, second] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(within(detailPanel()).getByText("primeiro achado")).toBeInTheDocument();

    await user.click(screen.getByRole("option", { name: /Ver detalhes do achado CVE-SECOND/ }));

    expect(within(detailPanel()).getByText("segundo achado")).toBeInTheDocument();
    expect(within(detailPanel()).queryByText("primeiro achado")).not.toBeInTheDocument();
  });

  it("sem tool.url (a ferramenta não permite montar um link), não mostra o link, só o nome", async () => {
    renderTable({ findings: [makeFinding({ tool: { name: "OWASP ZAP" } })] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(within(detailPanel()).getByText("OWASP ZAP")).toBeInTheDocument();
    expect(within(detailPanel()).queryByRole("link", { name: "Abrir na ferramenta →" })).not.toBeInTheDocument();
  });

  it("teclar Enter numa linha focada seleciona ela (acessibilidade de teclado)", async () => {
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST", description: "primeiro achado" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND", description: "segundo achado" });
    const user = userEvent.setup();
    renderTable({ findings: [first, second] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    screen.getByRole("option", { name: /Ver detalhes do achado CVE-SECOND/ }).focus();
    await user.keyboard("{Enter}");

    expect(within(detailPanel()).getByText("segundo achado")).toBeInTheDocument();
  });

  it("seta pra baixo/cima na lista navega pro achado seguinte/anterior", async () => {
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST", description: "primeiro achado" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND", description: "segundo achado" });
    const user = userEvent.setup();
    renderTable({ findings: [first, second] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    // Foca a linha selecionada (não o <div role="listbox"> em si, que
    // não é focável sozinho) — a seta de teclado borbulha do elemento
    // com foco até o onKeyDown da listbox, mesmo comportamento real de
    // um usuário tabulando até uma linha e usando as setas a partir
    // dela.
    screen.getByRole("option", { name: /Ver detalhes do achado CVE-FIRST/ }).focus();
    await user.keyboard("{ArrowDown}");
    expect(within(detailPanel()).getByText("segundo achado")).toBeInTheDocument();

    await user.keyboard("{ArrowUp}");
    expect(within(detailPanel()).getByText("primeiro achado")).toBeInTheDocument();
  });

  it("botões Anterior/Próximo do painel de detalhe navegam entre achados e desabilitam nas pontas", async () => {
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST", description: "primeiro achado" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND", description: "segundo achado" });
    const user = userEvent.setup();
    renderTable({ findings: [first, second] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(screen.getByRole("button", { name: "Achado anterior" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Próximo achado" }));

    expect(within(detailPanel()).getByText("segundo achado")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Próximo achado" })).toBeDisabled();
  });

  it("showScanLink controla se o link de volta pro scan aparece no painel de detalhe", async () => {
    const finding = makeFinding();
    const { rerender } = render(
      <ToastProvider>
        <FindingsTable findings={[finding]} showScanLink={false} />
      </ToastProvider>,
    );
    await screen.findByRole("region", { name: "Detalhe do achado" });
    expect(screen.queryByText("Ver o scan completo →")).not.toBeInTheDocument();

    rerender(
      <ToastProvider>
        <FindingsTable findings={[finding]} showScanLink />
      </ToastProvider>,
    );
    expect(screen.getByText("Ver o scan completo →")).toBeInTheDocument();
  });

  it("achado com snippet (Fase 12) mostra o trecho e destaca a linha do achado", async () => {
    renderTable({
      findings: [
        makeFinding({ line: 12, snippet: "10: func handler() {\n11:   data := input\n12:   exec(data)\n13: }\n14: " }),
      ],
    });

    expect(await screen.findByText("Trecho do código")).toBeInTheDocument();
    expect(screen.getByText("exec(data)")).toBeInTheDocument();
  });

  it("achado sem snippet (achado antigo, ou ferramenta sem linha específica) nunca mostra a seção", async () => {
    renderTable({ findings: [makeFinding({ snippet: undefined })] });
    await screen.findByText("Como corrigir");

    expect(screen.queryByText("Trecho do código")).not.toBeInTheDocument();
  });

  it("Copiar prompt pra IA copia o markdown do achado pra área de transferência", async () => {
    const user = userEvent.setup();
    renderTable({ findings: [makeFinding()] });
    await screen.findByText("Como corrigir");

    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await user.click(screen.getByRole("button", { name: "Copiar prompt pra IA" }));

    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = writeText.mock.calls[0]?.[0] as string;
    expect(copied).toContain("CVE-2026-0001");
    expect(copied).toContain("Trivy");
    expect(await screen.findByText("Prompt copiado")).toBeInTheDocument();
  });

  it("Copiar prompt pra IA: falha na cópia mostra um toast de erro em vez de travar", async () => {
    const user = userEvent.setup();
    renderTable({ findings: [makeFinding()] });
    await screen.findByText("Como corrigir");

    const writeText = vi.fn().mockRejectedValue(new Error("clipboard indisponível"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await user.click(screen.getByRole("button", { name: "Copiar prompt pra IA" }));

    expect(await screen.findByText("Não foi possível copiar")).toBeInTheDocument();
  });

  it("filtro de severidade: clicar num selo esconde os achados de outra severidade", async () => {
    const critical = makeFinding({ id: "f-critical", finding_id: "CRIT-1", severity: "CRITICAL" });
    const low = makeFinding({ id: "f-low", finding_id: "LOW-1", severity: "LOW" });
    const user = userEvent.setup();
    renderTable({ findings: [critical, low] });

    expect(await screen.findByRole("option", { name: /Ver detalhes do achado CRIT-1/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Ver detalhes do achado LOW-1/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Filtrar por severidade CRITICAL (1)" }));

    expect(screen.getByRole("option", { name: /Ver detalhes do achado CRIT-1/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Ver detalhes do achado LOW-1/ })).not.toBeInTheDocument();
  });

  it("filtro de ferramenta: clicar num selo de scanner isola os achados dele", async () => {
    const fromTrivy = makeFinding({ id: "f-trivy", finding_id: "TRIVY-1", scanner: "trivy" });
    const fromGitleaks = makeFinding({ id: "f-gitleaks", finding_id: "LEAK-1", scanner: "gitleaks" });
    const user = userEvent.setup();
    renderTable({ findings: [fromTrivy, fromGitleaks] });
    await screen.findByRole("option", { name: /TRIVY-1/ });

    await user.click(screen.getByRole("button", { name: "Gitleaks" }));

    expect(screen.queryByRole("option", { name: /Ver detalhes do achado TRIVY-1/ })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Ver detalhes do achado LEAK-1/ })).toBeInTheDocument();
  });

  it("busca livre filtra por texto do finding_id/descrição/arquivo", async () => {
    const match = makeFinding({ id: "f-match", finding_id: "CVE-MATCH", file: "src/auth.ts" });
    const other = makeFinding({ id: "f-other", finding_id: "CVE-OTHER", file: "go.sum" });
    const user = userEvent.setup();
    renderTable({ findings: [match, other] });
    await screen.findByRole("option", { name: /CVE-MATCH/ });

    await user.type(screen.getByLabelText("Buscar achados"), "auth.ts");

    expect(screen.getByRole("option", { name: /Ver detalhes do achado CVE-MATCH/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Ver detalhes do achado CVE-OTHER/ })).not.toBeInTheDocument();
  });

  it("filtro sem nenhum resultado mostra o EmptyState de filtro, não o de lista vazia", async () => {
    const user = userEvent.setup();
    renderTable({ findings: [makeFinding()] });
    await screen.findByText("Como corrigir");

    await user.type(screen.getByLabelText("Buscar achados"), "termo que não existe em nada");

    expect(screen.getByText("Nenhum achado corresponde aos filtros")).toBeInTheDocument();
    expect(screen.queryByText("Nenhum achado ainda")).not.toBeInTheDocument();
  });

  it("Ordenar (Mais antigo primeiro) muda a ordem de exibição da lista", async () => {
    const older = makeFinding({ id: "f-old", finding_id: "OLD-1", created_at: "2026-01-01T00:00:00Z" });
    const newer = makeFinding({ id: "f-new", finding_id: "NEW-1", created_at: "2026-08-01T00:00:00Z" });
    const user = userEvent.setup();
    renderTable({ findings: [newer, older] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    await user.selectOptions(screen.getByLabelText("Ordenar achados"), "Mais antigo primeiro");

    // Escopado à listbox — getAllByRole("option") sem escopo também
    // pegaria os <option> nativos do próprio <select> "Ordenar achados".
    const options = within(screen.getByRole("listbox")).getAllByRole("option");
    expect(options[0]).toHaveAccessibleName(/OLD-1/);
    expect(options[1]).toHaveAccessibleName(/NEW-1/);
  });

  it("Agrupar por alvo (só na visão agregada) reorganiza a lista por target", async () => {
    const findingA = makeFinding({ id: "f-a", finding_id: "A-1", target: "https://github.com/org/api.git" });
    const findingB = makeFinding({ id: "f-b", finding_id: "B-1", target: "https://github.com/org/web.git" });
    const user = userEvent.setup();
    renderTable({ findings: [findingA, findingB], showScanLink: true });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    await user.click(screen.getByLabelText("Agrupar por alvo"));

    expect(screen.getByText("https://github.com/org/api.git")).toBeInTheDocument();
    expect(screen.getByText("https://github.com/org/web.git")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Ver detalhes do achado A-1/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Ver detalhes do achado B-1/ })).toBeInTheDocument();
  });

  it("na página de um scan específico (showScanLink=false), não oferece 'Agrupar por alvo'", () => {
    renderTable({ findings: [makeFinding()], showScanLink: false });
    expect(screen.queryByLabelText("Agrupar por alvo")).not.toBeInTheDocument();
  });

  it("a barra de distribuição de severidade aparece com os achados carregados", () => {
    renderTable({ findings: [makeFinding({ severity: "CRITICAL" }), makeFinding({ id: "f-2", severity: "LOW" })] });
    expect(screen.getByRole("img", { name: /distribuição de severidade/i })).toBeInTheDocument();
  });

  // A partir daqui: deep link (?finding=<id>) — revisão de exibição de
  // resultados.

  it("selecionar um achado reflete o id na URL (?finding=), sem recarregar a página", async () => {
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND" });
    const user = userEvent.setup();
    renderTable({ findings: [first, second] });
    await screen.findByRole("option", { name: /CVE-FIRST/ });

    await user.click(screen.getByRole("option", { name: /Ver detalhes do achado CVE-SECOND/ }));

    await waitFor(() => expect(window.location.search).toBe("?finding=f-2"));
  });

  it("carregar a página com ?finding=<id> já na URL abre esse achado, não o primeiro da lista", async () => {
    window.history.pushState({}, "", "/?finding=f-2");
    const first = makeFinding({ id: "f-1", finding_id: "CVE-FIRST", description: "primeiro achado" });
    const second = makeFinding({ id: "f-2", finding_id: "CVE-SECOND", description: "segundo achado" });
    renderTable({ findings: [first, second] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(within(detailPanel()).getByText("segundo achado")).toBeInTheDocument();
    expect(within(detailPanel()).queryByText("primeiro achado")).not.toBeInTheDocument();
  });

  it("?finding= apontando pra um id que não existe na lista é ignorado (cai no primeiro achado)", async () => {
    window.history.pushState({}, "", "/?finding=nao-existe");
    renderTable({ findings: [makeFinding({ description: "único achado" })] });
    await screen.findByRole("region", { name: "Detalhe do achado" });

    expect(within(detailPanel()).getByText("único achado")).toBeInTheDocument();
  });

  // A partir daqui: triagem no painel de detalhe (projectId) — revisão
  // de exibição de resultados.

  it("sem projectId, o painel de detalhe não mostra controles de triagem", async () => {
    renderTable({ findings: [makeFinding()] });
    await screen.findByText("Como corrigir");

    expect(screen.queryByText("Triar…")).not.toBeInTheDocument();
  });

  it("com projectId, o painel de detalhe mostra 'Triar…' pro achado selecionado", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ data: [], error: null }) }),
    );
    renderTable({ findings: [makeFinding()], projectId: "11111111-2222-3333-4444-555555555555" });

    expect(await screen.findByText("Triar…")).toBeInTheDocument();
  });
});
