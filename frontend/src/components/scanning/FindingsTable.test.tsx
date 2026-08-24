import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

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
    created_at: "2026-08-24T12:00:00Z",
    tool: { name: "Trivy", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" },
    ...overrides,
  };
}

describe("FindingsTable", () => {
  it("lista vazia mostra o EmptyState em vez de uma tabela sem linhas", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText("Nenhum achado ainda")).toBeInTheDocument();
  });

  it("clicar numa linha abre o Dialog com o achado por extenso, inclusive como corrigir", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    render(<FindingsTable findings={[finding]} />);

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
    render(<FindingsTable findings={[finding]} />);

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).getByText("OWASP ZAP")).toBeInTheDocument();
    expect(within(dialog).queryByRole("link", { name: "Abrir na ferramenta →" })).not.toBeInTheDocument();
  });

  it("teclar Enter numa linha focada também abre o detalhe (acessibilidade de teclado)", async () => {
    const finding = makeFinding({ finding_id: "CVE-2026-9999" });
    const user = userEvent.setup();
    render(<FindingsTable findings={[finding]} />);

    screen.getByRole("button", { name: /Ver detalhes do achado CVE-2026-9999/ }).focus();
    await user.keyboard("{Enter}");

    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("showScanLink controla se o link de volta pro scan aparece no Dialog", async () => {
    const finding = makeFinding();
    const user = userEvent.setup();
    const { rerender } = render(<FindingsTable findings={[finding]} showScanLink={false} />);

    await user.click(screen.getByRole("button", { name: /Ver detalhes/ }));
    expect(screen.queryByText("Ver o scan completo →")).not.toBeInTheDocument();

    rerender(<FindingsTable findings={[finding]} showScanLink />);
    expect(screen.getByText("Ver o scan completo →")).toBeInTheDocument();
  });
});
