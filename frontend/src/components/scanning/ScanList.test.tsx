import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ScanStatus } from "@/types/api";

import { ScanList } from "./ScanList";

function makeScan(overrides: Partial<ScanStatus> = {}): ScanStatus {
  return {
    job_id: "11111111-2222-3333-4444-555555555555",
    status: "completed",
    target: "https://github.com/org/repo.git",
    requested_scanners: ["trivy"],
    succeeded_scanners: ["trivy"],
    failed_scanners: [],
    scanner_runs: [],
    progress_percent: 100,
    attempts: 1,
    created_at: "2026-08-24T12:00:00Z",
    ...overrides,
  };
}

describe("ScanList", () => {
  it("lista vazia mostra o EmptyState em vez de uma lista sem itens", () => {
    render(<ScanList scans={[]} />);
    expect(screen.getByText("Nenhum scan disparado ainda")).toBeInTheDocument();
  });

  it("cada scan linka pra sua própria página de detalhe (/seguranca/{job_id})", () => {
    const scan = makeScan();
    render(<ScanList scans={[scan]} />);
    const link = screen.getByRole("link", { name: /repo\.git/ });
    expect(link).toHaveAttribute("href", `/seguranca/${scan.job_id}`);
  });

  it("mostra a porcentagem só pra scans ainda não terminados", () => {
    const running = makeScan({ status: "processing", progress_percent: 40 });
    const { rerender } = render(<ScanList scans={[running]} />);
    expect(screen.getByText("40%")).toBeInTheDocument();

    const done = makeScan({ status: "completed", progress_percent: 100 });
    rerender(<ScanList scans={[done]} />);
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });

  it("mostra um selo com a contagem de falhas quando algum scanner falhou", () => {
    const scan = makeScan({
      failed_scanners: [{ scanner: "zap", code: "VALIDATION_ERROR", message: "x", hint: "y" }],
    });
    render(<ScanList scans={[scan]} />);
    expect(screen.getByText("1 falha(s)")).toBeInTheDocument();
  });

  // Reproduz o crash real relatado pelo usuário ("não consegui nem
  // acessar a página"): 3 jobs de verdade deste ambiente, de antes da
  // Fase 7 (Orquestração concorrente), tinham requested_scanners/
  // failed_scanners nulos no JSON — .join/.length quebravam a página
  // /seguranca INTEIRA, não só a linha desse job. O backend já foi
  // corrigido pra nunca mais mandar null (ver transport/dto.go's
  // nonNilStrings), mas este teste garante que o componente também não
  // quebra sozinho, caso um payload nulo chegue de outra forma.
  it("nunca quebra o render quando requested_scanners/failed_scanners vêm nulos", () => {
    const scan = makeScan();
    // @ts-expect-error simula o payload real de um job antigo, que o tipo ScanStatus não declara como possível
    scan.requested_scanners = null;
    // @ts-expect-error idem
    scan.failed_scanners = null;
    expect(() => render(<ScanList scans={[scan]} />)).not.toThrow();
  });

  // A partir daqui: revisão de exibição de resultados — ScanList virou a
  // tela inicial de /seguranca, ganhou o nome de cada ferramenta usada e
  // a contagem de erro/warning.

  it("mostra o nome de exibição de cada ferramenta pedida, não o slug cru", () => {
    const scan = makeScan({ requested_scanners: ["trivy", "sonarqube"] });
    render(<ScanList scans={[scan]} />);
    expect(screen.getByText("Trivy")).toBeInTheDocument();
    expect(screen.getByText("SonarQube")).toBeInTheDocument();
  });

  it("CRITICAL+HIGH viram 'erro(s)', MEDIUM+LOW viram 'warning(s)'", () => {
    const scan = makeScan({ findings_by_severity: { CRITICAL: 2, HIGH: 1, MEDIUM: 3, LOW: 1 } });
    render(<ScanList scans={[scan]} />);
    expect(screen.getByText("3 erro(s)")).toBeInTheDocument();
    expect(screen.getByText("4 warning(s)")).toBeInTheDocument();
  });

  it("sem findings_by_severity (scan sem achado, ou ainda rodando), não mostra selo de erro/warning nenhum", () => {
    const scan = makeScan({ findings_by_severity: undefined });
    render(<ScanList scans={[scan]} />);
    expect(screen.queryByText(/erro\(s\)/)).not.toBeInTheDocument();
    expect(screen.queryByText(/warning\(s\)/)).not.toBeInTheDocument();
  });
});
