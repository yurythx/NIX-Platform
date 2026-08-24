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
});
