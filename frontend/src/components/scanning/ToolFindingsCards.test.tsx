import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ScanFinding, ScanStatus } from "@/types/api";

import { ToolFindingsCards } from "./ToolFindingsCards";

function baseStatus(overrides: Partial<ScanStatus> = {}): ScanStatus {
  return {
    job_id: "11111111-2222-3333-4444-555555555555",
    status: "completed",
    target: "https://github.com/org/repo.git",
    requested_scanners: ["trivy", "semgrep"],
    succeeded_scanners: ["trivy", "semgrep"],
    failed_scanners: [],
    scanner_runs: [
      { scanner: "trivy", status: "succeeded", started_at: "2026-08-24T12:00:00Z", finished_at: "2026-08-24T12:00:05Z" },
      { scanner: "semgrep", status: "succeeded", started_at: "2026-08-24T12:00:00Z", finished_at: "2026-08-24T12:00:05Z" },
    ],
    progress_percent: 100,
    attempts: 1,
    created_at: "2026-08-24T12:00:00Z",
    ...overrides,
  };
}

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: "f1",
    scan_id: "scan-1",
    scanner: "trivy",
    target: "https://github.com/org/repo.git",
    finding_id: "CVE-2026-0001",
    owasp_category: "",
    severity: "HIGH",
    description: "desc",
    file: "",
    line: 0,
    fingerprint: "abc123fingerprint",
    created_at: "2026-08-24T12:00:00Z",
    tool: { name: "Trivy" },
    ...overrides,
  };
}

describe("ToolFindingsCards", () => {
  it("um card por scanner PEDIDO, mesmo sem nenhum achado (0 erros, 0 warnings, não some da lista)", () => {
    render(<ToolFindingsCards scanId="scan-1" status={baseStatus()} findings={[]} />);
    expect(screen.getByText("Trivy")).toBeInTheDocument();
    expect(screen.getByText("Semgrep")).toBeInTheDocument();
    expect(screen.getAllByText("0 erros").length).toBe(2);
    expect(screen.getAllByText("0 warnings").length).toBe(2);
  });

  it("separa achados CRITICAL/HIGH como 'erros' e MEDIUM/LOW como 'warnings'", () => {
    const findings = [
      makeFinding({ id: "f1", scanner: "trivy", severity: "CRITICAL" }),
      makeFinding({ id: "f2", scanner: "trivy", severity: "HIGH" }),
      makeFinding({ id: "f3", scanner: "trivy", severity: "MEDIUM" }),
      makeFinding({ id: "f4", scanner: "trivy", severity: "LOW" }),
      makeFinding({ id: "f5", scanner: "trivy", severity: "LOW" }),
    ];
    render(<ToolFindingsCards scanId="scan-1" status={baseStatus()} findings={findings} />);
    expect(screen.getByText("2 erros")).toBeInTheDocument();
    expect(screen.getByText("3 warnings")).toBeInTheDocument();
  });

  it("cada card linka pra /seguranca/{scanId}/{scanner}", () => {
    render(<ToolFindingsCards scanId="scan-42" status={baseStatus()} findings={[]} />);
    expect(screen.getByRole("link", { name: /Trivy/ })).toHaveAttribute("href", "/seguranca/scan-42/trivy");
    expect(screen.getByRole("link", { name: /Semgrep/ })).toHaveAttribute("href", "/seguranca/scan-42/semgrep");
  });

  it("scanner que falhou mostra o selo 'Falhou' no card", () => {
    render(
      <ToolFindingsCards
        scanId="scan-1"
        status={baseStatus({
          succeeded_scanners: ["trivy"],
          failed_scanners: [{ scanner: "semgrep", code: "DEPENDENCY_UNAVAILABLE", message: "x", hint: "y" }],
          scanner_runs: [
            { scanner: "trivy", status: "succeeded", started_at: "2026-08-24T12:00:00Z" },
            { scanner: "semgrep", status: "failed", started_at: "2026-08-24T12:00:00Z" },
          ],
        })}
        findings={[]}
      />,
    );
    expect(screen.getByText("Falhou")).toBeInTheDocument();
  });

  it("scanner ainda não iniciado mostra o selo 'Na fila'", () => {
    render(
      <ToolFindingsCards
        scanId="scan-1"
        status={baseStatus({ scanner_runs: [] })}
        findings={[]}
      />,
    );
    expect(screen.getAllByText("Na fila").length).toBe(2);
  });
});
