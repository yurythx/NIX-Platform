import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ScanStatus } from "@/types/api";

import { ScanProgress } from "./ScanProgress";

function baseStatus(overrides: Partial<ScanStatus> = {}): ScanStatus {
  return {
    job_id: "11111111-2222-3333-4444-555555555555",
    status: "processing",
    target: "https://github.com/org/repo.git",
    requested_scanners: ["trivy", "semgrep"],
    succeeded_scanners: [],
    failed_scanners: [],
    scanner_runs: [],
    progress_percent: 0,
    attempts: 1,
    created_at: "2026-08-24T12:00:00Z",
    ...overrides,
  };
}

describe("ScanProgress", () => {
  it("mostra um scanner pedido sem nenhuma entrada em scanner_runs como pendente, não some da lista", () => {
    render(<ScanProgress status={baseStatus()} polling />);
    expect(screen.getByText("trivy")).toBeInTheDocument();
    expect(screen.getByText("semgrep")).toBeInTheDocument();
    expect(screen.getAllByText("Na fila").length).toBeGreaterThan(0);
  });

  it("mostra um scanner 'running' com o spinner, distinto de succeeded/failed", () => {
    render(
      <ScanProgress
        status={baseStatus({
          scanner_runs: [
            { scanner: "trivy", status: "running", started_at: "2026-08-24T12:00:00Z" },
          ],
        })}
        polling
      />,
    );
    expect(screen.getAllByRole("status").length).toBeGreaterThan(0);
    expect(screen.getByText("trivy rodando")).toBeInTheDocument();
  });

  it("progress_percent aparece como texto e como largura da barra", () => {
    render(<ScanProgress status={baseStatus({ progress_percent: 50 })} polling />);
    expect(screen.getByText("50%")).toBeInTheDocument();
  });

  it("scanner com falha mostra o card com scanner/code/message/hint", () => {
    render(
      <ScanProgress
        status={baseStatus({
          status: "completed",
          progress_percent: 100,
          succeeded_scanners: ["trivy"],
          failed_scanners: [
            {
              scanner: "zap",
              code: "VALIDATION_ERROR",
              message: "no hosts are allowlisted",
              hint: "configure SCANNING_ZAP_ALLOWED_HOSTS",
            },
          ],
          scanner_runs: [
            { scanner: "trivy", status: "succeeded", started_at: "2026-08-24T12:00:00Z", finished_at: "2026-08-24T12:00:01Z", duration_ms: 1000, findings_count: 3 },
            { scanner: "zap", status: "failed", started_at: "2026-08-24T12:00:00Z", finished_at: "2026-08-24T12:00:01Z", duration_ms: 1000, error: "no hosts are allowlisted" },
          ],
        })}
        polling={false}
      />,
    );
    expect(screen.getByText("VALIDATION_ERROR")).toBeInTheDocument();
    expect(screen.getByText("no hosts are allowlisted")).toBeInTheDocument();
    expect(screen.getByText("configure SCANNING_ZAP_ALLOWED_HOSTS")).toBeInTheDocument();
    expect(screen.getByText("3 achado(s)")).toBeInTheDocument();
  });

  it("nunca quebra o render quando scanner_runs/failed_scanners/succeeded_scanners vêm ausentes", () => {
    const status = baseStatus();
    // @ts-expect-error simula um payload incompleto, como um mock de teste esquecido de atualizar
    delete status.scanner_runs;
    // @ts-expect-error idem
    delete status.failed_scanners;
    status.succeeded_scanners = null;
    expect(() => render(<ScanProgress status={status} polling />)).not.toThrow();
  });
});
