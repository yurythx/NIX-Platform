import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { Project } from "@/types/api";

import { ProjectCard } from "./ProjectCard";

const gitProjectNeverScanned: Project = {
  id: "proj-1",
  name: "api-principal",
  source_type: "git",
  target: "https://github.com/org/repo.git",
  created_at: "2026-08-24T12:00:00Z",
};

const gitProjectWithLastScan: Project = {
  ...gitProjectNeverScanned,
  last_scan: {
    job_id: "scan-1",
    status: "completed",
    target: "https://github.com/org/repo.git",
    requested_scanners: ["trivy", "gitleaks"],
    succeeded_scanners: ["trivy", "gitleaks"],
    failed_scanners: [],
    scanner_runs: [],
    progress_percent: 100,
    attempts: 1,
    created_at: "2026-08-24T12:00:00Z",
  },
};

const uploadProjectNeverScanned: Project = {
  id: "proj-2",
  name: "servico-legado",
  source_type: "upload",
  created_at: "2026-08-24T12:00:00Z",
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

describe("ProjectCard", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("projeto nunca escaneado: sem link de histórico nem de último scan", () => {
    render(
      <ToastProvider>
        <ProjectCard project={gitProjectNeverScanned} />
      </ToastProvider>,
    );
    expect(screen.getByText("Nunca rodado")).toBeInTheDocument();
    expect(screen.queryByText("Ver histórico →")).not.toBeInTheDocument();
    expect(screen.queryByText(/Ver último scan/)).not.toBeInTheDocument();
  });

  it("Rodar de novo reaproveita os scanners do último scan, não um default", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => ({ data: { job_id: "new-job-id", status: "queued" }, error: null }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ProjectCard project={gitProjectWithLastScan} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Rodar de novo" }));

    const [, init] = fetchMock.mock.calls[0] ?? [];
    const body = JSON.parse(init.body as string);
    expect(body.scanners).toEqual(["trivy", "gitleaks"]);
    expect(body.project_id).toBe("proj-1");
  });

  it("mostra com quais scanners vai rodar, e 'Alterar scanners' deixa mudar antes de disparar", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => ({ data: { job_id: "new-job-id", status: "queued" }, error: null }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ProjectCard project={gitProjectWithLastScan} />
      </ToastProvider>,
    );

    // A escolha (herdada do último scan) já aparece como texto, nunca
    // escondida atrás de um clique — é exatamente essa transparência que
    // faltava antes desta unificação com TriggerScanForm.
    expect(screen.getByText("com Trivy, Gitleaks")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Alterar scanners" }));
    await user.click(screen.getByRole("switch", { name: "Semgrep" }));
    expect(screen.getByText("com Trivy, Gitleaks, Semgrep")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Rodar de novo" }));

    const [, init] = fetchMock.mock.calls[0] ?? [];
    const body = JSON.parse(init.body as string);
    expect(body.scanners).toEqual(["trivy", "gitleaks", "semgrep"]);
  });

  it("projeto git: seletor de scanners não oferece OWASP ZAP, mas oferece SonarQube", async () => {
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ProjectCard project={gitProjectWithLastScan} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Alterar scanners" }));
    expect(screen.queryByRole("switch", { name: "OWASP ZAP" })).not.toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "SonarQube" })).toBeInTheDocument();
  });

  it("projeto de upload: seletor de scanners não oferece OWASP ZAP nem SonarQube (não implementam LocalScanner)", async () => {
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ProjectCard project={uploadProjectNeverScanned} />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Alterar scanners" }));
    expect(screen.queryByRole("switch", { name: "OWASP ZAP" })).not.toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "SonarQube" })).not.toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Trivy" })).toBeInTheDocument();
  });

  it("Ver histórico alterna o painel de histórico deduplicado (Fase 12)", async () => {
    mockFetchOnce(200, { data: [], error: null });
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ProjectCard project={gitProjectWithLastScan} />
      </ToastProvider>,
    );

    expect(screen.queryByText("Nenhum achado no histórico")).not.toBeInTheDocument();

    await user.click(screen.getByText("Ver histórico →"));
    expect(await screen.findByText("Nenhum achado no histórico")).toBeInTheDocument();

    await user.click(screen.getByText("Ocultar histórico ←"));
    expect(screen.queryByText("Nenhum achado no histórico")).not.toBeInTheDocument();
  });
});
