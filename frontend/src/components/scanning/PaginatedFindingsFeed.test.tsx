import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { PaginationMeta, ScanFinding } from "@/types/api";

import { PaginatedFindingsFeed } from "./PaginatedFindingsFeed";

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: "finding-1",
    scan_id: "scan-1",
    scanner: "trivy",
    target: "https://github.com/org/repo.git",
    finding_id: "CVE-2026-0001",
    owasp_category: "A06:2021-Vulnerable and Outdated Components",
    severity: "HIGH",
    description: "achado da primeira página",
    file: "go.sum",
    line: 12,
    fingerprint: "fp-page-1",
    created_at: "2026-08-24T12:00:00Z",
    tool: { name: "Trivy", url: "" },
    ...overrides,
  };
}

function meta(overrides: Partial<PaginationMeta> = {}): PaginationMeta {
  return { page: 1, page_size: 1, total_items: 2, total_pages: 2, ...overrides };
}

function renderFeed(findings: ScanFinding[], initialMeta: PaginationMeta | undefined) {
  return render(
    <ToastProvider>
      <PaginatedFindingsFeed initialFindings={findings} initialMeta={initialMeta} />
    </ToastProvider>,
  );
}

describe("PaginatedFindingsFeed", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sem mais páginas (page === total_pages), não mostra 'Carregar mais'", () => {
    renderFeed([makeFinding()], meta({ page: 1, total_pages: 1 }));
    expect(screen.queryByText("Carregar mais")).not.toBeInTheDocument();
  });

  it("com mais páginas, mostra 'Carregar mais' e o progresso de quantos já carregaram", () => {
    renderFeed([makeFinding()], meta({ page: 1, total_pages: 2, total_items: 2 }));
    expect(screen.getByText("Carregar mais")).toBeInTheDocument();
    expect(screen.getByText("1 de 2 achados carregados")).toBeInTheDocument();
  });

  it("clicar em 'Carregar mais' busca a próxima página, acumula achados e some quando não há mais", async () => {
    const user = userEvent.setup();
    const page2Finding = makeFinding({
      id: "finding-2",
      finding_id: "CVE-2026-0002",
      fingerprint: "fp-page-2",
      description: "achado da segunda página",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: [page2Finding],
          error: null,
          meta: meta({ page: 2, total_pages: 2, total_items: 2 }),
        }),
      }),
    );

    renderFeed([makeFinding()], meta({ page: 1, total_pages: 2, total_items: 2 }));
    await user.click(screen.getByText("Carregar mais"));

    // O achado da página 2 entra como uma linha nova na lista (a
    // seleção do painel de detalhe continua no da página 1, que
    // carregou primeiro — auto-seleção nunca troca sozinha só porque a
    // lista cresceu).
    await waitFor(() => expect(screen.getByRole("option", { name: /CVE-2026-0002/ })).toBeInTheDocument());
    // O achado da primeira página continua visível — acumula, não
    // substitui — e continua sendo o selecionado no painel de detalhe.
    const detailPanel = screen.getByRole("region", { name: "Detalhe do achado" });
    expect(within(detailPanel).getByText("achado da primeira página")).toBeInTheDocument();
    // page (2) == total_pages (2) agora — não há mais o que carregar.
    expect(screen.queryByText("Carregar mais")).not.toBeInTheDocument();

    const fetchSpy = vi.mocked(fetch);
    const call = fetchSpy.mock.calls.find(([url]) => String(url).includes("page=2"));
    expect(call).toBeDefined();
  });

  it("uma falha ao carregar mais mostra um toast de erro e mantém os achados já carregados", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ data: null, error: { code: "INTERNAL", message: "falha ao buscar mais achados" } }),
      }),
    );

    renderFeed([makeFinding()], meta({ page: 1, total_pages: 2, total_items: 2 }));
    await user.click(screen.getByText("Carregar mais"));

    expect(await screen.findByText("falha ao buscar mais achados")).toBeInTheDocument();
    const detailPanel = screen.getByRole("region", { name: "Detalhe do achado" });
    expect(within(detailPanel).getByText("achado da primeira página")).toBeInTheDocument();
  });
});
