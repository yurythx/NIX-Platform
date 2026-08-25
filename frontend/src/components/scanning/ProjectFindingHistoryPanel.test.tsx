import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ProjectFindingHistory } from "@/types/api";

import { ProjectFindingHistoryPanel } from "./ProjectFindingHistoryPanel";

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

function makeHistory(overrides: Partial<ProjectFindingHistory> = {}): ProjectFindingHistory {
  return {
    fingerprint: "fp-1",
    scanner: "trivy",
    owasp_category: "A06:2021-Vulnerable and Outdated Components",
    severity: "HIGH",
    description: "CVE-2026-1234 in some-package",
    file: "go.mod",
    line: 12,
    first_seen_at: "2026-08-12T00:00:00Z",
    last_seen_at: "2026-08-20T00:00:00Z",
    scan_count: 3,
    still_present: true,
    tool: { name: "Trivy", url: "" },
    ...overrides,
  };
}

// Refeito sobre useApiQuery (SWR) em vez de useEffect+useState manual —
// estes três testes cobrem os mesmos três estados que o componente
// tratava antes (carregando/erro/dados), que não tinham nenhum teste até
// esta mudança. Cada teste usa um projectId DIFERENTE de propósito: o
// cache do SWR é um Map em nível de módulo, compartilhado entre testes
// do mesmo arquivo — reusar a mesma key faria o segundo/terceiro teste
// receber instantaneamente o valor em cache do primeiro (dentro da
// mesma janela de dedupingInterval) em vez de bater no fetch mockado
// daquele teste.
describe("ProjectFindingHistoryPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("mostra o EmptyState quando o histórico vem vazio", async () => {
    mockFetchOnce(200, { data: [], error: null });
    render(<ProjectFindingHistoryPanel projectId="11111111-2222-3333-4444-555555555555" />);
    expect(await screen.findByText("Nenhum achado no histórico")).toBeInTheDocument();
  });

  it("lista o histórico com status 'Ainda presente'/'Corrigido' por achado", async () => {
    mockFetchOnce(200, {
      data: [makeHistory({ still_present: true }), makeHistory({ fingerprint: "fp-2", still_present: false })],
      error: null,
    });
    render(<ProjectFindingHistoryPanel projectId="22222222-2222-3333-4444-555555555555" />);
    expect(await screen.findByText("Ainda presente")).toBeInTheDocument();
    expect(screen.getByText("Corrigido")).toBeInTheDocument();
  });

  it("mostra a mensagem de erro em vez de travar num 'carregando' pra sempre", async () => {
    mockFetchOnce(500, { data: null, error: { code: "INTERNAL", message: "falha ao consultar o histórico" } });
    render(<ProjectFindingHistoryPanel projectId="33333333-2222-3333-4444-555555555555" />);
    expect(await screen.findByText("falha ao consultar o histórico")).toBeInTheDocument();
  });
});
