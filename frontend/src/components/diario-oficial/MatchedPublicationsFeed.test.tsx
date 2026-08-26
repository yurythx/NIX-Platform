import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SWRConfig } from "swr";

import { MatchedPublicationsFeed } from "./MatchedPublicationsFeed";

function mockFetchOnce(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, json: async () => body });
  vi.stubGlobal("fetch", fn);
  return fn;
}

function renderFeed() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <MatchedPublicationsFeed />
    </SWRConfig>,
  );
}

describe("MatchedPublicationsFeed", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sem publicação nenhuma, mostra o estado vazio", async () => {
    mockFetchOnce(200, { data: [], error: null });
    renderFeed();

    expect(await screen.findByText("Nenhuma publicação encontrada ainda")).toBeInTheDocument();
  });

  it("lista uma publicação casada, com tags HTML removidas do texto", async () => {
    mockFetchOnce(200, {
      data: [
        {
          id: "p1",
          tribunal: "TJMG",
          orgao: "1ª Vara Cível",
          tipo_comunicacao: "Intimação",
          texto: "<p>publicação <b>de teste</b></p>",
          process_number: "123",
          process_number_masked: "0000123-45.2026.8.13.0001",
          availability_date: "2026-08-26",
          link: "https://example.com/pub",
          monitored_term_id: "t1",
          monitored_term_label: "Dr. Fulano",
          matched_at: "2026-08-26T12:00:00Z",
        },
      ],
      error: null,
    });
    renderFeed();

    expect(await screen.findByText("TJMG")).toBeInTheDocument();
    expect(screen.getByText(/publicação\s+de teste/)).toBeInTheDocument();
    expect(screen.getByText("Casou com: Dr. Fulano")).toBeInTheDocument();
    expect(screen.getByText("Ver publicação original →")).toHaveAttribute("href", "https://example.com/pub");
  });

  it("uma falha na consulta mostra a mensagem de erro", async () => {
    mockFetchOnce(500, { data: null, error: { code: "INTERNAL", message: "falha ao buscar publicações" } });
    renderFeed();

    expect(await screen.findByText("falha ao buscar publicações")).toBeInTheDocument();
  });
});
