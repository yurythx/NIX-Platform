import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SWRConfig } from "swr";

import { ToastProvider } from "@/components/notifications/ToastProvider";

import { MatchedPublicationsFeed } from "./MatchedPublicationsFeed";

// mockFetchByPath: MatchedPublicationsFeed dispara duas buscas
// independentes ao montar — a lista de termos (useApiQuery, pro
// dropdown) e a primeira página de publicações (fetch direto via
// apiClient.get, fora de SWR) — cuja ORDEM não é garantida (useEffect x
// useSWR não sincronizam entre si). Rotear por trecho da URL, em vez de
// mockFetchSequence (uma resposta por CHAMADA, na ordem), evita um teste
// frágil a qual delas dispara primeiro.
function mockFetchByPath(routes: Record<string, { status: number; body: unknown }>) {
  const fn = vi.fn().mockImplementation((url: string) => {
    const match = Object.entries(routes).find(([path]) => url.includes(path));
    if (!match) {
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ data: [], error: null }) });
    }
    const [, { status, body }] = match;
    return Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

function renderFeed() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <ToastProvider>
        <MatchedPublicationsFeed />
      </ToastProvider>
    </SWRConfig>,
  );
}

describe("MatchedPublicationsFeed", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sem publicação nenhuma, mostra o estado vazio", async () => {
    mockFetchByPath({
      "monitored-terms": { status: 200, body: { data: [], error: null } },
      publications: { status: 200, body: { data: [], error: null, meta: { page: 1, page_size: 20, total_items: 0, total_pages: 0 } } },
    });
    renderFeed();

    expect(await screen.findByText("Nenhuma publicação encontrada")).toBeInTheDocument();
  });

  it("lista uma publicação casada, com tags HTML removidas do texto", async () => {
    mockFetchByPath({
      "monitored-terms": { status: 200, body: { data: [{ id: "t1", label: "Dr. Fulano", active: true, created_at: "2026-08-01T00:00:00Z" }], error: null } },
      publications: {
        status: 200,
        body: {
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
          meta: { page: 1, page_size: 20, total_items: 1, total_pages: 1 },
        },
      },
    });
    renderFeed();

    // getByText((content, element) => ...): TJMG aparece duas vezes no
    // DOM — o badge da publicação em si E uma <option> do filtro de
    // tribunal (populado a partir do que já foi carregado). Descarta a
    // option, mesmo achado real de getByText não filtrar por
    // visibilidade/tipo de elemento que já apareceu antes nesta sessão
    // (ver FindingsTable.test.tsx).
    expect(
      await screen.findByText((content, element) => content === "TJMG" && element?.tagName.toLowerCase() !== "option"),
    ).toBeInTheDocument();
    expect(screen.getByText(/publicação\s+de teste/)).toBeInTheDocument();
    expect(screen.getByText("Casou com: Dr. Fulano")).toBeInTheDocument();
    expect(screen.getByText("Ver publicação original →")).toHaveAttribute("href", "https://example.com/pub");
  });

  it("uma falha na consulta mostra a mensagem de erro", async () => {
    mockFetchByPath({
      "monitored-terms": { status: 200, body: { data: [], error: null } },
      publications: { status: 500, body: { data: null, error: { code: "INTERNAL", message: "falha ao buscar publicações" } } },
    });
    renderFeed();

    expect(await screen.findByText("falha ao buscar publicações")).toBeInTheDocument();
  });

  it("'Carregar mais' acumula a próxima página", async () => {
    const user = userEvent.setup();
    const page1 = {
      status: 200,
      body: {
        data: [{ id: "p1", tribunal: "TJMG", orgao: "x", tipo_comunicacao: "Intimação", texto: "primeira página", process_number: "1", process_number_masked: "1", availability_date: "2026-08-26", monitored_term_id: "t1", monitored_term_label: "Dr. Fulano", matched_at: "2026-08-26T12:00:00Z" }],
        error: null,
        meta: { page: 1, page_size: 20, total_items: 2, total_pages: 2 },
      },
    };
    const page2 = {
      status: 200,
      body: {
        data: [{ id: "p2", tribunal: "TJSP", orgao: "y", tipo_comunicacao: "Citação", texto: "segunda página", process_number: "2", process_number_masked: "2", availability_date: "2026-08-25", monitored_term_id: "t1", monitored_term_label: "Dr. Fulano", matched_at: "2026-08-25T12:00:00Z" }],
        error: null,
        meta: { page: 2, page_size: 20, total_items: 2, total_pages: 2 },
      },
    };
    // mockFetchByPath só suporta uma resposta fixa por rota — pra
    // "carregar mais" (2ª chamada à MESMA rota, resposta DIFERENTE),
    // um contador local decide qual página devolver.
    let publicationsCalls = 0;
    const fetchFn = vi.fn().mockImplementation((url: string) => {
      if (url.includes("monitored-terms")) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ data: [], error: null }) });
      }
      publicationsCalls += 1;
      const { status, body } = publicationsCalls === 1 ? page1 : page2;
      return Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
    });
    vi.stubGlobal("fetch", fetchFn);

    renderFeed();
    expect(await screen.findByText("primeira página")).toBeInTheDocument();
    expect(screen.getByText("1 de 2 publicações carregadas")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Carregar mais" }));

    expect(await screen.findByText("segunda página")).toBeInTheDocument();
    expect(screen.getByText("primeira página")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("2 de 2 publicações carregadas")).toBeInTheDocument());
  });

  it("trocar o filtro de termo dispara uma busca escopada a ele", async () => {
    const user = userEvent.setup();
    const fetchFn = vi.fn().mockImplementation((url: string) => {
      if (url.includes("monitored-terms/t1/publications")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            data: [{ id: "p3", tribunal: "TJRJ", orgao: "z", tipo_comunicacao: "Edital", texto: "só do termo t1", process_number: "3", process_number_masked: "3", availability_date: "2026-08-24", monitored_term_id: "t1", monitored_term_label: "Dr. Fulano", matched_at: "2026-08-24T12:00:00Z" }],
            error: null,
            meta: { page: 1, page_size: 20, total_items: 1, total_pages: 1 },
          }),
        });
      }
      if (url.includes("monitored-terms")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({ data: [{ id: "t1", label: "Dr. Fulano", active: true, created_at: "2026-08-01T00:00:00Z" }], error: null }),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ data: [], error: null, meta: { page: 1, page_size: 20, total_items: 0, total_pages: 0 } }) });
    });
    vi.stubGlobal("fetch", fetchFn);

    renderFeed();
    await screen.findByText("Nenhuma publicação encontrada");

    await user.selectOptions(screen.getByLabelText("Filtrar por termo monitorado"), "t1");

    expect(await screen.findByText("só do termo t1")).toBeInTheDocument();
    expect(fetchFn.mock.calls.some(([url]) => String(url).includes("monitored-terms/t1/publications"))).toBe(true);
  });
});
