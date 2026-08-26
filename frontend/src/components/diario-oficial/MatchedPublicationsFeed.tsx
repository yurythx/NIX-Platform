"use client";

import { useEffect, useMemo, useState } from "react";

import { useToast } from "@/components/notifications/ToastProvider";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { apiClient, ApiError } from "@/lib/api/client";
import { useApiQuery } from "@/lib/api/swr";
import type { MatchedPublication, MonitoredTerm, PaginationMeta } from "@/types/api";

const PAGE_SIZE = 20;
const ALL = "";

function pathFor(termId: string, page: number) {
  return termId
    ? `v1/diario-oficial/monitored-terms/${termId}/publications?page=${page}&page_size=${PAGE_SIZE}`
    : `v1/diario-oficial/publications?page=${page}&page_size=${PAGE_SIZE}`;
}

// MatchedPublicationsFeed — o feed de publicações que casaram com termo
// monitorado. Três filtros: por TERMO (troca a origem da busca —
// GET .../monitored-terms/{id}/publications em vez do feed global; o
// endpoint já existia no backend desde o MVP, só não estava exposto na
// UI) e por tribunal/tipo de comunicação (client-side, sobre o que já
// foi carregado — mesmo raciocínio que FindingsTable já usa pra
// severidade/ferramenta: a lista completa carregada até agora, não só a
// página visível).
//
// Fora de SWR de propósito (ao contrário de SourceHealthPanel/
// MonitoredTermsPanel): "carregar mais" acumula páginas em memória
// (mesmo padrão de PaginatedFindingsFeed em scanning) e trocar de termo
// reinicia a paginação — um estado multi-dimensional (filtro de origem +
// páginas acumuladas) que não cabe bem no modelo de UMA key por vez do
// useSWR sem reimplementar por cima dele o que já faria sentido ser
// local.
export function MatchedPublicationsFeed() {
  const { data: terms } = useApiQuery<MonitoredTerm[]>("v1/diario-oficial/monitored-terms");
  const { showToast } = useToast();

  const [termFilter, setTermFilter] = useState(ALL);
  const [tribunalFilter, setTribunalFilter] = useState(ALL);
  const [tipoFilter, setTipoFilter] = useState(ALL);

  const [publications, setPublications] = useState<MatchedPublication[] | null>(null);
  const [meta, setMeta] = useState<PaginationMeta | undefined>(undefined);
  // loading começa true pro fetch inicial (mount); handleTermFilterChange
  // (abaixo) reseta pra true de novo a cada troca — sempre dentro de um
  // event handler, nunca síncrono dentro do efeito, pra não disparar
  // `react-hooks/set-state-in-effect` (o mesmo achado real que já
  // levou FindingsTable, na revisão de exibição de resultados, a
  // useSyncExternalStore em vez de useEffect+setState direto).
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // handleTermFilterChange: os únicos setState SÍNCRONOS relacionados à
  // troca de termo vivem aqui (um event handler, nunca um efeito) — o
  // efeito abaixo só seta estado dentro de callbacks assíncronos
  // (.then/.catch/.finally), nunca no corpo síncrono do efeito em si.
  function handleTermFilterChange(next: string) {
    setTermFilter(next);
    setPublications(null);
    setMeta(undefined);
    setError(null);
    setLoading(true);
  }

  // Busca a página 1 pra termFilter atual — troca de termo é uma busca
  // NOVA (origem diferente no backend), a paginação acumulada recomeça.
  // Tribunal/tipo não entram nesta dependência: são filtro sobre o que
  // já está em memória, nunca pedem uma nova busca ao trocar.
  useEffect(() => {
    let cancelled = false;
    apiClient
      .get<MatchedPublication[]>(pathFor(termFilter, 1))
      .then(({ data, meta: nextMeta }) => {
        if (cancelled) return;
        setPublications(data);
        setMeta(nextMeta as PaginationMeta | undefined);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Falha ao carregar publicações");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [termFilter]);

  async function loadMore() {
    if (!meta) return;
    setLoadingMore(true);
    try {
      const nextPage = meta.page + 1;
      const { data, meta: nextMeta } = await apiClient.get<MatchedPublication[]>(pathFor(termFilter, nextPage));
      setPublications((current) => [...(current ?? []), ...data]);
      setMeta(nextMeta as PaginationMeta | undefined);
    } catch (err) {
      showToast({
        title: "Não foi possível carregar mais publicações",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setLoadingMore(false);
    }
  }

  const tribunalOptions = useMemo(
    () => Array.from(new Set((publications ?? []).map((p) => p.tribunal))).sort(),
    [publications],
  );
  const tipoOptions = useMemo(
    () => Array.from(new Set((publications ?? []).map((p) => p.tipo_comunicacao))).sort(),
    [publications],
  );

  const filtered = (publications ?? []).filter(
    (p) =>
      (!tribunalFilter || p.tribunal === tribunalFilter) && (!tipoFilter || p.tipo_comunicacao === tipoFilter),
  );

  const hasMore = meta !== undefined && meta.page < meta.total_pages;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        <label className="flex items-center gap-1.5 text-sm text-muted">
          Termo
          <select
            value={termFilter}
            onChange={(e) => handleTermFilterChange(e.target.value)}
            aria-label="Filtrar por termo monitorado"
            className="rounded-md border border-surface-border bg-surface px-2 py-1 text-sm text-foreground"
          >
            <option value={ALL}>Todos</option>
            {(terms ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-sm text-muted">
          Tribunal
          <select
            value={tribunalFilter}
            onChange={(e) => setTribunalFilter(e.target.value)}
            aria-label="Filtrar por tribunal"
            className="rounded-md border border-surface-border bg-surface px-2 py-1 text-sm text-foreground"
          >
            <option value={ALL}>Todos</option>
            {tribunalOptions.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-sm text-muted">
          Tipo
          <select
            value={tipoFilter}
            onChange={(e) => setTipoFilter(e.target.value)}
            aria-label="Filtrar por tipo de comunicação"
            className="rounded-md border border-surface-border bg-surface px-2 py-1 text-sm text-foreground"
          >
            <option value={ALL}>Todos</option>
            {tipoOptions.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error ? (
        <p className="text-sm text-danger">{error}</p>
      ) : loading && !publications ? (
        <p className="text-sm text-muted">Carregando…</p>
      ) : filtered.length === 0 ? (
        <EmptyState
          title="Nenhuma publicação encontrada"
          description={
            publications && publications.length > 0
              ? "Nenhuma publicação carregada bate com o filtro de tribunal/tipo escolhido."
              : "Assim que o worker sincronizar um termo monitorado contra o DJEN e encontrar uma publicação nova, ela aparece aqui."
          }
        />
      ) : (
        <ul className="flex flex-col divide-y divide-surface-border rounded-lg border border-surface-border bg-surface">
          {filtered.map((p) => (
            <li key={p.id} className="flex flex-col gap-2 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
                  <span className="rounded-full border border-surface-border px-2 py-0.5 font-medium text-foreground">
                    {p.tribunal}
                  </span>
                  <span>{p.tipo_comunicacao}</span>
                  {p.process_number_masked && <span>· {p.process_number_masked}</span>}
                </div>
                <span className="whitespace-nowrap text-xs text-muted">
                  {new Date(p.matched_at).toLocaleString()}
                </span>
              </div>
              <p className="line-clamp-3 text-sm text-foreground" title={p.texto}>
                {p.texto.replace(/<[^>]+>/g, " ").trim()}
              </p>
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                <span>Casou com: {p.monitored_term_label}</span>
                {p.link && (
                  <a href={p.link} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                    Ver publicação original →
                  </a>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      {meta && meta.total_items > 0 && (
        <div className="flex flex-col items-center gap-1">
          {hasMore && (
            <Button variant="secondary" size="sm" onClick={() => void loadMore()} loading={loadingMore}>
              Carregar mais
            </Button>
          )}
          <p className="text-xs text-muted">
            {publications?.length ?? 0} de {meta.total_items} publicações carregadas
          </p>
        </div>
      )}
    </div>
  );
}
