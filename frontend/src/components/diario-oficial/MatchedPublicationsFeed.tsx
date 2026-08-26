"use client";

import { EmptyState } from "@/components/ui/EmptyState";
import { ApiError, useApiQuery } from "@/lib/api/swr";
import type { MatchedPublication } from "@/types/api";

// MatchedPublicationsFeed — o feed agregado de publicações que casaram
// com QUALQUER termo monitorado, mais recente primeiro (equivalente
// diario_oficial de ScanList em /seguranca). Client Component via SWR
// (mesmo raciocínio de ScannerHealthPanel): uma publicação nova pode
// chegar a qualquer momento (o worker sincroniza a cada 6h), então
// revalidar ao voltar pra aba é mais útil aqui que um fetch só no
// primeiro paint.
//
// Paginação "carregar mais" fica como próximo passo natural (ver
// PaginatedFindingsFeed em scanning, o mesmo padrão já usado lá) — não
// implementada nesta primeira versão pra manter o escopo do MVP
// contido; a primeira página (20 mais recentes) já cobre o caso de uso
// mais comum ("o que apareceu recentemente").
export function MatchedPublicationsFeed() {
  const { data: publications, error, isLoading } = useApiQuery<MatchedPublication[]>(
    "v1/diario-oficial/publications?page=1&page_size=20",
  );

  if (error) {
    return (
      <p className="text-sm text-danger">
        {error instanceof ApiError ? error.message : "Falha ao carregar publicações"}
      </p>
    );
  }
  if (isLoading && !publications) {
    return <p className="text-sm text-muted">Carregando…</p>;
  }
  if (!publications || publications.length === 0) {
    return (
      <EmptyState
        title="Nenhuma publicação encontrada ainda"
        description="Assim que o worker sincronizar um termo monitorado contra o DJEN e encontrar uma publicação nova, ela aparece aqui."
      />
    );
  }

  return (
    <ul className="flex flex-col divide-y divide-surface-border rounded-lg border border-surface-border bg-surface">
      {publications.map((p) => (
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
  );
}
