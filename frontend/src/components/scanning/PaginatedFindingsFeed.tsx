"use client";

import { useState } from "react";

import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { PaginationMeta, ScanFinding } from "@/types/api";

import { FindingsTable } from "./FindingsTable";

// PaginatedFindingsFeed (Fase 14 — Maturidade de AppSec): antes desta
// mudança, GET /scanning/findings tinha um limit sem OFFSET — pedido
// "generoso" (limit=100 no frontend, teto de 200 no backend) e QUALQUER
// achado além disso simplesmente nunca aparecia em lugar nenhum da UI,
// sem nem um aviso de que havia mais. Server Component
// (app/(protected)/seguranca/page.tsx) continua buscando a PRIMEIRA
// página no servidor, pro primeiro paint continuar rápido — este
// componente só existe pra "Carregar mais" acumular páginas seguintes
// sob demanda, sem re-buscar a primeira de novo.
//
// Acumula em memória (nunca descarta uma página já carregada) — o
// filtro client-side que FindingsTable já faz (severidade/ferramenta/
// busca) precisa da lista completa carregada até agora pra funcionar
// direito, não só da última página.
export function PaginatedFindingsFeed({
  initialFindings,
  initialMeta,
}: {
  initialFindings: ScanFinding[];
  initialMeta: PaginationMeta | undefined;
}) {
  const [findings, setFindings] = useState(initialFindings);
  const [meta, setMeta] = useState(initialMeta);
  const [loadingMore, setLoadingMore] = useState(false);
  const { showToast } = useToast();

  const hasMore = meta !== undefined && meta.page < meta.total_pages;

  async function loadMore() {
    if (!meta) return;
    setLoadingMore(true);
    try {
      const nextPage = meta.page + 1;
      const { data, meta: nextMeta } = await apiClient.get<ScanFinding[]>(
        `v1/scanning/findings?page=${nextPage}&page_size=${meta.page_size}`,
      );
      setFindings((current) => [...current, ...data]);
      setMeta(nextMeta as PaginationMeta);
    } catch (err) {
      showToast({
        title: "Não foi possível carregar mais achados",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <FindingsTable findings={findings} showScanLink />
      {hasMore && (
        <div className="flex flex-col items-center gap-1">
          <Button variant="secondary" size="sm" onClick={() => void loadMore()} loading={loadingMore}>
            Carregar mais
          </Button>
          {meta && (
            <p className="text-xs text-muted">
              {findings.length} de {meta.total_items} achados carregados
            </p>
          )}
        </div>
      )}
    </div>
  );
}
