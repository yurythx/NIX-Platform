"use client";

import { Badge } from "@/components/ui/Badge";
import { ApiError, useApiQuery } from "@/lib/api/swr";
import type { SourceHealth } from "@/types/api";

const SOURCE_LABEL: Record<string, string> = {
  djen: "DJEN (Diário de Justiça Eletrônico Nacional)",
};

// SourceHealthPanel — mesmo raciocínio de ScannerHealthPanel
// (reestruturação de /seguranca): busca GET /diario-oficial/health via
// SWR, não Server Component, porque a saúde da fonte muda a qualquer
// momento e SWR já revalida sozinho ao voltar pra aba
// (revalidateOnFocus). Só UM item hoje (DJEN) — a lista existe pensando
// em quando uma segunda fonte (ex.: a API de uma prefeitura) entrar,
// pra não precisar reescrever este componente então.
export function SourceHealthPanel() {
  const { data: health, error, isLoading, mutate } = useApiQuery<SourceHealth>("v1/diario-oficial/health");

  return (
    <div className="rounded-lg border border-surface-border bg-surface p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Saúde da fonte de dados</h2>
          <p className="text-xs text-muted">
            Se a fonte estiver fora do ar, o worker não encontra publicação nova até ela voltar.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void mutate()}
          disabled={isLoading}
          className="shrink-0 rounded-md border border-surface-border px-2.5 py-1 text-xs text-foreground hover:bg-black/5 disabled:opacity-50 dark:hover:bg-white/5"
        >
          Verificar de novo
        </button>
      </div>

      {error ? (
        <p className="text-sm text-danger">
          {error instanceof ApiError ? error.message : "Falha ao verificar a saúde da fonte"}
        </p>
      ) : !health ? (
        <p className="text-sm text-muted">Verificando…</p>
      ) : (
        <div
          className="flex items-center justify-between gap-2 rounded-md border border-surface-border px-3 py-2"
          title={health.message}
        >
          <span className="truncate text-sm text-foreground">{SOURCE_LABEL[health.source] ?? health.source}</span>
          <Badge tone={health.healthy ? "success" : "danger"}>{health.healthy ? "No ar" : "Fora do ar"}</Badge>
        </div>
      )}
    </div>
  );
}
