"use client";

import { Badge } from "@/components/ui/Badge";
import { ApiError, useApiQuery } from "@/lib/api/swr";
import { scannerMeta } from "@/lib/scanning/scannerRegistry";
import type { ScannerHealth } from "@/types/api";

// ScannerHealthPanel (pedido do usuário: "seria legal ter uma tela onde
// mostra a saúde das ferramentas que estamos usando antes de
// iniciá-las"): busca GET /scanning/scanners/health via SWR (não
// Server Component) de propósito — a saúde de um sidecar muda a
// qualquer momento, e SWR já revalida sozinho quando o usuário volta
// pra esta aba depois de ter ido corrigir algo (revalidateOnFocus,
// ligado por padrão — ver lib/api/swr.ts), sem precisar de polling
// manual nem de um F5. mutate() no botão "Verificar de novo" cobre o
// caso de continuar na mesma aba esperando o sidecar voltar.
export function ScannerHealthPanel() {
  const { data: health, error, isLoading, mutate } = useApiQuery<ScannerHealth[]>("v1/scanning/scanners/health");

  return (
    <div className="rounded-lg border border-surface-border bg-surface p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Saúde das ferramentas</h2>
          <p className="text-xs text-muted">Confira antes de disparar um scan — uma ferramenta fora do ar falha só o scanner dela, nunca o scan inteiro.</p>
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
          {error instanceof ApiError ? error.message : "Falha ao verificar a saúde das ferramentas"}
        </p>
      ) : !health ? (
        <p className="text-sm text-muted">Verificando…</p>
      ) : (
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {health.map((h) => {
            const meta = scannerMeta(h.scanner);
            return (
              <li
                key={h.scanner}
                className="flex items-center justify-between gap-2 rounded-md border border-surface-border px-3 py-2"
              >
                <span className="truncate text-sm text-foreground" title={h.message}>
                  {meta.name}
                </span>
                <Badge tone={h.healthy ? "success" : "danger"}>{h.healthy ? "No ar" : "Fora do ar"}</Badge>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
