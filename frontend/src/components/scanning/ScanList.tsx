import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import type { ScanStatus } from "@/types/api";

// ScanList: pedido do usuário de "resultados separados por scan" — cada
// execução como sua própria entrada (com seu próprio link pra
// /seguranca/[scanId]), em vez de só o feed de achados de
// FindingsTable/ListRecentFindings, que mistura todo scan junto. Não é
// Client Component: só links e badges, nenhum estado — o polling de
// progresso ao vivo é responsabilidade da página de detalhe de cada
// scan, não desta lista.
const STATUS_LABEL: Record<string, string> = {
  queued: "Na fila",
  processing: "Rodando",
  completed: "Concluído",
  failed: "Tentando de novo",
  dead_letter: "Falhou",
};

const STATUS_TONE: Record<string, "neutral" | "success" | "danger" | "warning" | "info"> = {
  queued: "neutral",
  processing: "info",
  completed: "success",
  failed: "warning",
  dead_letter: "danger",
};

export function ScanList({ scans }: { scans: ScanStatus[] }) {
  if (scans.length === 0) {
    return (
      <EmptyState
        title="Nenhum scan disparado ainda"
        description="Use o formulário acima para disparar o primeiro."
      />
    );
  }

  return (
    <ul className="flex flex-col divide-y divide-surface-border rounded-lg border border-surface-border bg-surface">
      {scans.map((s) => {
        // Defensivo: o backend garante requested_scanners/failed_scanners
        // como lista (nunca null, ver transport/dto.go's
        // nonNilStrings), mas alguns jobs de scan de verdade deste
        // ambiente predatam essa garantia — cai aqui pra nunca quebrar o
        // render por causa de um job antigo.
        const requestedScanners = s.requested_scanners ?? [];
        const failedScanners = s.failed_scanners ?? [];
        return (
          <li key={s.job_id}>
            <Link
              href={`/seguranca/${s.job_id}`}
              className="flex flex-col gap-1 p-4 hover:bg-black/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary dark:hover:bg-white/5 sm:flex-row sm:items-center sm:justify-between sm:gap-4"
            >
              <div className="min-w-0">
                <div className="truncate font-medium text-foreground" title={s.target}>
                  {s.target}
                </div>
                <div className="text-xs text-muted">{requestedScanners.join(", ")}</div>
              </div>
              <div className="flex shrink-0 items-center gap-3 text-xs text-muted">
                {s.status !== "completed" && s.status !== "dead_letter" && (
                  <span>{s.progress_percent}%</span>
                )}
                {failedScanners.length > 0 && <Badge tone="danger">{failedScanners.length} falha(s)</Badge>}
                <Badge tone={STATUS_TONE[s.status] ?? "neutral"}>{STATUS_LABEL[s.status] ?? s.status}</Badge>
                <span className="whitespace-nowrap">{new Date(s.created_at).toLocaleString()}</span>
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
