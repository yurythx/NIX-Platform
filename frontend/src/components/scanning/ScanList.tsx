import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { scannerMeta } from "@/lib/scanning/scannerRegistry";
import type { ScanStatus } from "@/types/api";

// ScanList: pedido do usuário de "resultados separados por scan" — cada
// execução como sua própria entrada (com seu próprio link pra
// /seguranca/[scanId]), em vez de só o feed de achados de
// FindingsTable/ListRecentFindings, que mistura todo scan junto. Não é
// Client Component: só links e badges, nenhum estado — o polling de
// progresso ao vivo é responsabilidade da página de detalhe de cada
// scan, não desta lista.
//
// § Revisão de exibição de resultados (pedido do usuário: "uma tela
// inicial... com os scans que já foram feitos, quais ferramentas foram
// usadas... e quais erros e warnings foram achados"): ScanList virou a
// tela inicial de /seguranca, então ganhou o nome de exibição de cada
// ferramenta (não mais o slug cru) e a contagem de erro/warning —
// "erro" = CRITICAL+HIGH, "warning" = MEDIUM+LOW, a MESMA divisão que
// ToolFindingsCards já usa (nunca uma segunda convenção de severidade
// só pra esta lista).
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

const ERROR_SEVERITIES = ["CRITICAL", "HIGH"] as const;
const WARNING_SEVERITIES = ["MEDIUM", "LOW"] as const;

export function ScanList({ scans }: { scans: ScanStatus[] }) {
  if (scans.length === 0) {
    return (
      <EmptyState
        title="Nenhum scan disparado ainda"
        description="Clique em “Novo scan” pra disparar o primeiro."
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
        const counts = s.findings_by_severity ?? {};
        const errorCount = ERROR_SEVERITIES.reduce((sum, sev) => sum + (counts[sev] ?? 0), 0);
        const warningCount = WARNING_SEVERITIES.reduce((sum, sev) => sum + (counts[sev] ?? 0), 0);

        return (
          <li key={s.job_id}>
            <Link
              href={`/seguranca/${s.job_id}`}
              className="flex flex-col gap-2 p-4 hover:bg-black/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary dark:hover:bg-white/5 sm:flex-row sm:items-center sm:justify-between sm:gap-4"
            >
              <div className="min-w-0">
                <div className="truncate font-medium text-foreground" title={s.target}>
                  {s.target}
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {requestedScanners.map((key) => (
                    <span
                      key={key}
                      className="rounded-full border border-surface-border px-2 py-0.5 text-xs text-muted"
                    >
                      {scannerMeta(key).name}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-2 text-xs text-muted">
                {s.status !== "completed" && s.status !== "dead_letter" && (
                  <span>{s.progress_percent}%</span>
                )}
                {errorCount > 0 && <Badge tone="danger">{errorCount} erro(s)</Badge>}
                {warningCount > 0 && <Badge tone="warning">{warningCount} warning(s)</Badge>}
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
