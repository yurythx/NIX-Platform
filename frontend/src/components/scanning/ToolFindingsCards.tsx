import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { mergeScannerRows } from "@/lib/scanning/mergeScannerRows";
import { scannerMeta } from "@/lib/scanning/scannerRegistry";
import type { ScanFinding, ScanStatus } from "@/types/api";

// ToolFindingsCards: pedido do usuário — "quero uma separação em cards
// pra separar cada ferramenta... um card com o nome da ferramenta e
// quando clicado abre outra página que lista os erros que essa
// ferramenta achou... no card mostrar a quantidade de erros e warnings".
// Um card por scanner PEDIDO no scan (não só por scanner com achado —
// um scanner que rodou limpo ainda ganha card, mostrando "0 erros"),
// cada um linkando pra /seguranca/[scanId]/[scanner]. "Erros" =
// CRITICAL+HIGH, "warnings" = MEDIUM+LOW — a mesma escala de severidade
// que SeverityBadge já usa em toda outra tela desta seção, não uma
// categorização nova.
const ERROR_SEVERITIES = new Set(["CRITICAL", "HIGH"]);
const WARNING_SEVERITIES = new Set(["MEDIUM", "LOW"]);

export function ToolFindingsCards({
  scanId,
  status,
  findings,
}: {
  scanId: string;
  status: ScanStatus;
  findings: ScanFinding[];
}) {
  const byScanner = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const list = byScanner.get(f.scanner);
    if (list) list.push(f);
    else byScanner.set(f.scanner, [f]);
  }

  const rows = mergeScannerRows(status);
  // Defensivo: um achado de um scanner que por algum motivo não está em
  // requested_scanners (não deveria acontecer, mas nunca some achado
  // silenciosamente) ainda ganha um card.
  for (const scanner of byScanner.keys()) {
    if (!rows.some((r) => r.scanner === scanner)) {
      rows.push({ scanner, uiStatus: "succeeded" });
    }
  }

  if (rows.length === 0) {
    return null;
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {rows.map((row) => {
        const meta = scannerMeta(row.scanner);
        const list = byScanner.get(row.scanner) ?? [];
        const errors = list.filter((f) => ERROR_SEVERITIES.has(f.severity)).length;
        const warnings = list.filter((f) => WARNING_SEVERITIES.has(f.severity)).length;

        return (
          <Link
            key={row.scanner}
            href={`/seguranca/${scanId}/${row.scanner}`}
            className="flex flex-col gap-2 rounded-xl border border-surface-border bg-surface p-4 transition-colors hover:bg-black/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary dark:hover:bg-white/5"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-foreground">{meta.name}</span>
              {row.uiStatus === "failed" && <Badge tone="danger">Falhou</Badge>}
              {row.uiStatus === "running" && <Badge tone="info">Rodando…</Badge>}
              {row.uiStatus === "pending" && <Badge tone="neutral">Na fila</Badge>}
            </div>
            {meta.category && <div className="text-xs text-muted">{meta.category}</div>}
            <div className="mt-1 flex items-center gap-4 text-sm">
              <span className={errors > 0 ? "font-medium text-danger" : "text-muted"}>
                {errors} erro{errors === 1 ? "" : "s"}
              </span>
              <span className={warnings > 0 ? "font-medium text-amber-800 dark:text-amber-400" : "text-muted"}>
                {warnings} warning{warnings === 1 ? "" : "s"}
              </span>
            </div>
            <div className="text-xs text-primary">
              {list.length === 0 ? "Ver detalhes" : `Ver ${list.length} achado${list.length === 1 ? "" : "s"}`} →
            </div>
          </Link>
        );
      })}
    </div>
  );
}
