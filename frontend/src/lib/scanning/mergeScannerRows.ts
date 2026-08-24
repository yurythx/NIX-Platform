import type { ScanStatus, ScannerRun } from "@/types/api";

export type ScannerUIStatus = "pending" | "running" | "succeeded" | "failed";

export interface MergedScannerRow {
  scanner: string;
  uiStatus: ScannerUIStatus;
  run?: ScannerRun;
}

// mergeScannerRows junta requested_scanners (a lista pedida, sempre
// completa desde o disparo) com scanner_runs (só tem entrada pra quem já
// COMEÇOU a rodar) — um scanner pedido sem entrada em scanner_runs ainda
// não começou, e aparece como "pending" aqui em vez de simplesmente
// desaparecer da lista. Compartilhado entre ScanProgress (cards de
// progresso) e ToolFindingsCards (cards de achado por ferramenta) — as
// duas telas nunca podem divergir em "qual scanner está em que estado".
export function mergeScannerRows(status: ScanStatus): MergedScannerRow[] {
  // O backend sempre manda scanner_runs/requested_scanners como listas
  // (nunca omitidas), mas cai aqui defensivamente pra nunca quebrar o
  // render por causa de um payload inesperado.
  const byName = new Map((status.scanner_runs ?? []).map((r) => [r.scanner, r]));
  return (status.requested_scanners ?? []).map((scanner) => {
    const run = byName.get(scanner);
    if (!run) return { scanner, uiStatus: "pending" };
    return { scanner, uiStatus: run.status, run };
  });
}
