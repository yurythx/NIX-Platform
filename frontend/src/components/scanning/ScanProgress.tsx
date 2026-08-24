"use client";

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import type { ScanStatus, ScannerRun } from "@/types/api";

// Painel visual do progresso de UM scan — pedido do usuário: "um painel
// visual dos testes rodando... quero saber qual teste está rodando,
// quanto falta pra acabar... métricas em tempo real". Usado tanto pelo
// TriggerScanForm (logo depois de disparar) quanto pela página de
// detalhe de um scan (/seguranca/[scanId]) — os dois fazem polling de
// GET /api/v1/scanning/scans/{id} e passam o ScanStatus mais recente
// aqui; este componente é só apresentação, nenhum fetch próprio.

const STATUS_LABEL: Record<string, string> = {
  queued: "Na fila",
  processing: "Rodando",
  completed: "Concluído",
  failed: "Tentando de novo (falhou, será reprocessado)",
  dead_letter: "Falhou definitivamente",
};

const STATUS_TONE: Record<string, "neutral" | "success" | "danger" | "warning" | "info"> = {
  queued: "neutral",
  processing: "info",
  completed: "success",
  failed: "warning",
  dead_letter: "danger",
};

type ScannerUIStatus = "pending" | "running" | "succeeded" | "failed";

const SCANNER_STATUS_LABEL: Record<ScannerUIStatus, string> = {
  pending: "Na fila",
  running: "Rodando…",
  succeeded: "Concluído",
  failed: "Falhou",
};

interface MergedRow {
  scanner: string;
  uiStatus: ScannerUIStatus;
  run?: ScannerRun;
}

// mergeScannerRows junta requested_scanners (a lista pedida, sempre
// completa desde o disparo) com scanner_runs (só tem entrada pra quem já
// COMEÇOU a rodar) — um scanner pedido sem entrada em scanner_runs ainda
// não começou, e aparece como "pending" aqui em vez de simplesmente
// desaparecer da lista.
function mergeScannerRows(status: ScanStatus): MergedRow[] {
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

function formatElapsed(ms: number): string {
  if (ms < 1000) return "menos de 1s";
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${seconds}s`;
  return `${minutes}min ${seconds}s`;
}

export function ScanProgress({ status, polling }: { status: ScanStatus; polling: boolean }) {
  const rows = mergeScannerRows(status);
  const requestedScanners = status.requested_scanners ?? [];
  const failedScanners = status.failed_scanners ?? [];
  const succeededScanners = status.succeeded_scanners ?? [];
  const succeededCount = succeededScanners.length;
  const totalFindings = (status.scanner_runs ?? []).reduce((sum, r) => sum + (r.findings_count ?? 0), 0);

  // "Tempo decorrido" precisa de um relógio (Date.now()) — chamar isso
  // direto no corpo do componente violaria a regra de pureza de render
  // (o resultado mudaria a cada re-render sem nenhuma prop/estado ter
  // mudado). Em vez disso, um estado `now` que só o próprio efeito
  // atualiza a cada segundo — e só enquanto o scan ainda não terminou,
  // pra não ficar tiquetaqueando pra sempre num scan já concluído.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (status.finished_at) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [status.finished_at]);

  const startedAtMs = status.started_at ? new Date(status.started_at).getTime() : new Date(status.created_at).getTime();
  const endMs = status.finished_at ? new Date(status.finished_at).getTime() : now;
  const elapsedMs = Math.max(0, endMs - startedAtMs);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[status.status] ?? "neutral"}>{STATUS_LABEL[status.status] ?? status.status}</Badge>
        {polling && <span className="text-xs text-muted">atualizando automaticamente…</span>}
        <span className="text-xs text-muted">job {status.job_id.slice(0, 8)}</span>
      </div>

      {/* Barra de progresso + porcentagem — pedido explícito do usuário. */}
      <div>
        <div className="mb-1 flex items-center justify-between text-xs text-muted">
          <span>
            {rows.filter((r) => r.uiStatus === "succeeded" || r.uiStatus === "failed").length} de {rows.length}{" "}
            scanners concluídos
          </span>
          <span>{status.progress_percent}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-black/10 dark:bg-white/10">
          <div
            className="h-full rounded-full bg-blue-500 transition-all duration-500"
            style={{ width: `${status.progress_percent}%` }}
          />
        </div>
      </div>

      {/* Métricas simples, em tempo real por vir do polling — tempo
          decorrido, achados encontrados até agora, quantos scanners
          concluíram com sucesso. */}
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted">
        <span>
          Tempo decorrido: <span className="text-foreground">{formatElapsed(elapsedMs)}</span>
        </span>
        <span>
          Achados até agora: <span className="text-foreground">{totalFindings}</span>
        </span>
        <span>
          Sucesso: <span className="text-foreground">{succeededCount}</span> / {requestedScanners.length}
        </span>
      </div>

      {/* Um scanner por linha: qual está rodando agora, qual já terminou
          (com duração e contagem de achados), qual ainda nem começou. */}
      <ul className="flex flex-col divide-y divide-black/5 rounded-md border border-black/10 dark:divide-white/5 dark:border-white/10">
        {rows.map((row) => (
          <li key={row.scanner} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
            <div className="flex items-center gap-2">
              {row.uiStatus === "running" ? (
                <Spinner label={`${row.scanner} rodando`} />
              ) : (
                <Badge
                  tone={
                    row.uiStatus === "succeeded" ? "success" : row.uiStatus === "failed" ? "danger" : "neutral"
                  }
                >
                  {SCANNER_STATUS_LABEL[row.uiStatus]}
                </Badge>
              )}
              <span className="font-medium text-foreground">{row.scanner}</span>
            </div>
            <div className="text-xs text-muted">
              {row.run?.duration_ms != null && <span>{formatElapsed(row.run.duration_ms)}</span>}
              {row.run?.findings_count != null && (
                <span className="ml-2">{row.run.findings_count} achado(s)</span>
              )}
            </div>
          </li>
        ))}
      </ul>

      {/* Scanners que falharam: qual ferramenta, que tipo de erro, e como
          corrigir — o pedido original de separar erros por tipo/tool. */}
      {failedScanners.length > 0 && (
        <div className="flex flex-col gap-3">
          <span className="text-sm text-muted">
            {failedScanners.length === 1 ? "1 scanner falhou:" : `${failedScanners.length} scanners falharam:`}
          </span>
          {failedScanners.map((failure, i) => (
            <div
              key={`${failure.scanner}-${i}`}
              className="flex flex-col gap-1 rounded-md border border-red-200 bg-red-50 p-3 text-sm dark:border-red-500/20 dark:bg-red-500/10"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-foreground">{failure.scanner || "desconhecido"}</span>
                <Badge tone="danger">{failure.code || "ERRO"}</Badge>
              </div>
              <p className="text-muted">{failure.message}</p>
              <p>
                <span className="font-medium text-foreground">Como corrigir: </span>
                {failure.hint}
              </p>
            </div>
          ))}
        </div>
      )}

      {succeededScanners.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted">Concluído com sucesso:</span>
          {succeededScanners.map((name) => (
            <Badge key={name} tone="success">
              {name}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
