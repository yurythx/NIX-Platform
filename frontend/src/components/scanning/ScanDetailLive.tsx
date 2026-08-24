"use client";

import { useEffect, useRef, useState } from "react";

import { apiClient } from "@/lib/api/client";
import { useScanStatusPolling } from "@/lib/scanning/useScanStatusPolling";
import type { ScanFinding, ScanStatus } from "@/types/api";

import { ScanProgress } from "./ScanProgress";
import { ToolFindingsCards } from "./ToolFindingsCards";

const TERMINAL_STATUSES = new Set(["completed", "dead_letter"]);

// ScanDetailLive é o miolo client-side de /seguranca/[scanId]: acompanha
// o progresso via polling (useScanStatusPolling) e, quando o scan TERMINA
// de verdade enquanto a página já estava aberta (diferente de carregar a
// página já com um scan antigo, já terminado — refetchedRef parte de
// true nesse caso), busca os achados de novo — sem isso, achados
// descobertos DEPOIS do carregamento inicial da página só apareceriam
// depois de um F5 manual.
export function ScanDetailLive({
  jobId,
  initialStatus,
  initialFindings,
}: {
  jobId: string;
  initialStatus: ScanStatus;
  initialFindings: ScanFinding[];
}) {
  const { status, polling } = useScanStatusPolling(jobId, initialStatus);
  const [findings, setFindings] = useState(initialFindings);
  const refetchedRef = useRef(TERMINAL_STATUSES.has(initialStatus.status));

  useEffect(() => {
    if (!status) return;
    if (!TERMINAL_STATUSES.has(status.status)) return;
    if (refetchedRef.current) return;
    refetchedRef.current = true;

    apiClient
      .get<ScanFinding[]>(`v1/scanning/scans/${jobId}/findings`)
      .then(({ data }) => setFindings(data))
      .catch(() => {
        // Best-effort: se a rebusca falhar, os achados iniciais (talvez
        // incompletos) continuam visíveis em vez de sumir da tela.
      });
  }, [status, jobId]);

  return (
    <div className="flex flex-col gap-6">
      {status && <ScanProgress status={status} polling={polling} />}
      {status && (
        <div>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted">
            Achados por ferramenta
          </h2>
          <ToolFindingsCards scanId={jobId} status={status} findings={findings} />
        </div>
      )}
    </div>
  );
}
