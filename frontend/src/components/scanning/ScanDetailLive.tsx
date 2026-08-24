"use client";

import { useEffect, useRef, useState } from "react";

import { apiClient } from "@/lib/api/client";
import { useScanStatusPolling } from "@/lib/scanning/useScanStatusPolling";
import type { ScanFinding, ScanPackage, ScanStatus } from "@/types/api";

import { PackageInventoryTable } from "./PackageInventoryTable";
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
  initialPackages,
}: {
  jobId: string;
  initialStatus: ScanStatus;
  initialFindings: ScanFinding[];
  initialPackages: ScanPackage[];
}) {
  const { status, polling } = useScanStatusPolling(jobId, initialStatus);
  const [findings, setFindings] = useState(initialFindings);
  const [packages, setPackages] = useState(initialPackages);
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

    // packages (Fase 11 — Syft): mesmo refetch best-effort de findings
    // acima, pro caso de o Syft só terminar depois da página já aberta.
    apiClient
      .get<ScanPackage[]>(`v1/scanning/scans/${jobId}/packages`)
      .then(({ data }) => setPackages(data))
      .catch(() => {});
  }, [status, jobId]);

  // A aba de inventário só aparece quando este scan de fato pediu o Syft
  // — um scan que nunca rodou Syft não deveria mostrar uma seção vazia
  // "Inventário" só pra dizer "nada aqui".
  const ranSyft = (status?.requested_scanners ?? []).includes("syft");

  return (
    <div className="flex flex-col gap-6">
      {status && <ScanProgress status={status} polling={polling} />}
      {status && (
        <div>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
            Achados por ferramenta
          </h2>
          <ToolFindingsCards scanId={jobId} status={status} findings={findings} />
        </div>
      )}
      {ranSyft && (
        <div>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
            Inventário (SBOM)
          </h2>
          <PackageInventoryTable packages={packages} />
        </div>
      )}
    </div>
  );
}
