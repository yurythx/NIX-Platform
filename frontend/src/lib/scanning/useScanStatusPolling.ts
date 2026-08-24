"use client";

import { useEffect, useRef, useState } from "react";

import { apiClient } from "@/lib/api/client";
import type { ScanStatus } from "@/types/api";

// "failed" NÃO é terminal aqui — ainda pode virar completed numa nova
// tentativa (ver application.Service.ProcessScanJob no backend), então o
// polling continua. Só completed/dead_letter encerram o acompanhamento.
const TERMINAL_STATUSES = new Set(["completed", "dead_letter"]);

// Um scan pode levar de segundos a minutos (clone + análise) — poll a
// cada 3s por até ~4 minutos antes de desistir de acompanhar (o job
// continua rodando no worker de qualquer forma; só o polling para).
const POLL_INTERVAL_MS = 3000;
const MAX_POLLS = 80;

// useScanStatusPolling faz polling de GET /api/v1/scanning/scans/{jobId}
// até o status virar terminal — compartilhado entre TriggerScanForm
// (logo depois de disparar um scan) e a página de detalhe de um scan
// (/seguranca/[scanId], reaberta mais tarde pra um scan que já pode ter
// terminado, daí o parâmetro `initial`: se já vier terminal via SSR,
// nunca chega a fazer polling nenhum).
export function useScanStatusPolling(jobId: string | null, initial: ScanStatus | null = null) {
  const [status, setStatus] = useState<ScanStatus | null>(initial);
  const [polling, setPolling] = useState(false);
  const cancelledRef = useRef(false);
  const initialRef = useRef(initial);

  useEffect(() => {
    cancelledRef.current = false;
    if (!jobId) return;
    if (initialRef.current && TERMINAL_STATUSES.has(initialRef.current.status)) {
      return () => {
        cancelledRef.current = true;
      };
    }

    let attempt = 0;
    setPolling(true);

    async function poll() {
      if (cancelledRef.current) return;
      try {
        const { data } = await apiClient.get<ScanStatus>(`v1/scanning/scans/${jobId}`);
        if (cancelledRef.current) return;
        setStatus(data);
        attempt += 1;
        if (TERMINAL_STATUSES.has(data.status) || attempt >= MAX_POLLS) {
          setPolling(false);
          return;
        }
        setTimeout(poll, POLL_INTERVAL_MS);
      } catch {
        // Uma falha ao CONSULTAR o status (rede, sessão expirada) não é
        // o scan tendo falhado — só para de acompanhar aqui; o job
        // continua rodando no worker normalmente.
        if (!cancelledRef.current) setPolling(false);
      }
    }

    void poll();

    return () => {
      cancelledRef.current = true;
    };
  }, [jobId]);

  return { status, polling };
}
