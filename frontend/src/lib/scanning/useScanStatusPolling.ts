"use client";

import { useState } from "react";

import { useApiQuery } from "@/lib/api/swr";
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
//
// Implementado sobre useSWR (§ auditoria 2026-08) em vez de
// setTimeout/useState manual: refreshInterval é a mesma ideia do loop
// poll() de antes, só que o SWR cuida de cancelar/reagendar sozinho (sem
// o cancelledRef manual). pollCount substitui o `attempt` local do loop
// original — precisa ser state, não ref: o eslint-plugin-react-hooks
// desta versão do Next (ver AGENTS.md) proíbe tanto ler/escrever
// ref.current durante a renderização quanto chamar setState
// incondicionalmente dentro de um useEffect só pra resetar em resposta a
// uma prop mudando. O jeito aceito pelas duas regras ao mesmo tempo é
// resetar o state DURANTE a própria renderização, comparando jobId com o
// valor rastreado do render anterior (mesmo padrão documentado em
// react.dev/reference/react/useState#storing-information-from-previous-renders) —
// React re-renderiza imediatamente antes de pintar, sem o ciclo extra
// que um useEffect teria.
export function useScanStatusPolling(jobId: string | null, initial: ScanStatus | null = null) {
  const alreadyTerminal = initial !== null && TERMINAL_STATUSES.has(initial.status);

  const [pollCount, setPollCount] = useState(0);
  const [trackedJobId, setTrackedJobId] = useState(jobId);
  if (jobId !== trackedJobId) {
    setTrackedJobId(jobId);
    setPollCount(0);
  }

  const { data } = useApiQuery<ScanStatus>(jobId && !alreadyTerminal ? `v1/scanning/scans/${jobId}` : null, {
    fallbackData: initial ?? undefined,
    // Uma falha ao CONSULTAR o status (rede, sessão expirada) não é o
    // scan tendo falhado — só para de acompanhar, o job continua rodando
    // no worker normalmente (mesmo comportamento do catch{} original).
    shouldRetryOnError: false,
    refreshInterval: (latestData) => {
      if (!latestData || TERMINAL_STATUSES.has(latestData.status)) return 0;
      if (pollCount >= MAX_POLLS) return 0;
      setPollCount((c) => c + 1);
      return POLL_INTERVAL_MS;
    },
  });

  const status = data ?? initial;
  const polling = jobId !== null && !alreadyTerminal && !!status && !TERMINAL_STATUSES.has(status.status) && pollCount < MAX_POLLS;

  return { status, polling };
}
