"use client";

import { useState } from "react";

import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { TestJobResponse } from "@/types/api";

interface TriggerScanInput {
  scanners: string[];
  /** Alvo avulso (URL git ou de serviço vivo, pro ZAP) — mutuamente
   * exclusivo com projectId; exatamente um dos dois é esperado. */
  target?: string;
  /** Projeto salvo (Fase 10) — quando presente, o backend resolve o alvo
   * a partir do próprio projeto (CreateProjectScanJob), sem pedir a
   * URL/o .zip de novo. */
  projectId?: string;
}

// useTriggerScan: lógica de disparo de scan (POST /v1/scanning/scans +
// toast de sucesso/erro + job_id resultante) extraída pra cá porque duas
// telas precisam do EXATO mesmo comportamento — TriggerScanForm (alvo
// avulso) e ProjectCard (projeto salvo) — e antes desta extração cada uma
// reimplementava o mesmo try/catch/toast separadamente, já levemente
// divergentes uma da outra. O endpoint é o mesmo dos dois lados
// (createScanRequest aceita target OU project_id, nunca os dois — ver
// CreateScanJob/CreateProjectScanJob no backend); só o corpo enviado
// muda.
export function useTriggerScan() {
  const { showToast } = useToast();
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  async function trigger({ scanners, target, projectId }: TriggerScanInput): Promise<string | null> {
    setSubmitting(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/scanning/scans", {
        scanners,
        ...(projectId ? { project_id: projectId } : { target }),
      });
      showToast({
        title: "Scan disparado",
        description: `Job ${data.job_id.slice(0, 8)} — acompanhando o resultado abaixo.`,
        tone: "info",
      });
      setJobId(data.job_id);
      return data.job_id;
    } catch (err) {
      showToast({
        title: "Não foi possível disparar o scan",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
      return null;
    } finally {
      setSubmitting(false);
    }
  }

  return { trigger, submitting, jobId, setJobId };
}
