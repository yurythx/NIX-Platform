"use client";

import Link from "next/link";
import { useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Project, TestJobResponse } from "@/types/api";

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

// DEFAULT_SCANNERS é usado só na PRIMEIRA execução de um projeto (nunca
// escaneado ainda, sem last_scan pra reaproveitar) — trivy funciona tanto
// pra projeto git quanto upload (implementa LocalScanner), mesmo default
// que TriggerScanForm já usa pro formulário de scan avulso.
const DEFAULT_SCANNERS = ["trivy"];

// ProjectCard: Fase 10 (Projeto persistente + upload .zip) — pedido do
// usuário de nunca precisar digitar a URL/re-anexar o .zip de novo pra
// rodar o mesmo alvo outra vez. "Rodar de novo" dispara POST
// /api/v1/scanning/scans com project_id preenchido, reaproveitando os
// MESMOS scanners do último scan (ou DEFAULT_SCANNERS, na primeira vez) —
// mesmo endpoint que um scan avulso já usa (ver CreateScan/
// createScanRequest.ProjectID no backend), nunca um caminho paralelo.
export function ProjectCard({ project }: { project: Project }) {
  const { showToast } = useToast();
  const [running, setRunning] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  async function runAgain() {
    const scanners = project.last_scan?.requested_scanners?.length
      ? project.last_scan.requested_scanners
      : DEFAULT_SCANNERS;

    setRunning(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/scanning/scans", {
        scanners,
        project_id: project.id,
      });
      setJobId(data.job_id);
      showToast({
        title: "Scan disparado",
        description: `Job ${data.job_id.slice(0, 8)} — acompanhe em "Scans recentes" ou clique abaixo.`,
        tone: "info",
      });
    } catch (err) {
      showToast({
        title: "Não foi possível disparar o scan",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4 space-y-0">
        <CardTitle className="truncate" title={project.name}>
          {project.name}
        </CardTitle>
        <Badge tone="neutral">{project.source_type === "upload" ? "Upload .zip" : "Git"}</Badge>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {project.source_type === "git" && (
          <div className="truncate text-xs text-muted" title={project.target}>
            {project.target}
          </div>
        )}

        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted">
          <dt>Último scan</dt>
          <dd>
            {project.last_scan ? (
              <Badge tone={STATUS_TONE[project.last_scan.status] ?? "neutral"}>
                {STATUS_LABEL[project.last_scan.status] ?? project.last_scan.status}
              </Badge>
            ) : (
              "Nunca rodado"
            )}
          </dd>
          <dt>Criado em</dt>
          <dd>{new Date(project.created_at).toLocaleString()}</dd>
        </dl>

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" loading={running} onClick={runAgain}>
            Rodar de novo
          </Button>
          {project.last_scan && (
            <Link
              href={`/seguranca/${project.last_scan.job_id}`}
              className="text-sm text-primary hover:underline"
            >
              Ver último scan →
            </Link>
          )}
          {jobId && jobId !== project.last_scan?.job_id && (
            <Link href={`/seguranca/${jobId}`} className="text-sm text-primary hover:underline">
              Ver scan disparado agora →
            </Link>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
