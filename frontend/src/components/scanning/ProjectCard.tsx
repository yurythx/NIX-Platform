"use client";

import Link from "next/link";
import { useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { SCANNERS } from "@/lib/scanning/scannerRegistry";
import { useTriggerScan } from "@/lib/scanning/useTriggerScan";
import type { Project } from "@/types/api";

import { ProjectFindingHistoryPanel } from "./ProjectFindingHistoryPanel";
import { ScannerPicker } from "./ScannerPicker";

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

// scannerNamesFor: rótulo de exibição de um conjunto de scanners
// selecionados (ex.: "Trivy, Gitleaks"), na mesma ordem/nome do registro
// — nunca a chave crua ("trivy") que o resto da UI já não mostra em
// lugar nenhum.
function scannerNamesFor(selected: Record<string, boolean>): string {
  return SCANNERS.filter((s) => selected[s.key])
    .map((s) => s.name)
    .join(", ");
}

// ProjectCard: Fase 10 (Projeto persistente + upload .zip) — pedido do
// usuário de nunca precisar digitar a URL/re-anexar o .zip de novo pra
// rodar o mesmo alvo outra vez. "Rodar de novo" dispara o mesmo endpoint
// que um scan avulso já usa (useTriggerScan, com projectId em vez de
// target — ver CreateScan/createScanRequest.ProjectID no backend), nunca
// um caminho paralelo.
//
// § Unificação com TriggerScanForm (auditoria 2026-08): antes, "Rodar de
// novo" era um botão único que disparava com uma lista de scanners
// ESCONDIDA (a do último scan, ou só "trivy" na primeira vez) — na
// prática, a primeira execução de qualquer projeto rodava só Trivy, sem
// nenhuma UI pra perceber isso ou escolher outra coisa, bem diferente do
// scan avulso (TriggerScanForm), que sempre deixa escolher livremente. A
// seleção atual (`selected`) começa pré-marcada com o último conjunto
// usado (ou o default, na primeira vez) e fica sempre visível como texto
// — "Rodar de novo" já mostra COM QUAIS scanners vai rodar antes de
// clicar; "Alterar scanners" expande a mesma grade (ScannerPicker) que o
// scan avulso usa, pra quem quiser mudar antes de disparar. Um clique
// continua dando o mesmo resultado rápido de antes; a diferença é que a
// escolha agora é visível e editável, nunca escondida.
export function ProjectCard({ project }: { project: Project }) {
  const initialScanners = project.last_scan?.requested_scanners?.length
    ? project.last_scan.requested_scanners
    : DEFAULT_SCANNERS;
  const [selected, setSelected] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(initialScanners.map((key) => [key, true])),
  );
  const [pickerOpen, setPickerOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const { trigger, submitting, jobId } = useTriggerScan();

  // OWASP ZAP ataca uma URL de serviço vivo, nunca um repositório git nem
  // um .zip — um Project SALVO é sempre um dos dois (git ou upload),
  // nunca um serviço vivo, então ZAP nunca faz sentido aqui. SonarQube
  // exige um `git clone` (não implementa domain.LocalScanner) — some
  // também, mas só pra um projeto de UPLOAD, onde não há URL nenhuma pra
  // clonar (mesma checagem que createScanJob já faz no backend,
  // antecipada aqui pra nunca deixar escolher algo que o servidor vai
  // rejeitar).
  const excludeKeys = project.source_type === "upload" ? ["zap", "sonarqube"] : ["zap"];

  function toggle(key: string) {
    setSelected((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function runAgain() {
    const scanners = SCANNERS.filter((s) => selected[s.key]).map((s) => s.key);
    if (scanners.length === 0) return;
    await trigger({ scanners, projectId: project.id });
  }

  const scannerCount = Object.values(selected).filter(Boolean).length;

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

        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Button
              size="sm"
              variant="secondary"
              loading={submitting}
              disabled={scannerCount === 0}
              onClick={runAgain}
            >
              Rodar de novo
            </Button>
            <span className="text-xs text-muted">
              {scannerCount > 0 ? `com ${scannerNamesFor(selected)}` : "nenhum scanner selecionado"}
            </span>
            <button
              type="button"
              onClick={() => setPickerOpen((open) => !open)}
              className="text-sm text-primary hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
            >
              {pickerOpen ? "Ocultar scanners ←" : "Alterar scanners"}
            </button>
          </div>

          {pickerOpen && (
            <div className="rounded-lg border border-surface-border bg-black/5 p-3 dark:bg-white/5">
              <ScannerPicker selected={selected} onToggle={toggle} excludeKeys={excludeKeys} />
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
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
          {/* Histórico deduplicado (Fase 12) — só faz sentido depois de
              pelo menos um scan; buscado sob demanda (ver
              ProjectFindingHistoryPanel), nunca no carregamento de
              /seguranca. */}
          {project.last_scan && (
            <button
              type="button"
              onClick={() => setHistoryOpen((open) => !open)}
              className="text-sm text-primary hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
            >
              {historyOpen ? "Ocultar histórico ←" : "Ver histórico →"}
            </button>
          )}
        </div>

        {historyOpen && (
          <div className="border-t border-surface-border pt-3">
            <ProjectFindingHistoryPanel projectId={project.id} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
