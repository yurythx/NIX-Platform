"use client";

import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { ApiError, useApiQuery } from "@/lib/api/swr";
import type { ProjectFindingHistory } from "@/types/api";

import { SeverityBadge } from "./SeverityBadge";
import { TriageControls } from "./TriageControls";

// ProjectFindingHistoryPanel: Fase 12 (deduplicação por fingerprint) —
// pedido literal do roadmap: "achado X apareceu pela primeira vez no scan
// de 12/08, ainda presente no scan de 20/08" em vez de listar a mesma
// vulnerabilidade repetida uma vez por re-scan. Busca sob demanda (só
// quando o card expande — ver ProjectCard), nunca no carregamento inicial
// de /seguranca: a maioria dos projetos não vai ter esse painel aberto na
// maior parte do tempo.
//
// useApiQuery (SWR, § auditoria 2026-08) em vez de useEffect+useState
// manual: reabrir o mesmo card duas vezes na mesma sessão reaproveita o
// cache em vez de refazer a requisição, e o dedupe automático cobre o
// caso de dois cards do mesmo projeto abertos quase juntos.
//
// § Triagem (Fase 14 — Maturidade de AppSec): até aqui, "ainda presente"
// era o único sinal — nenhum jeito de um humano dizer "isto é falso
// positivo" ou "risco aceito por ora" sem o mesmo achado voltar a
// aparecer como pendente em todo re-scan seguinte. A UI de triagem em si
// vive em TriageControls (revisão de exibição de resultados — extraído
// daqui pra ser reaproveitado também no painel mestre-detalhe de
// FindingsTable, quando ele conhece um projectId); este painel continua
// sendo o único lugar que busca ProjectFindingHistory (o dado
// deduplicado por fingerprint que a triagem é escopada a).
export function ProjectFindingHistoryPanel({ projectId }: { projectId: string }) {
  const {
    data: history,
    error: swrError,
    mutate,
  } = useApiQuery<ProjectFindingHistory[]>(`v1/scanning/projects/${projectId}/findings-history`);

  if (swrError) {
    return (
      <p className="text-sm text-danger">
        {swrError instanceof ApiError ? swrError.message : "Falha ao carregar o histórico"}
      </p>
    );
  }
  if (history === undefined) {
    return <p className="text-sm text-muted">Carregando histórico…</p>;
  }
  if (history.length === 0) {
    return (
      <EmptyState
        title="Nenhum achado no histórico"
        description="Nenhum scan deste projeto encontrou problema algum até agora."
      />
    );
  }

  return (
    <>
      <div className="mb-2 flex justify-end">
        <a
          href={`/api/backend/v1/scanning/projects/${projectId}/findings-history.csv`}
          className="text-sm text-primary hover:underline"
        >
          Exportar CSV →
        </a>
      </div>
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell>Severidade</TableHeaderCell>
            <TableHeaderCell>Achado</TableHeaderCell>
            <TableHeaderCell>Primeira vez</TableHeaderCell>
            <TableHeaderCell>Última vez</TableHeaderCell>
            <TableHeaderCell>Scans</TableHeaderCell>
            <TableHeaderCell>Status</TableHeaderCell>
            <TableHeaderCell>Triagem</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {history.map((h) => (
            <TableRow key={h.fingerprint}>
              <TableCell>
                <SeverityBadge severity={h.severity} />
              </TableCell>
              <TableCell>
                <div className="font-medium text-foreground">{h.tool.name}</div>
                <div className="max-w-md truncate text-muted" title={h.description}>
                  {h.description}
                </div>
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted">
                {new Date(h.first_seen_at).toLocaleDateString()}
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted">
                {new Date(h.last_seen_at).toLocaleDateString()}
              </TableCell>
              <TableCell className="text-muted">{h.scan_count}</TableCell>
              <TableCell>
                <Badge tone={h.still_present ? "danger" : "success"}>
                  {h.still_present ? "Ainda presente" : "Corrigido"}
                </Badge>
              </TableCell>
              <TableCell>
                <TriageControls
                  projectId={projectId}
                  fingerprint={h.fingerprint}
                  status={h.triage_status}
                  reason={h.triage_reason}
                  expiresAt={h.triage_expires_at}
                  expired={h.triage_expired}
                  onChanged={mutate}
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  );
}
