"use client";

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { apiClient, ApiError } from "@/lib/api/client";
import type { ProjectFindingHistory } from "@/types/api";

import { SeverityBadge } from "./SeverityBadge";

// ProjectFindingHistoryPanel: Fase 12 (deduplicação por fingerprint) —
// pedido literal do roadmap: "achado X apareceu pela primeira vez no scan
// de 12/08, ainda presente no scan de 20/08" em vez de listar a mesma
// vulnerabilidade repetida uma vez por re-scan. Busca sob demanda (só
// quando o card expande — ver ProjectCard), nunca no carregamento inicial
// de /seguranca: a maioria dos projetos não vai ter esse painel aberto na
// maior parte do tempo.
export function ProjectFindingHistoryPanel({ projectId }: { projectId: string }) {
  const [history, setHistory] = useState<ProjectFindingHistory[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get<ProjectFindingHistory[]>(`v1/scanning/projects/${projectId}/findings-history`)
      .then(({ data }) => {
        if (!cancelled) setHistory(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Falha ao carregar o histórico");
      });
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  if (error) {
    return <p className="text-sm text-danger">{error}</p>;
  }
  if (history === null) {
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
    <Table>
      <TableHead>
        <TableRow>
          <TableHeaderCell>Severidade</TableHeaderCell>
          <TableHeaderCell>Achado</TableHeaderCell>
          <TableHeaderCell>Primeira vez</TableHeaderCell>
          <TableHeaderCell>Última vez</TableHeaderCell>
          <TableHeaderCell>Scans</TableHeaderCell>
          <TableHeaderCell>Status</TableHeaderCell>
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
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
