"use client";

import Link from "next/link";
import { useState, type KeyboardEvent } from "react";

import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { remediationFor } from "@/lib/scanning/remediation";
import type { ScanFinding } from "@/types/api";

import { SeverityBadge } from "./SeverityBadge";

// FindingsTable: pedido do usuário de "poder clicar [nos achados] de
// forma individual e ver os detalhes de cada erro" — cada linha abre um
// Dialog com o achado por extenso. A tabela em si continua truncando
// descrição/local por espaço (mesmo comportamento de antes desta
// mudança); o Dialog nunca trunca nada, e é onde "como corrigir"
// (remediationFor) aparece por completo, não só no title="" de hover que
// a versão anterior desta tabela usava.
//
// showScanLink liga o Dialog de volta pra página do scan inteiro
// (/seguranca/[scanId]) — só faz sentido na visão AGREGADA de
// /seguranca (achados de todos os scans misturados); a própria página de
// um scan específico já é essa página, então passa showScanLink={false}.
export function FindingsTable({
  findings,
  showScanLink = false,
}: {
  findings: ScanFinding[];
  showScanLink?: boolean;
}) {
  const [selected, setSelected] = useState<ScanFinding | null>(null);

  if (findings.length === 0) {
    return (
      <EmptyState
        title="Nenhum achado ainda"
        description="Nenhum scan rodou até agora, ou nenhum problema foi encontrado nos scans mais recentes."
      />
    );
  }

  function handleRowKeyDown(e: KeyboardEvent<HTMLTableRowElement>, finding: ScanFinding) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setSelected(finding);
    }
  }

  return (
    <>
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell>Severidade</TableHeaderCell>
            <TableHeaderCell>Achado</TableHeaderCell>
            <TableHeaderCell>Categoria OWASP</TableHeaderCell>
            <TableHeaderCell>Scanner</TableHeaderCell>
            <TableHeaderCell>Local</TableHeaderCell>
            <TableHeaderCell>Quando</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {findings.map((finding) => (
            <TableRow
              key={finding.id}
              onClick={() => setSelected(finding)}
              onKeyDown={(e) => handleRowKeyDown(e, finding)}
              role="button"
              tabIndex={0}
              aria-label={`Ver detalhes do achado ${finding.finding_id}`}
              className="cursor-pointer hover:bg-black/5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500 dark:hover:bg-white/5"
            >
              <TableCell>
                <SeverityBadge severity={finding.severity} />
              </TableCell>
              <TableCell>
                <div className="font-medium text-foreground">{finding.finding_id}</div>
                <div className="max-w-md truncate text-muted" title={finding.description}>
                  {finding.description}
                </div>
              </TableCell>
              <TableCell className="text-muted">{finding.owasp_category || "—"}</TableCell>
              <TableCell className="text-muted">{finding.scanner}</TableCell>
              <TableCell className="text-muted">
                {finding.file ? (finding.line > 0 ? `${finding.file}:${finding.line}` : finding.file) : "—"}
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted">
                {new Date(finding.created_at).toLocaleString()}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.finding_id ?? ""}
        description={selected ? `${selected.scanner} · ${selected.severity}` : undefined}
      >
        {selected && (
          <div className="flex max-h-[60vh] flex-col gap-3 overflow-y-auto text-sm">
            <div>
              <div className="font-medium text-foreground">Descrição</div>
              <p className="text-muted">{selected.description}</p>
            </div>
            {selected.owasp_category && (
              <div>
                <div className="font-medium text-foreground">Categoria OWASP</div>
                <p className="text-muted">{selected.owasp_category}</p>
              </div>
            )}
            {selected.file && (
              <div>
                <div className="font-medium text-foreground">Local</div>
                <p className="text-muted">
                  {selected.file}
                  {selected.line > 0 ? `:${selected.line}` : ""}
                </p>
              </div>
            )}
            <div>
              <div className="font-medium text-foreground">Como corrigir</div>
              <p className="text-muted">{remediationFor(selected)}</p>
            </div>
            <div className="text-xs text-muted">
              Encontrado em {new Date(selected.created_at).toLocaleString()}
            </div>
            {showScanLink && (
              <Link
                href={`/seguranca/${selected.scan_id}`}
                className="text-blue-600 hover:underline dark:text-blue-400"
              >
                Ver o scan completo →
              </Link>
            )}
          </div>
        )}
      </Dialog>
    </>
  );
}
