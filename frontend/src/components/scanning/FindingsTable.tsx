"use client";

import Link from "next/link";
import { useState, type KeyboardEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { useToast } from "@/components/notifications/ToastProvider";
import { buildAIPrompt } from "@/lib/scanning/aiPrompt";
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
  const { showToast } = useToast();

  async function copyAIPrompt(finding: ScanFinding) {
    try {
      await navigator.clipboard.writeText(buildAIPrompt(finding));
      showToast({ title: "Prompt copiado", description: "Cole numa IA de sua preferência.", tone: "info" });
    } catch {
      showToast({ title: "Não foi possível copiar", tone: "danger" });
    }
  }

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
              className="cursor-pointer hover:bg-black/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary dark:hover:bg-white/5"
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
            {/* Dados da ferramenta — pedido explícito do usuário: "quero
                que esse detalhe tenha os dados da ferramenta". Nome de
                exibição (não o slug "sonarqube" que já aparece na
                tabela) + um link pra abrir esse achado (ou pelo menos a
                regra/CVE por trás dele) na própria ferramenta, quando o
                backend consegue montar um (ver toolLink no backend —
                nem toda ferramenta/achado permite, então o link some em
                vez de aparecer quebrado). */}
            <div className="flex flex-wrap items-center gap-2 rounded-md bg-black/5 p-2 dark:bg-white/5">
              <span className="font-medium text-foreground">{selected.tool?.name ?? selected.scanner}</span>
              {selected.tool?.url && (
                <a
                  href={selected.tool.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  Abrir na ferramenta →
                </a>
              )}
            </div>
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
            {/* Trecho do código (Fase 12) — pedido implícito de "ver o
                código da vulnerabilidade sem abrir o repositório", já que
                esta plataforma nunca mantém um checkout persistente pra
                navegar livremente (ver docs/roadmap-secops-orchestrator.md).
                Achado sem snippet (ferramenta sem linha específica, ou
                achado de antes desta fase) simplesmente omite esta seção,
                nunca mostra um bloco vazio. */}
            {selected.snippet && (
              <div>
                <div className="font-medium text-foreground">Trecho do código</div>
                <SnippetBlock snippet={selected.snippet} highlightLine={selected.line} />
              </div>
            )}
            <div>
              <div className="font-medium text-foreground">Como corrigir</div>
              <p className="text-muted">{remediationFor(selected)}</p>
            </div>
            {/* "Copiar prompt pra IA" (Fase 13) — monta o mesmo markdown
                do bloco "Como corrigir" acima + os dados da ferramenta/
                trecho de código, pronto pra colar numa IA de preferência
                do usuário. navigator.clipboard.writeText, nenhuma
                dependência nova. */}
            <div>
              <Button size="sm" variant="secondary" onClick={() => copyAIPrompt(selected)}>
                Copiar prompt pra IA
              </Button>
            </div>
            <div className="text-xs text-muted">
              Encontrado em {new Date(selected.created_at).toLocaleString()}
            </div>
            {showScanLink && (
              <Link
                href={`/seguranca/${selected.scan_id}`}
                className="text-primary hover:underline"
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

// SnippetBlock renderiza o snippet capturado pelo backend (Fase 12) —
// cada linha vem prefixada com o número REAL do arquivo, ex. "10: foo()"
// (ver captureSnippet no backend, git_clone.go), nunca a posição dentro
// do snippet: a linha do achado nem sempre é a primeira/central (perto
// do início/fim do arquivo, o contexto fica truncado assimetricamente).
// Faz o parsing inverso desse prefixo só pra decidir qual linha destacar
// como "a do achado" — o texto exibido continua vindo do backend, nunca
// reformatado.
const SNIPPET_LINE_PATTERN = /^(\d+): (.*)$/;

function SnippetBlock({ snippet, highlightLine }: { snippet: string; highlightLine: number }) {
  const lines = snippet.split("\n");
  return (
    <pre className="overflow-x-auto rounded-md border border-surface-border bg-black/5 p-3 text-xs dark:bg-white/5">
      <code>
        {lines.map((raw, i) => {
          const match = raw.match(SNIPPET_LINE_PATTERN);
          const lineNumber = match ? Number(match[1]) : null;
          const content = match ? match[2] : raw;
          const isTarget = lineNumber === highlightLine;
          return (
            <div
              key={i}
              className={`flex gap-3 px-1 ${isTarget ? "bg-danger/10 text-foreground" : "text-muted"}`}
            >
              <span className="w-8 shrink-0 select-none text-right opacity-60">{lineNumber ?? ""}</span>
              <span className="whitespace-pre">{content}</span>
            </div>
          );
        })}
      </code>
    </pre>
  );
}
