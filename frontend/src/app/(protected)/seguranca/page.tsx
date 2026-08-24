import { ErrorState } from "@/components/ui/ErrorState";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { SeverityBadge } from "@/components/scanning/SeverityBadge";
import { TriggerScanForm } from "@/components/scanning/TriggerScanForm";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { ScanFinding } from "@/types/api";

// Segurança (Fase 9 do roadmap de segurança —
// docs/roadmap-secops-orchestrator.md): "achados recentes por
// severidade", reaproveitando o padrão de Server Component + Table já em
// uso no resto do dashboard — não um design novo. Busca
// GET /api/v1/scanning/findings (o feed entre TODOS os scans, não
// escopado a um scan_id — GET .../scans/{scanID}/findings continua
// existindo pra quem já sabe o scan_id de um job específico).
//
// TriggerScanForm (Client Component, abaixo) veio depois da Fase 9
// original — perguntado explicitamente pelo usuário como disparar um
// scan e "mostrar pra aplicação onde atacar" (o alvo do ZAP), já que a
// primeira versão desta página só listava achados. Server Component pai
// renderizando um Client Component filho é o padrão normal do App
// Router — a busca de achados continua acontecendo no servidor.
export default async function SegurancaPage() {
  let findings: ScanFinding[] | null = null;
  let errorMessage: string | null = null;
  try {
    const { data } = await serverApiGet<ScanFinding[]>("v1/scanning/findings?limit=100");
    findings = data;
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar achados";
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Segurança</h1>
        <p className="text-sm text-muted">
          Achados mais graves e recentes entre todas as execuções de scan (Trivy, Semgrep,
          SonarQube, OWASP ZAP) — os mais críticos primeiro.
        </p>
      </div>

      <TriggerScanForm />

      {errorMessage && <ErrorState message={errorMessage} />}

      {findings && findings.length === 0 && (
        <EmptyState
          title="Nenhum achado ainda"
          description="Nenhum scan rodou até agora, ou nenhum problema foi encontrado nos scans mais recentes."
        />
      )}

      {findings && findings.length > 0 && (
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
              <TableRow key={finding.id}>
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
      )}
    </div>
  );
}
