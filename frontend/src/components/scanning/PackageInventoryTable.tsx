import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import type { ScanPackage } from "@/types/api";

// PackageInventoryTable: aba "Inventário" de um scan (Fase 11 — Syft, ver
// docs/roadmap-secops-orchestrator.md). Ao contrário de FindingsTable, não
// tem Dialog de detalhe nenhum — um pacote não é um achado acionável, só
// uma linha do inventário (nome/versão/tipo/licença), então a própria
// linha da tabela já é a informação completa.
export function PackageInventoryTable({ packages }: { packages: ScanPackage[] }) {
  if (packages.length === 0) {
    return (
      <EmptyState
        title="Nenhum pacote no inventário"
        description="Este scan não rodou o Syft, ou o Syft não encontrou nenhum pacote/dependência neste alvo."
      />
    );
  }

  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableHeaderCell>Pacote</TableHeaderCell>
          <TableHeaderCell>Versão</TableHeaderCell>
          <TableHeaderCell>Tipo</TableHeaderCell>
          <TableHeaderCell>Licença</TableHeaderCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {packages.map((pkg, i) => (
          <TableRow key={`${pkg.name}@${pkg.version}-${i}`}>
            <TableCell className="font-medium text-foreground">{pkg.name}</TableCell>
            <TableCell className="text-muted">{pkg.version || "—"}</TableCell>
            <TableCell className="text-muted">{pkg.type || "—"}</TableCell>
            <TableCell className="text-muted">{pkg.license || "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
