import Link from "next/link";
import { notFound } from "next/navigation";

import { FindingsTable } from "@/components/scanning/FindingsTable";
import { ScannerFailureCard } from "@/components/scanning/ScannerFailureCard";
import { ErrorState } from "@/components/ui/ErrorState";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import { scannerMeta } from "@/lib/scanning/scannerRegistry";
import type { ScanFinding, ScanStatus } from "@/types/api";

// Página de achados de UMA ferramenta dentro de UM scan — pedido do
// usuário: os cards de /seguranca/[scanId] ("um card com o nome da
// ferramenta... quando clicado abre outra página que lista os erros que
// essa ferramenta achou") levam pra cá. Mesmos dois fetches que
// /seguranca/[scanId] já faz (status do scan + achados) — nenhum
// endpoint novo, só filtra os achados pelo scanner do parâmetro de rota
// e mostra a descrição da ferramenta (mesmo registro que TriggerScanForm
// e ScanProgress já usam) no topo.
export default async function ScannerFindingsPage({
  params,
}: {
  params: Promise<{ scanId: string; scanner: string }>;
}) {
  const { scanId, scanner } = await params;

  let status: ScanStatus;
  try {
    const res = await serverApiGet<ScanStatus>(`v1/scanning/scans/${scanId}`);
    status = res.data;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      notFound();
    }
    return <ErrorState message={err instanceof ApiError ? err.message : "Falha ao carregar o scan"} />;
  }

  let allFindings: ScanFinding[] = [];
  try {
    const res = await serverApiGet<ScanFinding[]>(`v1/scanning/scans/${scanId}/findings`);
    allFindings = res.data;
  } catch {
    // Achados são secundários aqui — o status do scan já carregou com
    // sucesso; uma falha só nesta segunda busca não deveria impedir a
    // página inteira de renderizar.
  }
  const findings = allFindings.filter((f) => f.scanner === scanner);

  // scanner que não faz parte deste scan (nem pedido, nem com achado
  // nenhum) — URL inválida, não um estado legítimo de "zero achados".
  const wasRequested = (status.requested_scanners ?? []).includes(scanner);
  if (!wasRequested && findings.length === 0) {
    notFound();
  }

  const meta = scannerMeta(scanner);
  const failure = (status.failed_scanners ?? []).find((f) => f.scanner === scanner);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href={`/seguranca/${scanId}`} className="text-sm text-blue-600 hover:underline dark:text-blue-400">
          ← Voltar pro scan
        </Link>
        <h1 className="mt-1 text-xl font-semibold">{meta.name}</h1>
        {meta.category && <p className="text-sm text-muted">{meta.category}</p>}
        {meta.description && <p className="mt-2 text-sm text-muted">{meta.description}</p>}
        <p className="mt-1 break-all text-xs text-muted">Alvo: {status.target}</p>
      </div>

      {failure && <ScannerFailureCard failure={failure} />}

      <FindingsTable findings={findings} showScanLink={false} />
    </div>
  );
}
