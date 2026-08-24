import Link from "next/link";
import { notFound } from "next/navigation";

import { ScanDetailLive } from "@/components/scanning/ScanDetailLive";
import { ErrorState } from "@/components/ui/ErrorState";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { ScanFinding, ScanStatus } from "@/types/api";

// Página de detalhe de UM scan — pedido do usuário: "quero os resultados
// separados por scan". Antes desta rota existir, /seguranca só mostrava
// um feed de achados de TODOS os scans misturados, sem link nenhum de
// volta pra "qual execução gerou isso" nem pra progresso em andamento.
// Cada disparo (TriggerScanForm) e cada entrada da listagem de
// /seguranca (ScanList) leva pra cá, sempre com o mesmo job_id que a UI
// já usa desde a criação — GET .../scans/{scanID} é o mesmo endpoint que
// GetScanStatus (backend) e useScanStatusPolling (frontend) já usam em
// outros lugares, nenhum formato novo.
export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;

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

  let findings: ScanFinding[] = [];
  try {
    const res = await serverApiGet<ScanFinding[]>(`v1/scanning/scans/${scanId}/findings`);
    findings = res.data;
  } catch {
    // Achados são secundários aqui — o status do scan já carregou com
    // sucesso; uma falha só nesta segunda busca não deveria impedir a
    // página inteira de renderizar (ScanDetailLive tenta de novo assim
    // que o scan terminar, se ainda estiver em andamento).
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href="/seguranca" className="text-sm text-blue-600 hover:underline dark:text-blue-400">
          ← Todos os scans
        </Link>
        <h1 className="mt-1 break-all text-xl font-semibold">{status.target}</h1>
        <p className="text-sm text-muted">
          Disparado em {new Date(status.created_at).toLocaleString()} — {(status.requested_scanners ?? []).join(", ")}
        </p>
      </div>

      <ScanDetailLive jobId={scanId} initialStatus={status} initialFindings={findings} />
    </div>
  );
}
