import { Badge } from "@/components/ui/Badge";
import type { ScannerFailure } from "@/types/api";

// ScannerFailureCard: qual ferramenta encontrou o erro, de que tipo foi
// (Code, a mesma taxonomia de internal/domain/errors.Code do backend) e
// como corrigir (Hint, já em texto pronto — ver
// scanning/transport/dto.go's remediationHint). Extraído de
// ScanProgress.tsx pra ser reaproveitado também na página de achados de
// um scanner específico (/seguranca/[scanId]/[scanner]), onde a mesma
// falha pode fazer sentido aparecer de novo (o scanner falhou = não tem
// achado nenhum pra mostrar ali, só o motivo).
export function ScannerFailureCard({ failure }: { failure: ScannerFailure }) {
  return (
    <div className="flex flex-col gap-1 rounded-xl border border-red-200 bg-red-50 p-3 text-sm dark:border-red-500/20 dark:bg-red-500/10">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-foreground">{failure.scanner || "desconhecido"}</span>
        <Badge tone="danger">{failure.code || "ERRO"}</Badge>
      </div>
      <p className="text-muted">{failure.message}</p>
      <p>
        <span className="font-medium text-foreground">Como corrigir: </span>
        {failure.hint}
      </p>
    </div>
  );
}
