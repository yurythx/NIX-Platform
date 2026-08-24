import { Badge } from "@/components/ui/Badge";
import type { ScanSeverity } from "@/types/api";

// Selo de severidade de um achado de scan — reaproveita o Badge genérico
// do kit de UI (§ Fase 9 do roadmap de segurança: "não um design novo").
// CRITICAL e HIGH dividem o mesmo tom "danger": o Badge só tem um tom
// vermelho, e o texto de cada selo ("CRITICAL" vs "HIGH") já diferencia
// os dois — a cor é só um agrupamento grosso, nunca a única pista (mesmo
// princípio de StatusIndicator, que também nunca depende só de cor).
const severityTone: Record<ScanSeverity, "danger" | "warning" | "info"> = {
  CRITICAL: "danger",
  HIGH: "danger",
  MEDIUM: "warning",
  LOW: "info",
};

export function SeverityBadge({ severity }: { severity: ScanSeverity }) {
  return <Badge tone={severityTone[severity]}>{severity}</Badge>;
}
