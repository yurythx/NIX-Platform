import type { ScanSeverity } from "@/types/api";

// SeverityDistributionBar (revisão de exibição de resultados): uma barra
// horizontal proporcional — bater o olho e entender a gravidade GERAL de
// uma lista de achados sem somar os números dos chips de filtro na
// cabeça, o que GitHub/Snyk/Wiz sempre têm em algum lugar da tela de
// resultados. Cores PRÓPRIAS (não as de SeverityBadge/Badge): o Badge
// genérico usa só 3 tons (danger/warning/info) e funde CRITICAL+HIGH no
// mesmo vermelho — correto pra um selo de texto (o texto já diferencia
// os dois), mas numa barra só de cor, sem texto nenhum, essa fusão
// esconderia exatamente a distinção que mais importa. 4 cores reais,
// vermelho→laranja→âmbar→cinza, a mesma progressão que
// PostureTrendChart/SecurityPostureCard já usam nos outros lugares desta
// seção que precisam diferenciar as 4 severidades de verdade.
const SEVERITY_COLORS: Record<ScanSeverity, string> = {
  CRITICAL: "bg-red-600",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-slate-300 dark:bg-slate-600",
};

export function SeverityDistributionBar({ counts }: { counts: Record<ScanSeverity, number> }) {
  const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  if (total === 0) return null;

  const severities: ScanSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div
      role="img"
      aria-label={`Distribuição de severidade: ${counts.CRITICAL} crítico, ${counts.HIGH} alto, ${counts.MEDIUM} médio, ${counts.LOW} baixo`}
      className="flex h-2 w-full overflow-hidden rounded-full bg-black/5 dark:bg-white/10"
    >
      {severities.map((sev) => {
        const pct = (counts[sev] / total) * 100;
        if (pct === 0) return null;
        return <div key={sev} title={`${sev}: ${counts[sev]}`} className={SEVERITY_COLORS[sev]} style={{ width: `${pct}%` }} />;
      })}
    </div>
  );
}
