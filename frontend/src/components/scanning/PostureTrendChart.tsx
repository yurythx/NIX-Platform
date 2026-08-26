import type { PostureSnapshot } from "@/types/api";

// PostureTrendChart (Fase 14, continuação — tendência histórica): o
// gráfico que faltava — SecurityPosture sozinho só respondia "quantos
// problemas abertos existem AGORA", nunca "estamos melhorando ou
// piorando". SVG desenhado à mão, sem biblioteca de gráfico nova
// (nenhuma já existe nas dependências do frontend, e um gráfico de
// linha simples — 2 séries, poucos pontos — não justifica adicionar
// uma só pra isto). Server Component puro (sem "use client"): não tem
// interação nenhuma, só desenho estático a partir de dados já buscados.
//
// Só crítico + alto (não médio/baixo) — as duas severidades que
// realmente mudam a decisão de "isso está piorando?"; médio/baixo
// tendem a ter volume alto e ruidoso demais pra um gráfico pequeno sem
// virar zoom automático de eixo.
export function PostureTrendChart({ snapshots }: { snapshots: PostureSnapshot[] }) {
  if (snapshots.length < 2) {
    return (
      <p className="text-xs text-muted">
        Ainda não há histórico suficiente pra mostrar uma tendência — volte depois de alguns dias.
      </p>
    );
  }

  const width = 320;
  const height = 80;
  const padding = 4;

  const maxValue = Math.max(1, ...snapshots.map((s) => Math.max(s.open_critical, s.open_high)));
  const stepX = (width - padding * 2) / (snapshots.length - 1);

  function pointsFor(pick: (s: PostureSnapshot) => number): string {
    return snapshots
      .map((s, i) => {
        const x = padding + i * stepX;
        const y = height - padding - (pick(s) / maxValue) * (height - padding * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }

  const first = snapshots[0];
  const last = snapshots[snapshots.length - 1];
  if (!first || !last) return null; // inalcançável (snapshots.length >= 2 já garantido acima), só satisfaz noUncheckedIndexedAccess

  return (
    <div className="flex flex-col gap-2">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" role="img" aria-label="Tendência de achados críticos e altos abertos ao longo do tempo">
        <polyline points={pointsFor((s) => s.open_critical)} fill="none" stroke="currentColor" strokeWidth="2" className="text-red-500" />
        <polyline points={pointsFor((s) => s.open_high)} fill="none" stroke="currentColor" strokeWidth="2" className="text-amber-500" />
      </svg>
      <div className="flex items-center justify-between text-xs text-muted">
        <span>{new Date(first.date).toLocaleDateString()}</span>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-red-500" /> Crítico
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-amber-500" /> Alto
          </span>
        </div>
        <span>{new Date(last.date).toLocaleDateString()}</span>
      </div>
    </div>
  );
}
