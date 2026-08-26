import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import type { SecurityPosture } from "@/types/api";

// SecurityPostureCard (Fase 14 — Maturidade de AppSec): o card que
// faltava no dashboard — até aqui, nenhum lugar da plataforma respondia
// "quantos problemas abertos existem AGORA, no total" sem abrir
// /seguranca e contar na mão. Server Component puro (sem "use client"):
// dashboard/page.tsx já busca SecurityPosture no servidor (mesmo padrão
// de "Status das integrações" ao lado), este componente só formata.
export function SecurityPostureCard({ posture }: { posture: SecurityPosture }) {
  const totalOpen = posture.open_critical + posture.open_high + posture.open_medium + posture.open_low;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Postura de segurança</CardTitle>
      </CardHeader>
      <CardContent>
        {totalOpen === 0 && posture.projects_scanned === 0 ? (
          <EmptyState
            title="Nenhum projeto escaneado ainda"
            description="Crie um projeto em Segurança e rode um scan pra ver o resumo aqui."
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              {posture.open_critical > 0 && <Badge tone="danger">{posture.open_critical} crítico(s)</Badge>}
              {posture.open_high > 0 && <Badge tone="warning">{posture.open_high} alto(s)</Badge>}
              {posture.open_medium > 0 && <Badge tone="info">{posture.open_medium} médio(s)</Badge>}
              {posture.open_low > 0 && <Badge tone="neutral">{posture.open_low} baixo(s)</Badge>}
              {totalOpen === 0 && <Badge tone="success">Nenhum achado aberto</Badge>}
            </div>
            <p className="text-xs text-muted">
              {posture.projects_scanned} projeto(s) escaneado(s)
              {posture.triaged_count > 0 && ` · ${posture.triaged_count} achado(s) triado(s) (não contam acima)`}
            </p>

            {posture.top_vulnerable.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                  Projetos mais vulneráveis
                </p>
                <ul className="flex flex-col gap-1.5">
                  {posture.top_vulnerable.map((p) => (
                    <li key={p.project_id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate text-foreground">{p.project_name}</span>
                      <span className="shrink-0 text-xs text-muted">
                        {p.open_critical > 0 && `${p.open_critical} crítico(s)`}
                        {p.open_critical > 0 && p.open_high > 0 && ", "}
                        {p.open_high > 0 && `${p.open_high} alto(s)`}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <Link href="/seguranca" className="text-sm text-primary hover:underline">
              Ver tudo em Segurança →
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
