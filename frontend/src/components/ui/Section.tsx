import type { ReactNode } from "react";

// Section: painel com moldura própria (mesma linguagem visual de Card —
// rounded-xl/border-surface-border/bg-surface/shadow-sm) pra agrupar um
// bloco de conteúdo da página com um cabeçalho sempre no mesmo lugar
// (título + descrição opcional + ação opcional), separado do resto por
// uma borda inferior própria.
//
// § Auditoria de layout 2026-08: antes, uma página com várias seções
// (ex.: /seguranca — Projetos, Scans recentes, Achados recentes) só
// separava cada bloco com um <h2> pequeno em caixa alta e um gap — sem
// moldura nenhuma ao redor do bloco em si, o conteúdo ficava "colado"
// direto no fundo da página, bem diferente da Sidebar/Topbar (que já são
// bg-surface com borda). Section estende essa mesma linguagem pro
// conteúdo principal, sem duplicar Card (que é genérico demais pra
// carregar cabeçalho/ação padronizados) nem remover a moldura própria de
// quem já tem uma (Table, a lista de ScanList) — o `padding` da Section
// vira só o respiro ao redor delas.
export function Section({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-surface-border bg-surface shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-surface-border px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
        </div>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}
