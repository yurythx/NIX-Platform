import type { ReactNode } from "react";

// Estado "sem dados" do kit de UI — usado quando uma listagem carregou
// com sucesso mas não tem itens (distinto de ErrorState, para quando a
// carga falhou). title/description/action são sempre fornecidos por
// quem chama; este componente não tem texto padrão embutido.
export interface EmptyStateProps {
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-surface-border p-10 text-center">
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="max-w-sm text-sm text-muted">{description}</p>}
      {action}
    </div>
  );
}
