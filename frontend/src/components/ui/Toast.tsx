export type ToastTone = "info" | "success" | "danger";

export interface ToastData {
  id: string;
  title: string;
  description?: string;
  tone: ToastTone;
}

const toneBorder: Record<ToastTone, string> = {
  info: "border-l-blue-500",
  success: "border-l-green-500",
  danger: "border-l-red-500",
};

export function Toast({ toast, onDismiss }: { toast: ToastData; onDismiss: (id: string) => void }) {
  return (
    // w-[calc(100vw-2rem)] max-w-80 — § revisão de mobile 2026-08: um
    // toast de 320px fixos (w-80) ancorado a 1rem da borda direita
    // (ToastProvider) passa da borda ESQUERDA de qualquer tela com menos
    // de 336px de largura — comum em celulares mais antigos/estreitos.
    // Limitado à viewport menos a margem em telas pequenas, sem perder o
    // tamanho de 320px de antes em telas maiores.
    <div
      className={`w-[calc(100vw-2rem)] max-w-80 rounded-lg border border-surface-border border-l-4 bg-surface p-3 shadow-md ${toneBorder[toast.tone]}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-medium text-foreground">{toast.title}</p>
          {toast.description && <p className="mt-0.5 text-xs text-muted">{toast.description}</p>}
        </div>
        <button
          type="button"
          onClick={() => onDismiss(toast.id)}
          aria-label="Dispensar notificação"
          className="shrink-0 rounded p-1 text-muted hover:bg-black/5 dark:hover:bg-white/10"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
