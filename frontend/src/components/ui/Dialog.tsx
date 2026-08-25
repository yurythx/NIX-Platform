"use client";

import { useEffect, useRef, type ReactNode } from "react";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children?: ReactNode;
}

/**
 * Construído sobre o elemento nativo <dialog>: captura de foco,
 * fechar-com-Escape e o backdrop vêm todos do navegador em vez de serem
 * reimplementados — menos bugs de acessibilidade para errar.
 */
export function Dialog({ open, onClose, title, description, children }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={onClose}
      aria-labelledby="dialog-title"
      aria-describedby={description ? "dialog-description" : undefined}
      // max-w-[calc(100vw-2rem)] — § revisão de mobile 2026-08: o <dialog>
      // nativo já tem um limite de UA (~"calc(100% - 6px)"), mas essa
      // garantia explícita não depende do navegador/versão pra nunca
      // encostar na borda da tela num celular estreito.
      className="m-auto max-w-[calc(100vw-2rem)] rounded-xl border border-surface-border bg-surface p-0 text-foreground shadow-lg backdrop:bg-black/40"
    >
      <div className="w-full max-w-md p-5">
        <h2 id="dialog-title" className="text-base font-semibold">
          {title}
        </h2>
        {description && (
          <p id="dialog-description" className="mt-1 text-sm text-muted">
            {description}
          </p>
        )}
        <div className="mt-4">{children}</div>
      </div>
    </dialog>
  );
}
