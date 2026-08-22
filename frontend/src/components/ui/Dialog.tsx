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
 * Built on the native <dialog> element: focus trapping, Escape-to-close
 * and a backdrop all come from the browser instead of being
 * reimplemented — fewer accessibility bugs to get wrong.
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
      className="m-auto rounded-xl border border-surface-border bg-surface p-0 text-foreground shadow-lg backdrop:bg-black/40"
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
