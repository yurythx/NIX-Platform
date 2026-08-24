"use client";

import type { KeyboardEvent } from "react";

import { SCANNERS } from "@/lib/scanning/scannerRegistry";

// ScannerPicker: grade de seleção de scanners extraída de TriggerScanForm
// pra ser reusada também por ProjectCard ("Rodar de novo") — antes desta
// extração, um scan avulso deixava escolher os scanners livremente
// enquanto um scan de projeto disparava com uma lista escondida
// (requested_scanners do último scan, ou só "trivy" na primeira vez),
// sem UI nenhuma pra ver ou mudar isso. Mesma grade, mesmo registro
// (scannerRegistry) e mesmo comportamento de seleção nas duas telas —
// nunca duas implementações divergentes do "que scanners existem e o
// que cada um faz".
export function ScannerPicker({
  selected,
  onToggle,
  excludeKeys = [],
}: {
  selected: Record<string, boolean>;
  onToggle: (key: string) => void;
  /** Scanners que não fazem sentido pro alvo atual (ex.: OWASP ZAP pra um
   * projeto salvo, que nunca é uma URL de serviço vivo) — omitidos da
   * grade em vez de aparecerem selecionáveis e falharem só depois que o
   * worker tentar rodá-los. */
  excludeKeys?: string[];
}) {
  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>, key: string) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onToggle(key);
    }
  }

  const scanners = SCANNERS.filter((s) => !excludeKeys.includes(s.key));

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      {scanners.map((s) => {
        const checked = !!selected[s.key];
        return (
          <div
            key={s.key}
            role="switch"
            aria-checked={checked}
            aria-label={s.name}
            tabIndex={0}
            onClick={() => onToggle(s.key)}
            onKeyDown={(e) => handleKeyDown(e, s.key)}
            className={`flex cursor-pointer flex-col gap-2 rounded-xl border p-4 text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
              checked
                ? "border-primary bg-primary/10"
                : "border-surface-border bg-surface hover:bg-black/5 dark:hover:bg-white/5"
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-medium text-foreground">{s.name}</div>
                <div className="text-xs text-muted">{s.category}</div>
              </div>
              <span
                aria-hidden="true"
                className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 text-xs ${
                  checked ? "border-primary bg-primary text-primary-foreground" : "border-surface-border"
                }`}
              >
                {checked && "✓"}
              </span>
            </div>
            <p className="text-sm text-muted">{s.description}</p>
            <p className="text-xs text-muted">{s.usage}</p>
          </div>
        );
      })}
    </div>
  );
}
