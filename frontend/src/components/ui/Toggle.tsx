"use client";

// Interruptor on/off (§ Configurações — feature flags): um checkbox nativo
// escondido visualmente + uma trilha/thumb desenhada por cima, o padrão
// usual para "switch" acessível sem depender de nenhuma lib de UI-kit —
// mesmo espírito de Button.tsx/Badge.tsx (props tipadas, classes
// orientadas a token, sem style="" inline).
export interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  label: string; // acessível (aria-label) — sempre obrigatório, nunca só um ícone/cor
}

export function Toggle({ checked, onChange, disabled, label }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors
        focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary
        disabled:cursor-not-allowed disabled:opacity-50
        ${checked ? "bg-primary" : "bg-surface-border"}`}
    >
      <span
        aria-hidden="true"
        className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform
          ${checked ? "translate-x-5" : "translate-x-1"}`}
      />
    </button>
  );
}
