"use client";

import { useState } from "react";

import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { FeatureFlag } from "@/types/api";

// Painel de Configurações > Feature flags — primeira UI para
// GET/PATCH /api/v1/admin/feature-flags (o endpoint já existia desde o
// upgrade enterprise, mas só era alcançável via chamada de API crua; ver
// docs/adr/002-enterprise-resilience-and-governance.md).
//
// initialFlags vem pronto do servidor (app/(protected)/configuracao/page.tsx
// já buscou a lista antes de renderizar — § Migração pra Server
// Components) — este componente só existe pra ficar "use client" e
// possuir o estado otimista do toggle/PATCH, que é genuinamente
// interativo; ele não busca mais nada sozinho no mount. O caso 403
// (restrito a nix-admin) já é tratado por quem chama, antes deste
// componente sequer ser montado.
export function FeatureFlagsPanel({ initialFlags }: { initialFlags: FeatureFlag[] }) {
  const { showToast } = useToast();
  const [flags, setFlags] = useState(initialFlags);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  async function toggle(flag: FeatureFlag, next: boolean) {
    setPendingKey(flag.key);
    // Otimista: a maioria das trocas é bem-sucedida, e esperar o round-trip
    // pra atualizar um único switch deixaria a UI visivelmente lenta.
    setFlags((current) => current.map((f) => (f.key === flag.key ? { ...f, enabled: next } : f)));
    try {
      await apiClient.patch(`v1/admin/feature-flags/${flag.key}`, { enabled: next });
    } catch (err) {
      // Desfaz a mudança otimista e avisa — não deixa a UI mentir sobre o
      // estado real do flag no backend.
      setFlags((current) => current.map((f) => (f.key === flag.key ? { ...f, enabled: !next } : f)));
      showToast({
        title: `Não foi possível alterar "${flag.key}"`,
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setPendingKey(null);
    }
  }

  if (flags.length === 0) {
    return <p className="text-sm text-muted">Nenhuma feature flag registrada.</p>;
  }

  return (
    <ul className="flex flex-col divide-y divide-surface-border">
      {flags.map((flag) => (
        <li key={flag.key} className="flex items-center justify-between gap-4 py-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-foreground">{flag.key}</p>
            {flag.description && <p className="truncate text-xs text-muted">{flag.description}</p>}
          </div>
          <Toggle
            checked={flag.enabled}
            onChange={(next) => void toggle(flag, next)}
            disabled={pendingKey === flag.key}
            label={`${flag.enabled ? "Desativar" : "Ativar"} ${flag.key}`}
          />
        </li>
      ))}
    </ul>
  );
}
