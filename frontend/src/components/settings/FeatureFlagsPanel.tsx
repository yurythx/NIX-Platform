"use client";

import { useEffect, useState } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { FeatureFlag } from "@/types/api";

// Painel de Configurações > Feature flags — primeira UI para
// GET/PATCH /api/v1/admin/feature-flags (o endpoint já existia desde o
// upgrade enterprise, mas só era alcançável via chamada de API crua; ver
// docs/adr/002-enterprise-resilience-and-governance.md). Restrito a
// nix-admin no backend — um 403 aqui é esperado para qualquer outro
// usuário e é tratado como um estado normal da UI, não um erro genérico.
export function FeatureFlagsPanel() {
  const { showToast } = useToast();
  const [flags, setFlags] = useState<FeatureFlag[] | null>(null);
  const [error, setError] = useState<{ message: string; forbidden: boolean } | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const load = () => {
    apiClient
      .get<FeatureFlag[]>("v1/admin/feature-flags")
      .then(({ data }) => {
        setError(null);
        setFlags(data);
      })
      .catch((err: unknown) => {
        const forbidden = err instanceof ApiError && err.status === 403;
        setError({
          message: err instanceof ApiError ? err.message : "Falha ao carregar feature flags",
          forbidden,
        });
      });
  };

  useEffect(load, []);

  async function toggle(flag: FeatureFlag, next: boolean) {
    setPendingKey(flag.key);
    // Otimista: a maioria das trocas é bem-sucedida, e esperar o round-trip
    // pra atualizar um único switch deixaria a UI visivelmente lenta.
    setFlags((current) =>
      current?.map((f) => (f.key === flag.key ? { ...f, enabled: next } : f)) ?? current,
    );
    try {
      await apiClient.patch(`v1/admin/feature-flags/${flag.key}`, { enabled: next });
    } catch (err) {
      // Desfaz a mudança otimista e avisa — não deixa a UI mentir sobre o
      // estado real do flag no backend.
      setFlags((current) =>
        current?.map((f) => (f.key === flag.key ? { ...f, enabled: !next } : f)) ?? current,
      );
      showToast({
        title: `Não foi possível alterar "${flag.key}"`,
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setPendingKey(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Feature flags</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {error?.forbidden && (
          <p className="text-sm text-muted">
            Restrito a administradores — sua conta não tem permissão para ver ou alterar feature
            flags.
          </p>
        )}
        {error && !error.forbidden && <ErrorState message={error.message} onRetry={load} />}

        {!error && !flags && (
          <div className="flex flex-col gap-3">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {flags?.length === 0 && <p className="text-sm text-muted">Nenhuma feature flag registrada.</p>}

        {flags && flags.length > 0 && (
          <ul className="flex flex-col divide-y divide-surface-border">
            {flags.map((flag) => (
              <li key={flag.key} className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-foreground">{flag.key}</p>
                  {flag.description && (
                    <p className="truncate text-xs text-muted">{flag.description}</p>
                  )}
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
        )}
      </CardContent>
    </Card>
  );
}
