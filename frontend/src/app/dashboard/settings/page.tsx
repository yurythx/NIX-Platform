"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { FeatureFlagsPanel } from "@/components/settings/FeatureFlagsPanel";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration } from "@/types/api";

// Mapeia a chave de uma integração para o endpoint de teste e/ou uma
// página de detalhe dedicada, sem embutir regra de negócio no próprio
// card genérico (IntegrationCard).
const testPathByKey: Record<string, string> = {
  virustotal: "v1/integrations/secops/virustotal/test",
};

// Configurações (§ Reestruturação de páginas): consolida tudo que antes
// vivia em /dashboard/integrations (movido pra cá — a rota antiga
// redireciona, ver next.config.ts) com Feature flags, que já existia no
// backend desde o upgrade enterprise mas nunca teve uma UI.
export default function SettingsPage() {
  const [integrations, setIntegrations] = useState<Integration[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    apiClient
      .get<Integration[]>("v1/integrations")
      .then(({ data }) => {
        setError(null);
        setIntegrations(data);
      })
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : "Falha ao carregar integrações"),
      );
  };

  useEffect(load, []);

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold">Configurações</h1>
        <p className="text-sm text-muted">Integrações externas e configuração dinâmica do sistema.</p>
      </div>

      <section className="flex flex-col gap-4">
        <h2 className="text-sm font-semibold text-muted">Integrações</h2>

        {error && <ErrorState message={error} onRetry={load} />}

        {!error && !integrations && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        )}

        {integrations && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {integrations.map((integration) =>
              integration.key === "diario-oficial" ? (
                <IntegrationCard
                  key={integration.id}
                  integration={integration}
                  extra={
                    <Link href="/dashboard/settings/integrations/diario">
                      <Button size="sm" variant="ghost">
                        Detalhes
                      </Button>
                    </Link>
                  }
                />
              ) : (
                <IntegrationCard
                  key={integration.id}
                  integration={integration}
                  testPath={testPathByKey[integration.key]}
                />
              ),
            )}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-4">
        <h2 className="text-sm font-semibold text-muted">Configuração dinâmica</h2>
        <FeatureFlagsPanel />
      </section>
    </div>
  );
}
