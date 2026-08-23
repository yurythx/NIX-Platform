"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration } from "@/types/api";

// Mapeia a chave de uma integração para o endpoint de teste e/ou uma
// página de detalhe dedicada, sem embutir regra de negócio no próprio
// card genérico (IntegrationCard).
const testPathByKey: Record<string, string> = {
  virustotal: "v1/integrations/secops/virustotal/test",
};

// Aba "Integrações" de /configuracao.
export default function IntegracoesPage() {
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
    <div className="flex flex-col gap-4">
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
                  <Link href="/configuracao/integracoes/diario">
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
    </div>
  );
}
