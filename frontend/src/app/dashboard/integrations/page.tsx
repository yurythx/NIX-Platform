"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration } from "@/types/api";

// Maps an integration's key to the test endpoint and/or a dedicated
// detail page, without hardcoding business logic into the card itself.
const testPathByKey: Record<string, string> = {
  virustotal: "v1/integrations/secops/virustotal/test",
};

export default function IntegrationsPage() {
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
        setError(err instanceof ApiError ? err.message : "Failed to load integrations"),
      );
  };

  useEffect(load, []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Integrations</h1>
        <p className="text-sm text-muted">External systems NIX Platform connects to.</p>
      </div>

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
                  <Link href="/dashboard/integrations/diario">
                    <Button size="sm" variant="ghost">
                      Details
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
