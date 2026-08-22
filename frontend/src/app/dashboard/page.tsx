"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration } from "@/types/api";

export default function DashboardOverviewPage() {
  const [integrations, setIntegrations] = useState<Integration[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Deliberadamente nenhum setState síncrono antes de a requisição
  // começar: o estado inicial null já renderiza o skeleton de
  // carregamento, e uma nova tentativa simplesmente substitui o
  // resultado/erro antigo assim que o novo chega.
  const load = () => {
    apiClient
      .get<Integration[]>("v1/integrations")
      .then(({ data }) => {
        setError(null);
        setIntegrations(data);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Falha ao carregar"));
  };

  useEffect(load, []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Visão geral</h1>
        <p className="text-sm text-muted">Status do sistema e ações rápidas.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/dashboard/integrations">
          <Button variant="secondary" size="sm">
            Ver integrações
          </Button>
        </Link>
        <Link href="/dashboard/integrations/diario">
          <Button variant="secondary" size="sm">
            Testar Diário Oficial
          </Button>
        </Link>
        <Link href="/dashboard/users">
          <Button variant="secondary" size="sm">
            Ver usuários
          </Button>
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Status das integrações</CardTitle>
        </CardHeader>
        <CardContent>
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && !integrations && (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-6 w-full" />
              <Skeleton className="h-6 w-full" />
            </div>
          )}
          {integrations && (
            <ul className="flex flex-col gap-3">
              {integrations.map((integration) => (
                <li key={integration.id} className="flex items-center justify-between">
                  <span className="text-sm">{integration.name}</span>
                  <StatusIndicator status={integration.status} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
