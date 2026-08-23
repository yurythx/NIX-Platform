"use client";

import { useSession } from "next-auth/react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration } from "@/types/api";

// Visão geral (§ Reestruturação de rotas): a partir de agora /dashboard
// serve SÓ isto — status do sistema e atalhos. Usuários, integrações e
// configuração dinâmica vivem em /configuracao (ver
// app/(protected)/configuracao/).
export default function DashboardOverviewPage() {
  const { data: session } = useSession();
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

  const firstName = (session?.user?.name ?? session?.user?.email ?? "").split(/[@\s]/)[0];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">
          {firstName ? `Olá, ${firstName}` : "Visão geral"}
        </h1>
        <p className="text-sm text-muted">Status do sistema e ações rápidas.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/configuracao">
          <Button variant="secondary" size="sm">
            Ver configurações
          </Button>
        </Link>
        <Link href="/configuracao/integracoes/diario">
          <Button variant="secondary" size="sm">
            Testar Diário Oficial
          </Button>
        </Link>
        <Link href="/configuracao/usuarios">
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
