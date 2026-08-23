"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Integration, TestJobResponse } from "@/types/api";

// Movida de app/dashboard/integrations/diario (§ Reestruturação de
// páginas) para dentro de Configurações, junto com o resto de
// integrações — /dashboard/integrations/diario redireciona pra cá (ver
// next.config.ts).
export default function DiarioOficialPage() {
  const { showToast } = useToast();
  const [integration, setIntegration] = useState<Integration | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [lastJobId, setLastJobId] = useState<string | null>(null);

  const load = () => {
    apiClient
      .get<Integration[]>("v1/integrations")
      .then(({ data }) => {
        const found = data.find((i) => i.key === "diario-oficial");
        setError(null);
        setIntegration(found ?? null);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Falha ao carregar"));
  };

  useEffect(load, []);

  const runTest = async () => {
    setTesting(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/integrations/diario-oficial/test");
      setLastJobId(data.job_id);
      showToast({
        title: "Verificação do Diário Oficial enfileirada",
        description: `Job ${data.job_id.slice(0, 8)} — você será notificado quando terminar.`,
        tone: "info",
      });
    } catch (err) {
      showToast({
        title: "Não foi possível iniciar a verificação",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Diário Oficial</h1>
        <p className="text-sm text-muted">
          Executa uma verificação assíncrona de conectividade com o endpoint configurado do Diário
          Oficial.
        </p>
      </div>

      {error && <ErrorState message={error} onRetry={load} />}

      {!error && !integration && <Skeleton className="h-40 w-full" />}

      {integration && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle>Status da conexão</CardTitle>
            <StatusIndicator status={integration.status} />
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
              <dt>Última verificação</dt>
              <dd>
                {integration.last_check_at
                  ? new Date(integration.last_check_at).toLocaleString()
                  : "Nunca"}
              </dd>
              <dt>Último sucesso</dt>
              <dd>
                {integration.last_success_at
                  ? new Date(integration.last_success_at).toLocaleString()
                  : "—"}
              </dd>
            </dl>
            {integration.last_error && (
              <p className="text-sm text-danger">{integration.last_error}</p>
            )}

            <div>
              <Button loading={testing} onClick={runTest}>
                Rodar teste agora
              </Button>
              {lastJobId && (
                <p className="mt-2 text-xs text-muted">
                  Último job disparado: <code>{lastJobId}</code> — o resultado chega como
                  notificação.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
