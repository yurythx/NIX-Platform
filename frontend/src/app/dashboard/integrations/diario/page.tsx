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
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load"));
  };

  useEffect(load, []);

  const runTest = async () => {
    setTesting(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/integrations/diario-oficial/test");
      setLastJobId(data.job_id);
      showToast({
        title: "Diário Oficial check queued",
        description: `Job ${data.job_id.slice(0, 8)} — you'll be notified when it finishes.`,
        tone: "info",
      });
    } catch (err) {
      showToast({
        title: "Could not start check",
        description: err instanceof ApiError ? err.message : "Unexpected error",
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
          Runs an asynchronous connectivity check against the configured Diário Oficial endpoint.
        </p>
      </div>

      {error && <ErrorState message={error} onRetry={load} />}

      {!error && !integration && <Skeleton className="h-40 w-full" />}

      {integration && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle>Connection status</CardTitle>
            <StatusIndicator status={integration.status} />
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
              <dt>Last check</dt>
              <dd>
                {integration.last_check_at
                  ? new Date(integration.last_check_at).toLocaleString()
                  : "Never"}
              </dd>
              <dt>Last success</dt>
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
                Run test now
              </Button>
              {lastJobId && (
                <p className="mt-2 text-xs text-muted">
                  Last triggered job: <code>{lastJobId}</code> — result arrives as a notification.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
