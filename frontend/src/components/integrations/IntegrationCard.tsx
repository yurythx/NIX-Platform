"use client";

import { useState, type ReactNode } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { apiClient, ApiError } from "@/lib/api/client";
import { useToast } from "@/components/notifications/ToastProvider";
import type { Integration, TestJobResponse } from "@/types/api";

export function IntegrationCard({
  integration,
  testPath,
  extra,
}: {
  integration: Integration;
  /** POST path (relative to /api/backend/) that triggers a test run, e.g. "v1/integrations/secops/virustotal/test". */
  testPath?: string;
  extra?: ReactNode;
}) {
  const { showToast } = useToast();
  const [testing, setTesting] = useState(false);

  const runTest = async () => {
    if (!testPath) return;
    setTesting(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>(testPath);
      showToast({
        title: "Test queued",
        description: `Job ${data.job_id.slice(0, 8)} — you'll be notified when it finishes.`,
        tone: "info",
      });
    } catch (err) {
      showToast({
        title: "Could not start test",
        description: err instanceof ApiError ? err.message : "Unexpected error",
        tone: "danger",
      });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4 space-y-0">
        <CardTitle>{integration.name}</CardTitle>
        <StatusIndicator status={integration.status} />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted">
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
        {integration.last_error && <p className="text-xs text-danger">{integration.last_error}</p>}
        <div className="flex items-center gap-2">
          {testPath && (
            <Button size="sm" variant="secondary" loading={testing} onClick={runTest}>
              Test connection
            </Button>
          )}
          {extra}
        </div>
      </CardContent>
    </Card>
  );
}
