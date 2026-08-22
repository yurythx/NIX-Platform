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

  // Deliberately no synchronous setState before the request starts: the
  // initial null state already renders the loading skeleton, and a retry
  // simply replaces the old result/error once the new one arrives.
  const load = () => {
    apiClient
      .get<Integration[]>("v1/integrations")
      .then(({ data }) => {
        setError(null);
        setIntegrations(data);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load"));
  };

  useEffect(load, []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Overview</h1>
        <p className="text-sm text-muted">System status and quick actions.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/dashboard/integrations">
          <Button variant="secondary" size="sm">
            View integrations
          </Button>
        </Link>
        <Link href="/dashboard/integrations/diario">
          <Button variant="secondary" size="sm">
            Test Diário Oficial
          </Button>
        </Link>
        <Link href="/dashboard/users">
          <Button variant="secondary" size="sm">
            View users
          </Button>
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Integration status</CardTitle>
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
