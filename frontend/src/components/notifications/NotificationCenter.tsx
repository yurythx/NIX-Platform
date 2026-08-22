"use client";

import { useCallback, useEffect } from "react";

import { useNotifications } from "@/hooks/useNotifications";
import { useToast } from "@/components/notifications/ToastProvider";
import {
  integrationStatusPayloadSchema,
  jobEventPayloadSchema,
  type EventEnvelope,
} from "@/lib/validation/schemas";
import type { ConnectionState } from "@/lib/websocket/client";

const eventCopy: Partial<Record<string, { title: string; tone: "success" | "danger" | "info" }>> = {
  "diario_oficial.job.completed": { title: "Diário Oficial check completed", tone: "success" },
  "diario_oficial.job.failed": { title: "Diário Oficial check failed", tone: "danger" },
  "integration.test.completed": { title: "Integration test completed", tone: "success" },
  "notification.created": { title: "New notification", tone: "info" },
};

/** Mounted once in the dashboard layout — renders nothing itself beyond
 * the toast stack (via ToastProvider), translating validated WebSocket
 * events into toasts (§43). */
export function NotificationCenter({
  onConnectionStateChange,
}: {
  onConnectionStateChange?: (state: ConnectionState) => void;
}) {
  const { showToast } = useToast();

  const handleEvent = useCallback(
    (event: EventEnvelope) => {
      if (event.type === "integration.status.changed") {
        const result = integrationStatusPayloadSchema.safeParse(event.payload);
        if (result.success) {
          showToast({
            title: `Integration ${result.data.key} is now ${result.data.status}`,
            tone: result.data.status === "online" ? "success" : "danger",
          });
        }
        return;
      }

      const copy = eventCopy[event.type];
      if (!copy) return; // unrecognized event type — ignore rather than guess

      const job = jobEventPayloadSchema.safeParse(event.payload);
      showToast({
        title: copy.title,
        description: job.success ? `Job ${job.data.job_id.slice(0, 8)}` : undefined,
        tone: copy.tone,
      });
    },
    [showToast],
  );

  const state = useNotifications(handleEvent);

  useEffect(() => {
    onConnectionStateChange?.(state);
  }, [state, onConnectionStateChange]);

  return null;
}
