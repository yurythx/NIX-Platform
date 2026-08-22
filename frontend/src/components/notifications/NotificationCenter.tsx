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
  "diario_oficial.job.completed": { title: "Verificação do Diário Oficial concluída", tone: "success" },
  "diario_oficial.job.failed": { title: "Verificação do Diário Oficial falhou", tone: "danger" },
  "integration.test.completed": { title: "Teste de integração concluído", tone: "success" },
  "notification.created": { title: "Nova notificação", tone: "info" },
};

/** Montado uma única vez no layout do dashboard — não renderiza nada além
 * da pilha de toasts (via ToastProvider); traduz os eventos de WebSocket
 * já validados em toasts (§43). */
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
            title: `Integração ${result.data.key} agora está ${result.data.status}`,
            tone: result.data.status === "online" ? "success" : "danger",
          });
        }
        return;
      }

      const copy = eventCopy[event.type];
      if (!copy) return; // tipo de evento não reconhecido — ignora em vez de adivinhar

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
