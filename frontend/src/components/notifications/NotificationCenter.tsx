"use client";

import { useCallback, useEffect } from "react";

import { useNotifications } from "@/hooks/useNotifications";
import { useNotificationHistory } from "@/components/notifications/NotificationHistoryProvider";
import { useToast } from "@/components/notifications/ToastProvider";
import type { ToastTone } from "@/components/ui/Toast";
import {
  integrationStatusPayloadSchema,
  jobEventPayloadSchema,
  scanCompletedPayloadSchema,
  type EventEnvelope,
} from "@/lib/validation/schemas";
import type { ConnectionState } from "@/lib/websocket/client";

const eventCopy: Partial<Record<string, { title: string; tone: "success" | "danger" | "info" }>> = {
  "diario_oficial.job.completed": { title: "Verificação do Diário Oficial concluída", tone: "success" },
  "diario_oficial.job.failed": { title: "Verificação do Diário Oficial falhou", tone: "danger" },
  "integration.test.completed": { title: "Teste de integração concluído", tone: "success" },
  "notification.created": { title: "Nova notificação", tone: "info" },
  // scanning.scan.completed NÃO entra aqui — payload é scan_id, não
  // job_id (ver scanCompletedPayloadSchema), então tem tratamento
  // próprio abaixo, igual integration.status.changed.
  "scanning.scan.failed": { title: "Scan de segurança falhou", tone: "danger" },
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
  const { push: pushHistory } = useNotificationHistory();

  const handleEvent = useCallback(
    (event: EventEnvelope) => {
      if (event.type === "integration.status.changed") {
        const result = integrationStatusPayloadSchema.safeParse(event.payload);
        if (result.success) {
          const tone: ToastTone = result.data.status === "online" ? "success" : "danger";
          const notification = {
            title: `Integração ${result.data.key} agora está ${result.data.status}`,
            tone,
          };
          showToast(notification);
          pushHistory(notification);
        }
        return;
      }

      if (event.type === "scanning.scan.completed") {
        const result = scanCompletedPayloadSchema.safeParse(event.payload);
        if (result.success) {
          const { scanners, findings_count, critical_count, high_count } = result.data;
          // Fase 14 (Maturidade de AppSec): até aqui todo scan com achado
          // nenhum virava "info", não importa a gravidade — um scan que
          // achou 1 CRITICAL merece o mesmo destaque visual (tone
          // "danger") que uma falha de scan já tinha, não o mesmo "info"
          // neutro de "achou 3 coisas de baixa severidade". CRITICAL
          // sempre fala por si na descrição; HIGH só aparece ali quando
          // não há CRITICAL nenhum (evita "1 crítico, 3 altos" competindo
          // por atenção — o crítico é a manchete).
          const tone: ToastTone = findings_count === 0 ? "success" : critical_count > 0 ? "danger" : "info";
          const severityNote =
            critical_count > 0 ? `, ${critical_count} crítico(s)!` : high_count > 0 ? `, ${high_count} alto(s)` : "";
          const notification = {
            title: `Scan concluído (${scanners.join(", ")})`,
            description:
              findings_count === 0
                ? "Nenhum achado."
                : `${findings_count} achado(s)${severityNote} — veja em Segurança.`,
            tone,
          };
          showToast(notification);
          pushHistory(notification);
        }
        return;
      }

      const copy = eventCopy[event.type];
      if (!copy) return; // tipo de evento não reconhecido — ignora em vez de adivinhar

      const job = jobEventPayloadSchema.safeParse(event.payload);
      const notification = {
        title: copy.title,
        description: job.success ? `Job ${job.data.job_id.slice(0, 8)}` : undefined,
        tone: copy.tone,
      };
      showToast(notification);
      pushHistory(notification);
    },
    [showToast, pushHistory],
  );

  const state = useNotifications(handleEvent);

  useEffect(() => {
    onConnectionStateChange?.(state);
  }, [state, onConnectionStateChange]);

  return null;
}
