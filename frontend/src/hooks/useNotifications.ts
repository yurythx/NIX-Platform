"use client";

import { useEffect, useRef, useState } from "react";

import { apiClient } from "@/lib/api/client";
import { NotificationClient, type ConnectionState } from "@/lib/websocket/client";
import type { EventEnvelope } from "@/lib/validation/schemas";

interface TicketResponse {
  ticket: string;
}

/**
 * Controla o ciclo de vida da conexão WebSocket para todo o dashboard:
 * busca um ticket novo a cada (re)conexão, encaminha os eventos já
 * validados para onEvent, e expõe o estado atual da conexão para um
 * indicador de status (ver Header.tsx).
 */
export function useNotifications(onEvent: (event: EventEnvelope) => void): ConnectionState {
  const [state, setState] = useState<ConnectionState>("idle");
  const onEventRef = useRef(onEvent);

  // Mantém a ref atualizada sem torná-la uma dependência do efeito — refs
  // só podem ser escritas fora da renderização (event handlers/efeitos),
  // nunca de forma síncrona durante a própria renderização.
  useEffect(() => {
    onEventRef.current = onEvent;
  });

  useEffect(() => {
    const wsBaseUrl = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";

    const client = new NotificationClient({
      wsBaseUrl,
      getTicket: async () => {
        const { data } = await apiClient.post<TicketResponse>("v1/ws/ticket");
        return data.ticket;
      },
      onMessage: (event) => onEventRef.current(event),
      onStateChange: setState,
    });

    client.connect();
    return () => client.disconnect();
  }, []);

  return state;
}
