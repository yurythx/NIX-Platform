"use client";

import { useEffect, useRef, useState } from "react";

import { apiClient } from "@/lib/api/client";
import { NotificationClient, type ConnectionState } from "@/lib/websocket/client";
import type { EventEnvelope } from "@/lib/validation/schemas";

interface TicketResponse {
  ticket: string;
}

/**
 * Owns the WebSocket connection lifecycle for the whole dashboard:
 * fetches a fresh ticket per (re)connect, forwards validated events to
 * onEvent, and exposes the current connection state for a status
 * indicator.
 */
export function useNotifications(onEvent: (event: EventEnvelope) => void): ConnectionState {
  const [state, setState] = useState<ConnectionState>("idle");
  const onEventRef = useRef(onEvent);

  // Keep the ref current without making it an effect dependency — refs
  // must only be written outside of render (event handlers/effects), not
  // synchronously during render itself.
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
