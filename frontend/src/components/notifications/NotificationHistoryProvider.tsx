"use client";

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

import type { ToastTone } from "@/components/ui/Toast";

export interface NotificationHistoryItem {
  id: string;
  title: string;
  description?: string;
  tone: ToastTone;
  createdAt: number;
  read: boolean;
}

// Quantas notificações a bandeja do sino guarda — não é um histórico
// completo (isso exigiria persistência no backend), só o suficiente para
// "o que aconteceu recentemente enquanto eu não estava olhando", igual ao
// dropdown de notificações da maioria dos dashboards (§ Redesenho de
// layout — inspirado em papermoon.cloud).
const MAX_ITEMS = 20;

interface NotificationHistoryContextValue {
  items: NotificationHistoryItem[];
  unreadCount: number;
  push: (item: { title: string; description?: string; tone?: ToastTone }) => void;
  markAllRead: () => void;
}

const NotificationHistoryContext = createContext<NotificationHistoryContextValue | null>(null);

// Provedor da bandeja de notificações persistentes, montado uma vez no
// DashboardShell ao lado de ToastProvider. NotificationCenter alimenta os
// dois a partir do mesmo evento de WebSocket — o toast é a notificação
// "ao vivo" que desaparece sozinha, este provider é a lista que fica
// disponível no sino da Topbar até o usuário marcar como lida.
export function NotificationHistoryProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<NotificationHistoryItem[]>([]);
  const idRef = useRef(0);

  const push = useCallback<NotificationHistoryContextValue["push"]>(
    ({ title, description, tone = "info" }) => {
      idRef.current += 1;
      const item: NotificationHistoryItem = {
        id: `notif-${idRef.current}`,
        title,
        description,
        tone,
        createdAt: Date.now(),
        read: false,
      };
      setItems((current) => [item, ...current].slice(0, MAX_ITEMS));
    },
    [],
  );

  const markAllRead = useCallback(() => {
    setItems((current) => current.map((item) => ({ ...item, read: true })));
  }, []);

  const unreadCount = items.filter((item) => !item.read).length;

  return (
    <NotificationHistoryContext.Provider value={{ items, unreadCount, push, markAllRead }}>
      {children}
    </NotificationHistoryContext.Provider>
  );
}

export function useNotificationHistory(): NotificationHistoryContextValue {
  const ctx = useContext(NotificationHistoryContext);
  if (!ctx) {
    throw new Error("useNotificationHistory must be used within a NotificationHistoryProvider");
  }
  return ctx;
}
