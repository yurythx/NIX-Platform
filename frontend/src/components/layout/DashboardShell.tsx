"use client";

import { useState, useSyncExternalStore, type ReactNode } from "react";

import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { NotificationCenter } from "@/components/notifications/NotificationCenter";
import { NotificationHistoryProvider } from "@/components/notifications/NotificationHistoryProvider";
import { ToastProvider } from "@/components/notifications/ToastProvider";
import {
  getSidebarCollapsedServerSnapshot,
  getSidebarCollapsedSnapshot,
  setSidebarCollapsed,
  subscribeSidebarCollapsed,
} from "@/lib/layout/sidebarCollapsedStore";
import type { ConnectionState } from "@/lib/websocket/client";

// Mesmo valor do breakpoint md: do Tailwind — usado para decidir se
// onToggleSidebar deve recolher (desktop) ou abrir/fechar (mobile) a
// Sidebar, já que os dois compartilham um único botão na Topbar.
const MD_BREAKPOINT_QUERY = "(min-width: 768px)";

// Layout raiz do dashboard (§ Redesenho de layout, inspirado em
// papermoon.cloud): Sidebar recolhível + Topbar fixos, conteúdo da rota
// no meio, e o NotificationCenter (invisível, só lógica) montado uma vez
// aqui para alimentar tanto o indicador de conexão da Topbar quanto a
// pilha de toasts (ToastProvider) e a bandeja do sino
// (NotificationHistoryProvider).
export function DashboardShell({
  userLabel,
  initialTheme,
  children,
}: {
  userLabel: string;
  initialTheme?: "light" | "dark";
  children: ReactNode;
}) {
  const [connectionState, setConnectionState] = useState<ConnectionState>("idle");
  // Preferência puramente deste dispositivo/navegador — ver o comentário
  // em lib/layout/sidebarCollapsedStore.ts sobre por que isto é
  // useSyncExternalStore e não useState+useEffect.
  const collapsed = useSyncExternalStore(
    subscribeSidebarCollapsed,
    getSidebarCollapsedSnapshot,
    getSidebarCollapsedServerSnapshot,
  );
  const [mobileOpen, setMobileOpen] = useState(false);

  function toggleSidebar() {
    if (window.matchMedia(MD_BREAKPOINT_QUERY).matches) {
      setSidebarCollapsed(!collapsed);
    } else {
      setMobileOpen((prev) => !prev);
    }
  }

  return (
    <ToastProvider>
      <NotificationHistoryProvider>
        <div className="flex min-h-screen">
          <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} />
          <div className="flex min-w-0 flex-1 flex-col">
            <Topbar
              userLabel={userLabel}
              connectionState={connectionState}
              onToggleSidebar={toggleSidebar}
              initialTheme={initialTheme}
            />
            <main className="flex-1 overflow-x-auto p-4 sm:p-6">{children}</main>
          </div>
        </div>
        <NotificationCenter onConnectionStateChange={setConnectionState} />
      </NotificationHistoryProvider>
    </ToastProvider>
  );
}
