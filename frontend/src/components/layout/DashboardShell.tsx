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
        {/* Pular para o conteúdo (§ auditoria 2026-08): invisível até
            receber foco por teclado — sem ele, quem navega por teclado/
            leitor de tela precisa tabular pela Sidebar inteira em toda
            página só pra chegar no conteúdo principal. z-[60]: acima da
            Topbar (z-50) e da Sidebar (z-40), únicos outros elementos
            fixos nesta árvore. */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[60] focus:rounded-md focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-primary-foreground"
        >
          Pular para o conteúdo
        </a>

        <Topbar
          userLabel={userLabel}
          connectionState={connectionState}
          onToggleSidebar={toggleSidebar}
          initialTheme={initialTheme}
        />
        <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} />

        {/* Topbar e Sidebar são fixed (fora do fluxo normal — ver seus
            próprios comentários) — este <main> precisa compensar os dois
            manualmente: pt-14 pela altura da Topbar (sempre presente,
            mobile incluso), pl-16/pl-60 pela largura da Sidebar SÓ no
            desktop (md:), já que no mobile ela fica off-canvas e não
            ocupa espaço nenhum na página. */}
        <main
          id="main-content"
          className={`min-h-screen overflow-x-auto pt-14 px-4 pb-4 transition-[padding] duration-200 sm:px-6 sm:pb-6
            ${collapsed ? "md:pl-16" : "md:pl-60"}`}
        >
          {children}
        </main>

        <NotificationCenter onConnectionStateChange={setConnectionState} />
      </NotificationHistoryProvider>
    </ToastProvider>
  );
}
