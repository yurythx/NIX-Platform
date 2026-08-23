"use client";

import { Menu } from "lucide-react";

import { NotificationBell } from "@/components/notifications/NotificationBell";
import { ThemeToggle } from "@/components/ui/ThemeToggle";
import { UserMenu } from "@/components/layout/UserMenu";
import type { ConnectionState } from "@/lib/websocket/client";

// Rótulo + classe de cor (não style="" inline — ver StatusIndicator.tsx
// para a justificativa ligada ao CSP com nonce em proxy.ts) para cada
// estado da conexão WebSocket.
const connectionCopy: Record<ConnectionState, { label: string; dotClass: string }> = {
  idle: { label: "Conectando…", dotClass: "bg-status-unknown" },
  connecting: { label: "Conectando…", dotClass: "bg-status-unknown" },
  open: { label: "Ao vivo", dotClass: "bg-status-online" },
  closed: { label: "Reconectando…", dotClass: "bg-status-degraded" },
};

// Barra superior (§ Redesenho de layout, inspirado em papermoon.cloud):
// alterna a Sidebar (recolher no desktop, abrir/fechar no mobile — a
// mesma ação, resolvida por onToggleSidebar em DashboardShell conforme o
// breakpoint), mostra o indicador de conexão do WebSocket, e agrupa
// tema/notificações/usuário no canto superior direito.
export function Topbar({
  userLabel,
  connectionState,
  onToggleSidebar,
  initialTheme,
}: {
  userLabel: string;
  connectionState: ConnectionState;
  onToggleSidebar: () => void;
  initialTheme?: "light" | "dark";
}) {
  const status = connectionCopy[connectionState];

  return (
    <header className="flex items-center justify-between border-b border-surface-border px-4 py-3">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onToggleSidebar}
          aria-label="Alternar menu lateral"
          className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-black/5 hover:text-foreground dark:hover:bg-white/5"
        >
          <Menu size={18} aria-hidden="true" />
        </button>

        <span className="text-sm font-semibold md:hidden">NIX Platform</span>

        <div
          className="hidden items-center gap-2 text-xs text-muted sm:flex"
          title="Conexão de notificações em tempo real"
        >
          <span
            className={`h-2 w-2 rounded-full transition-colors ${status.dotClass}`}
            aria-hidden="true"
          />
          <span>{status.label}</span>
        </div>
      </div>

      <div className="flex items-center gap-1.5">
        <ThemeToggle initialTheme={initialTheme} />
        <NotificationBell />
        <div className="ml-1.5">
          <UserMenu userLabel={userLabel} />
        </div>
      </div>
    </header>
  );
}
