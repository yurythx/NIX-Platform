"use client";

import { Menu } from "lucide-react";

import { NotificationBell } from "@/components/notifications/NotificationBell";
import { Logo } from "@/components/ui/Logo";
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
  // Sessão expirada (§ NotificationClient.open) — nunca vai virar "Ao
  // vivo" sozinho, ao contrário de "closed"/"Reconectando…"; só um login
  // novo resolve. Vermelho (bg-status-offline), não âmbar, porque não é
  // transitório.
  unauthorized: { label: "Sessão expirada — atualize a página", dotClass: "bg-status-offline" },
};

// Barra superior (§ Sidebar/Topbar no layout do papermoon.cloud): fixa,
// ocupando a largura inteira da viewport, sempre acima de tudo — a
// Sidebar (fixa também) começa ABAIXO dela (top-14, ver Sidebar.tsx), não
// ao lado. DashboardShell.tsx compensa isso dando ao <main> um
// padding-top do tamanho desta barra (h-14) e um padding-left do tamanho
// da Sidebar, já que os dois elementos fixos saem do fluxo normal do
// layout.
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
    <header className="fixed inset-x-0 top-0 z-50 flex h-14 items-center justify-between border-b border-surface-border bg-surface px-4">
      <div className="flex items-center gap-3">
        {/* h-10 w-10 (não h-8 w-8) — § revisão de mobile 2026-08: alvo de
            toque de ~40px, mais confortável que 32px pra quem abre/fecha
            a Sidebar pelo dedo, não só pelo mouse; mesmo ajuste em
            ThemeToggle/NotificationBell/UserMenu logo abaixo, os quatro
            controles interativos desta barra. */}
        <button
          type="button"
          onClick={onToggleSidebar}
          aria-label="Alternar menu lateral"
          className="inline-flex h-10 w-10 items-center justify-center rounded-md text-muted hover:bg-black/5 hover:text-foreground dark:hover:bg-white/5"
        >
          <Menu size={18} aria-hidden="true" />
        </button>

        <span className="flex items-center gap-2 text-sm font-semibold">
          <Logo size={24} />
          <span className="hidden sm:inline">NIX Platform</span>
        </span>

        <div
          className="hidden items-center gap-2 text-xs text-muted md:flex"
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
