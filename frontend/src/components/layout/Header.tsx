"use client";

import { signOut } from "next-auth/react";

import { Button } from "@/components/ui/Button";
import type { ConnectionState } from "@/lib/websocket/client";

const connectionCopy: Record<ConnectionState, { label: string; color: string }> = {
  idle: { label: "Connecting…", color: "var(--status-unknown)" },
  connecting: { label: "Connecting…", color: "var(--status-unknown)" },
  open: { label: "Live", color: "var(--status-online)" },
  closed: { label: "Reconnecting…", color: "var(--status-degraded)" },
};

export function Header({
  userLabel,
  connectionState,
}: {
  userLabel: string;
  connectionState: ConnectionState;
}) {
  const status = connectionCopy[connectionState];

  return (
    <header className="flex items-center justify-between border-b border-surface-border px-6 py-3">
      <div
        className="flex items-center gap-2 text-xs text-muted"
        title="Real-time notification connection"
      >
        <span
          className="h-2 w-2 rounded-full transition-colors"
          style={{ backgroundColor: status.color }}
          aria-hidden="true"
        />
        <span>{status.label}</span>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-sm text-muted">{userLabel}</span>
        <Button variant="secondary" size="sm" onClick={() => signOut({ callbackUrl: "/" })}>
          Sign out
        </Button>
      </div>
    </header>
  );
}
