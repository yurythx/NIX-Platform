"use client";

import { useState, type ReactNode } from "react";

import { Header } from "@/components/layout/Header";
import { Sidebar } from "@/components/layout/Sidebar";
import { NotificationCenter } from "@/components/notifications/NotificationCenter";
import { ToastProvider } from "@/components/notifications/ToastProvider";
import type { ConnectionState } from "@/lib/websocket/client";

export function DashboardShell({
  userLabel,
  children,
}: {
  userLabel: string;
  children: ReactNode;
}) {
  const [connectionState, setConnectionState] = useState<ConnectionState>("idle");

  return (
    <ToastProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex flex-1 flex-col">
          <Header userLabel={userLabel} connectionState={connectionState} />
          <main className="flex-1 p-6">{children}</main>
        </div>
      </div>
      <NotificationCenter onConnectionStateChange={setConnectionState} />
    </ToastProvider>
  );
}
