"use client";

import { Bell } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { useNotificationHistory } from "@/components/notifications/NotificationHistoryProvider";

const toneDot: Record<string, string> = {
  info: "bg-status-unknown",
  success: "bg-status-online",
  danger: "bg-status-offline",
};

function relativeTime(ts: number): string {
  const seconds = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (seconds < 60) return "agora";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}min atrás`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h atrás`;
}

// Sino de notificações na Topbar (§ Redesenho de layout): mostra a
// contagem de não lidas e, ao clicar, um dropdown com as mais recentes —
// mesmo popover hand-rolled do UserMenu (useState + useRef +
// click-fora/Escape), alimentado por NotificationHistoryProvider (que
// NotificationCenter já preenche a partir dos mesmos eventos de
// WebSocket que disparam os toasts).
export function NotificationBell() {
  const { items, unreadCount, markAllRead } = useNotificationHistory();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function toggle() {
    setOpen((v) => {
      const next = !v;
      if (next) markAllRead();
      return next;
    });
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={toggle}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={unreadCount > 0 ? `Notificações, ${unreadCount} não lidas` : "Notificações"}
        className="relative inline-flex h-8 w-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-black/5 hover:text-foreground dark:hover:bg-white/5"
      >
        <Bell size={17} aria-hidden="true" />
        {unreadCount > 0 && (
          <span
            aria-hidden="true"
            className="absolute right-0.5 top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-semibold text-white"
          >
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-10 z-50 max-h-96 w-80 overflow-y-auto rounded-md border border-surface-border bg-surface py-1 shadow-lg"
        >
          <div className="border-b border-surface-border px-3 py-2 text-sm font-semibold">
            Notificações
          </div>
          {items.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-muted">Nenhuma notificação ainda.</p>
          ) : (
            <ul>
              {items.slice(0, 5).map((item) => (
                <li key={item.id} className="border-b border-surface-border px-3 py-2 last:border-0">
                  <div className="flex items-start gap-2">
                    <span
                      className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${toneDot[item.tone] ?? toneDot.info}`}
                      aria-hidden="true"
                    />
                    <div className="min-w-0">
                      <p className="truncate text-sm text-foreground">{item.title}</p>
                      {item.description && (
                        <p className="truncate text-xs text-muted">{item.description}</p>
                      )}
                      <p className="text-xs text-muted">{relativeTime(item.createdAt)}</p>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
