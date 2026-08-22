"use client";

import { signOut } from "next-auth/react";

import { Button } from "@/components/ui/Button";
import type { ConnectionState } from "@/lib/websocket/client";

// Logout completo (RP-Initiated Logout — §30): 1) busca a URL de logout
// do Keycloak ENQUANTO a sessão local ainda existe (precisa do
// id_token_hint, lido server-side em /api/auth/keycloak-logout-url);
// 2) só então limpa a sessão local (signOut, sem redirecionar ainda);
// 3) navega o navegador até o Keycloak para encerrar a sessão lá também.
// Chamar apenas signOut() deixaria a sessão viva no provedor de
// identidade — outra aba, ou um login silencioso, reautenticaria sem
// pedir credenciais de novo.
async function fullSignOut() {
  let logoutUrl = "/";
  try {
    const res = await fetch("/api/auth/keycloak-logout-url");
    const data: { url: string } = await res.json();
    logoutUrl = data.url;
  } catch {
    // Se a chamada falhar, ainda assim completamos o logout local abaixo
    // — melhor encerrar só a sessão local do que travar o usuário logado.
  }
  await signOut({ redirect: false });
  window.location.href = logoutUrl;
}

// Rótulo + classe de cor (não style="" inline — ver StatusIndicator.tsx
// para a justificativa ligada ao CSP com nonce em proxy.ts) para cada
// estado da conexão WebSocket.
const connectionCopy: Record<ConnectionState, { label: string; dotClass: string }> = {
  idle: { label: "Conectando…", dotClass: "bg-status-unknown" },
  connecting: { label: "Conectando…", dotClass: "bg-status-unknown" },
  open: { label: "Ao vivo", dotClass: "bg-status-online" },
  closed: { label: "Reconectando…", dotClass: "bg-status-degraded" },
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
        title="Conexão de notificações em tempo real"
      >
        <span
          className={`h-2 w-2 rounded-full transition-colors ${status.dotClass}`}
          aria-hidden="true"
        />
        <span>{status.label}</span>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-sm text-muted">{userLabel}</span>
        <Button variant="secondary" size="sm" onClick={() => void fullSignOut()}>
          Sair
        </Button>
      </div>
    </header>
  );
}
