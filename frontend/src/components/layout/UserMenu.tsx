"use client";

import { LogOut } from "lucide-react";
import { signOut } from "next-auth/react";
import { useEffect, useRef, useState } from "react";

// Logout completo (RP-Initiated Logout — §30): 1) busca a URL de logout
// do Keycloak ENQUANTO a sessão local ainda existe (precisa do
// id_token_hint, lido server-side em /api/auth/keycloak-logout-url);
// 2) só então limpa a sessão local (signOut, sem redirecionar ainda);
// 3) navega o navegador até o Keycloak para encerrar a sessão lá também.
// Chamar apenas signOut() deixaria a sessão viva no provedor de
// identidade — outra aba, ou um login silencioso, reautenticaria sem
// pedir credenciais de novo. Sessões do login local não têm id_token
// nenhum (ver next-auth.d.ts) — a chamada de qualquer forma funciona
// nesse caso, só resolve para logoutUrl = "/" (o valor padrão).
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

function initialsFrom(label: string): string {
  const parts = label.replace(/@.*/, "").split(/[.\s_-]+/).filter(Boolean);
  const chars = parts.length >= 2 ? [parts[0]?.[0] ?? "?", parts[1]?.[0] ?? "?"] : [label[0] ?? "?"];
  return chars.join("").toUpperCase();
}

// Menu do usuário no canto superior direito (§ Redesenho de layout):
// avatar com iniciais + dropdown com o rótulo do usuário e "Sair". O
// mesmo popover hand-rolled (useState + useRef + click-fora/Escape) já
// usado em NotificationBell — nenhuma biblioteca de UI-kit nova para
// isto, consistente com o resto deste kit de componentes.
export function UserMenu({ userLabel }: { userLabel: string }) {
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

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Menu do usuário ${userLabel}`}
        className="flex h-10 w-10 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground"
      >
        {initialsFrom(userLabel)}
      </button>

      {open && (
        // max-w-[calc(100vw-2rem)] — mesma folga de segurança de
        // NotificationBell, pro caso raro de userLabel ser um e-mail
        // longo demais numa tela muito estreita.
        <div
          role="menu"
          className="absolute right-0 top-11 z-50 w-56 max-w-[calc(100vw-2rem)] rounded-md border border-surface-border bg-surface py-1 shadow-lg"
        >
          <div className="truncate border-b border-surface-border px-3 py-2 text-sm text-muted">
            {userLabel}
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={() => void fullSignOut()}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-black/5 dark:hover:bg-white/5"
          >
            <LogOut size={15} aria-hidden="true" />
            Sair
          </button>
        </div>
      )}
    </div>
  );
}
