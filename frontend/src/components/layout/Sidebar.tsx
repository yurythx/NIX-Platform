"use client";

import { LayoutDashboard, Settings, Users, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";

const links = [
  { href: "/dashboard", label: "Visão geral", icon: LayoutDashboard },
  { href: "/dashboard/users", label: "Usuários", icon: Users },
  { href: "/dashboard/settings", label: "Configurações", icon: Settings },
];

interface SidebarProps {
  /** Recolhida a ícone-somente no desktop (md: e acima) — persistida pelo
   * chamador (DashboardShell) em localStorage, uma preferência puramente
   * do dispositivo/navegador, não algo que precise sincronizar entre
   * abas ou dispositivos. */
  collapsed: boolean;
  /** Aberta como painel flutuante no mobile (abaixo de md:) — sempre
   * fechada por padrão a cada navegação, ao contrário de "collapsed". */
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

// Navegação lateral (§ Redesenho de layout, inspirado em
// papermoon.cloud): recolhível a uma trilha de ícones no desktop, e um
// painel off-canvas com overlay no mobile — mesmo componente cobrindo os
// dois casos via classes condicionais, em vez de dois componentes
// separados.
export function Sidebar({ collapsed, mobileOpen, onCloseMobile }: SidebarProps) {
  const pathname = usePathname();

  // Fecha o painel mobile com Escape, e trava o scroll do body enquanto
  // ele está aberto — o mesmo comportamento de qualquer off-canvas/modal.
  useEffect(() => {
    if (!mobileOpen) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onCloseMobile();
    }
    document.addEventListener("keydown", onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [mobileOpen, onCloseMobile]);

  return (
    <>
      {/* Overlay do painel mobile — só existe (e só captura clique) com o
          painel aberto; invisível e fora do fluxo de layout no desktop. */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/40 md:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <nav
        aria-label="Principal"
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-surface-border bg-surface
          transition-transform duration-200 md:static md:z-auto md:translate-x-0
          ${collapsed ? "md:w-16" : "md:w-56"}
          ${mobileOpen ? "translate-x-0" : "-translate-x-full"} w-64`}
      >
        <div className="flex items-center justify-between px-4 py-4">
          {!collapsed && <span className="text-lg font-semibold">NIX Platform</span>}
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Fechar menu"
            className="rounded-md p-1 text-muted hover:bg-black/5 hover:text-foreground dark:hover:bg-white/5 md:hidden"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <ul className="flex flex-col gap-1 px-2">
          {links.map((link) => {
            const Icon = link.icon;
            // startsWith cobre sub-rotas (ex.: /dashboard/settings/integrations/diario
            // ainda deve marcar "Configurações" como ativa) — só para
            // /dashboard, que "contém" toda rota do dashboard, é preciso o
            // match exato pra não marcar todo item como ativo ao mesmo tempo.
            const active =
              pathname === link.href ||
              (link.href !== "/dashboard" && pathname.startsWith(link.href + "/"));
            return (
              <li key={link.href}>
                <Link
                  href={link.href}
                  onClick={onCloseMobile}
                  title={collapsed ? link.label : undefined}
                  aria-current={active ? "page" : undefined}
                  className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors
                    ${active ? "bg-primary/10 text-primary" : "text-foreground hover:bg-black/5 dark:hover:bg-white/5"}
                    ${collapsed ? "md:justify-center" : ""}`}
                >
                  <Icon size={18} aria-hidden="true" className="shrink-0" />
                  <span className={collapsed ? "md:hidden" : ""}>{link.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </>
  );
}
