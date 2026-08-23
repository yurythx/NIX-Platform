"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

// Sub-navegação de /configuracao (§ Reestruturação de rotas): três
// seções — Sistema (index, feature flags), Integrações, Usuários — que
// antes viviam soltas sob /dashboard/*. Mesmo padrão de estado ativo por
// pathname já usado em Sidebar.tsx, só que como uma tira de abas
// horizontal em vez de itens verticais.
const tabs = [
  { href: "/configuracao", label: "Sistema" },
  { href: "/configuracao/integracoes", label: "Integrações" },
  { href: "/configuracao/usuarios", label: "Usuários" },
];

export default function ConfiguracaoLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Configurações</h1>
        <p className="text-sm text-muted">
          Integrações externas, usuários e configuração dinâmica do sistema.
        </p>
      </div>

      <nav aria-label="Configurações" className="border-b border-surface-border">
        <ul className="-mb-px flex gap-4">
          {tabs.map((tab) => {
            // Só /configuracao (o índice) precisa de match exato — as
            // outras duas abas não têm sub-rotas hoje, mas usar startsWith
            // pra elas também não custa nada e evita o mesmo bug se uma
            // sub-rota for adicionada depois.
            const active =
              pathname === tab.href || (tab.href !== "/configuracao" && pathname.startsWith(tab.href + "/"));
            return (
              <li key={tab.href}>
                <Link
                  href={tab.href}
                  aria-current={active ? "page" : undefined}
                  className={`inline-block border-b-2 px-1 pb-3 text-sm font-medium transition-colors
                    ${active ? "border-primary text-primary" : "border-transparent text-muted hover:text-foreground"}`}
                >
                  {tab.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {children}
    </div>
  );
}
