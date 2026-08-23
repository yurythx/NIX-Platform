"use client";

import { Moon, Sun } from "lucide-react";
import { useState } from "react";

import { usePrefersDark } from "@/lib/theme/usePrefersDark";

const COOKIE_NAME = "nix-theme";

// Alterna entre claro/escuro persistindo a escolha num cookie (lido
// server-side em app/layout.tsx/app/dashboard/layout.tsx) em vez de usar
// next-themes: a técnica usual dessa biblioteca para evitar flash de
// tema errado injeta um <script> inline no <head>, o que a CSP com nonce
// estrito deste app (script-src sem 'unsafe-inline' — ver src/proxy.ts)
// bloquearia. Um cookie lido no Server Component raiz alcança o mesmo
// resultado (o HTML já chega com data-theme certo) sem nenhum script
// inline.
//
// initialTheme vem do servidor (o mesmo cookie, já decodificado em
// app/dashboard/layout.tsx) — quando ausente (nenhuma escolha explícita
// ainda), usePrefersDark() decide o ícone a partir do SO via
// useSyncExternalStore, mantendo este componente livre de qualquer
// useEffect/setState-em-efeito.
export function ThemeToggle({ initialTheme }: { initialTheme?: "light" | "dark" }) {
  const prefersDark = usePrefersDark();
  const [explicit, setExplicit] = useState<"light" | "dark" | null>(initialTheme ?? null);
  const theme = explicit ?? (prefersDark ? "dark" : "light");

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setExplicit(next);
    document.documentElement.setAttribute("data-theme", next);
    // 1 ano, path=/ — o mesmo cookie que os layouts do servidor leem a
    // cada request seguinte para decidir o atributo data-theme já no
    // primeiro paint.
    document.cookie = `${COOKIE_NAME}=${next}; path=/; max-age=31536000; samesite=lax`;
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro"}
      title={theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro"}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-black/5 hover:text-foreground dark:hover:bg-white/5"
    >
      {theme === "dark" ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
    </button>
  );
}
