import { Check, ShieldCheck } from "lucide-react";
import { connection } from "next/server";
import { cookies } from "next/headers";
import Link from "next/link";
import { Suspense } from "react";

import { LoginCard } from "@/components/auth/LoginCard";
import { ThemeToggle } from "@/components/ui/ThemeToggle";

// O que este painel de marca promete é literalmente o que a plataforma
// faz — nada de recursos inventados/de outro produto (a versão anterior
// desta página foi inspirada em papermoon.cloud, mas seus recursos
// listados eram do produto DELES, não fazia sentido copiar o texto).
const features = [
  "Integrações extensíveis (Diário Oficial, SecOps/VirusTotal e mais)",
  "Notificações em tempo real via WebSocket",
  "Auditoria imutável de toda ação sensível",
  "Resiliência: circuit breaker e retry automático",
];

export default async function LoginPage() {
  // Força renderização dinâmica — necessário para que o
  // Content-Security-Policy com nonce (proxy.ts) seja aplicado
  // corretamente; veja o comentário equivalente em app/page.tsx.
  await connection();

  // Mesmo cookie "nix-theme" que o dashboard lê (app/dashboard/layout.tsx)
  // — o login também tem um ThemeToggle (canto superior direito, como no
  // painel direito do papermoon), então precisa do mesmo tratamento
  // sem-flash.
  const cookieStore = await cookies();
  const themeCookie = cookieStore.get("nix-theme")?.value;
  const initialTheme = themeCookie === "dark" || themeCookie === "light" ? themeCookie : undefined;

  return (
    <div className="flex min-h-screen">
      {/* Painel de marca — só no desktop (lg: e acima), igual ao
          comportamento do papermoon.cloud: abaixo disso a tela vira só o
          formulário, centralizado. */}
      <div className="relative hidden overflow-hidden bg-brand-panel text-primary-foreground lg:flex lg:w-[44%] lg:flex-col lg:justify-between lg:p-12">
        <div
          className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-white/10 blur-3xl"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute -bottom-32 -right-16 h-96 w-96 rounded-full bg-black/20 blur-3xl"
          aria-hidden="true"
        />

        <div className="relative flex items-center gap-2 text-lg font-semibold">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/15 text-sm font-bold">
            N
          </span>
          NIX Platform
        </div>

        <div className="relative flex flex-col gap-6">
          <h1 className="text-3xl font-semibold leading-tight">
            Uma plataforma modular para suas integrações
          </h1>
          <p className="max-w-sm text-sm text-primary-foreground/80">
            Centralize integrações, automações e notificações corporativas num único painel
            seguro e extensível.
          </p>
          <ul className="flex flex-col gap-3 text-sm">
            {features.map((feature) => (
              <li key={feature} className="flex items-center gap-3">
                <span
                  aria-hidden="true"
                  className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/15"
                >
                  <Check size={13} />
                </span>
                {feature}
              </li>
            ))}
          </ul>
        </div>

        <p className="relative flex items-center gap-2 text-xs text-primary-foreground/60">
          <ShieldCheck size={14} aria-hidden="true" />
          Segurança por padrão — RS256, auditoria e bloqueio de conta
        </p>
      </div>

      {/* Painel do formulário */}
      <div className="relative flex flex-1 flex-col items-center justify-center p-6">
        <div className="absolute right-4 top-4">
          <ThemeToggle initialTheme={initialTheme} />
        </div>

        <Link href="/" className="mb-10 flex items-center gap-2 text-lg font-semibold lg:hidden">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-sm font-bold text-primary-foreground">
            N
          </span>
          NIX Platform
        </Link>

        <Suspense fallback={null}>
          <LoginCard />
        </Suspense>

        <Link href="/" className="mt-10 text-xs text-muted hover:text-foreground">
          ← Voltar para a página inicial
        </Link>
      </div>
    </div>
  );
}
