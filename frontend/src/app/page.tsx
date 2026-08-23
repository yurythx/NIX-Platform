import {
  Bell,
  Blocks,
  Link as LinkIcon,
  ScrollText,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { Metadata } from "next";
import { connection } from "next/server";
import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Logo } from "@/components/ui/Logo";

// §auditoria 2026-08: sem metadados públicos antes disto — só a página
// inicial e /sobre ganham (as únicas duas rotas públicas com algo que
// vale compartilhar; rotas autenticadas não têm por quê ser indexadas).
const description =
  "Plataforma modular que centraliza integrações, automações e notificações corporativas — construída como um monólito modular, com resiliência e segurança por padrão.";

export const metadata: Metadata = {
  title: "NIX Platform — integrações, automação e notificações",
  description,
  openGraph: { title: "NIX Platform", description, type: "website" },
};

// Serviços/módulos reais da plataforma — nada aqui é aspiracional, cada
// item corresponde a um módulo que já existe em backend/internal/modules
// ou internal/platform (§ Reestruturação de páginas: página inicial
// apresentando filosofia e serviços).
const services = [
  {
    icon: LinkIcon,
    title: "Integrações extensíveis",
    description:
      "Diário Oficial, SecOps/VirusTotal e um padrão pronto para adicionar o próximo provedor sem tocar no núcleo da plataforma.",
  },
  {
    icon: Bell,
    title: "Notificações em tempo real",
    description: "Eventos de job e de integração chegam via WebSocket, com reconexão automática.",
  },
  {
    icon: ScrollText,
    title: "Auditoria imutável",
    description: "Toda ação sensível fica registrada — inclusive tentativas de login malsucedidas.",
  },
  {
    icon: ShieldCheck,
    title: "Segurança por padrão",
    description:
      "OIDC via Keycloak, login local com RSA e bloqueio de conta, CSP com nonce, rate limiting distribuído.",
  },
  {
    icon: Users,
    title: "Gestão de usuários",
    description: "Contas via Keycloak ou login local coexistindo na mesma base, com os mesmos papéis.",
  },
  {
    icon: Blocks,
    title: "Configuração dinâmica",
    description: "Feature flags alteráveis em tempo real, sem reimplantar a aplicação.",
  },
];

export default async function LandingPage() {
  // Força renderização dinâmica (não estática) — necessário para que o
  // Content-Security-Policy com nonce gerado a cada requisição em
  // proxy.ts seja efetivamente aplicado aos scripts desta página. Uma
  // página pré-renderizada em build-time é sempre o mesmo HTML, sem
  // nenhum nonce embutido, então o navegador bloquearia os próprios
  // scripts do framework.
  await connection();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between px-6 py-5">
        <span className="flex items-center gap-2 text-lg font-semibold">
          <Logo size={32} />
          NIX Platform
        </span>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/sobre" className="text-muted hover:text-foreground">
            Sobre
          </Link>
          <Link href="/login">
            <Button size="sm">Entrar</Button>
          </Link>
        </nav>
      </header>

      <main className="flex flex-1 flex-col gap-20 px-6 py-12">
        <section className="mx-auto flex max-w-2xl flex-col items-center gap-6 text-center">
          <h1 className="text-4xl font-bold tracking-tight text-foreground sm:text-5xl">
            Uma plataforma modular para suas integrações
          </h1>
          <p className="max-w-xl text-muted">
            O NIX Platform centraliza integrações, automações e notificações corporativas num
            único painel seguro e extensível — construído como um monólito modular, para crescer
            sem virar um emaranhado de microsserviços prematuros.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link href="/login">
              <Button size="md">Entrar</Button>
            </Link>
            <Link href="/sobre">
              <Button size="md" variant="secondary">
                Conhecer a filosofia
              </Button>
            </Link>
          </div>
        </section>

        <section className="mx-auto flex w-full max-w-5xl flex-col gap-8">
          <div className="text-center">
            <h2 className="text-2xl font-semibold text-foreground">Serviços</h2>
            <p className="mt-1 text-sm text-muted">O que já roda em produção hoje.</p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {services.map((service) => {
              const Icon = service.icon;
              return (
                <Card key={service.title}>
                  <CardHeader className="flex flex-row items-center gap-3 space-y-0">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <Icon size={18} aria-hidden="true" />
                    </span>
                    <CardTitle className="text-base">{service.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted">{service.description}</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>
      </main>

      <footer className="border-t border-surface-border px-6 py-6 text-center text-xs text-muted">
        © {new Date().getFullYear()} NIX Platform — <Link href="/sobre" className="hover:text-foreground">Sobre a plataforma</Link>
      </footer>
    </div>
  );
}
