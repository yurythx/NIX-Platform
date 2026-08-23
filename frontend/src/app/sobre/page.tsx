import { Layers, Lock, Radar, RefreshCw } from "lucide-react";
import { connection } from "next/server";
import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";

// Princípios como o README/os ADRs deste repositório já os descrevem —
// não duplicando o texto deles, só resumindo pro visitante da página
// pública (§ Reestruturação de páginas: página "Sobre").
const principles = [
  {
    icon: Layers,
    title: "Monólito modular",
    description:
      "Um único deployable, dividido em módulos com fronteiras claras — a simplicidade operacional de um monólito sem virar um emaranhado de dependências internas.",
  },
  {
    icon: RefreshCw,
    title: "Resiliência",
    description:
      "Circuit breaker e retry com backoff em toda chamada a um provedor externo, fila de mensagens mortas (DLQ) e um outbox transacional — falhas são esperadas, não exceções.",
  },
  {
    icon: Lock,
    title: "Segurança por padrão",
    description:
      "Autenticação via Keycloak (OIDC) ou login local com chave RSA própria, CSP com nonce, auditoria imutável, rate limiting e bloqueio de conta — não itens adicionados depois.",
  },
  {
    icon: Radar,
    title: "Observabilidade",
    description:
      "Métricas Prometheus, tracing OpenTelemetry e logs estruturados correlacionados por request id em toda a pilha, do frontend ao worker.",
  },
];

export default async function AboutPage() {
  // Ver o comentário equivalente em app/page.tsx — necessário para o CSP
  // com nonce de proxy.ts.
  await connection();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between px-6 py-5">
        <Link href="/" className="flex items-center gap-2 text-lg font-semibold">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-sm font-bold text-primary-foreground">
            N
          </span>
          NIX Platform
        </Link>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/" className="text-muted hover:text-foreground">
            Início
          </Link>
          <Link href="/login">
            <Button size="sm">Entrar</Button>
          </Link>
        </nav>
      </header>

      <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-12 px-6 py-12">
        <section className="flex flex-col gap-4">
          <h1 className="text-3xl font-bold text-foreground">Sobre a plataforma</h1>
          <p className="text-muted">
            O NIX Platform existe para resolver um problema comum: integrações corporativas
            espalhadas em scripts avulsos, sem auditoria, sem resiliência a falhas e sem um lugar
            único para acompanhar o que está funcionando. A proposta é simples — um painel
            modular onde cada integração nova segue o mesmo padrão, é observável do mesmo jeito, e
            nunca compromete a segurança das demais.
          </p>
        </section>

        <section className="flex flex-col gap-4">
          <h2 className="text-xl font-semibold text-foreground">Princípios</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {principles.map((principle) => {
              const Icon = principle.icon;
              return (
                <Card key={principle.title}>
                  <CardHeader className="flex flex-row items-center gap-3 space-y-0">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <Icon size={18} aria-hidden="true" />
                    </span>
                    <CardTitle className="text-base">{principle.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted">{principle.description}</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold text-foreground">Como é construído</h2>
          <p className="text-muted">
            Backend em Go (monólito modular, PostgreSQL, RabbitMQ com outbox transacional) e
            frontend em Next.js/TypeScript, ambos containerizados. Todo o código, decisões de
            arquitetura (ADRs) e a documentação da API estão versionados junto com o resto do
            repositório — nada sobre esta plataforma vive só na cabeça de quem a construiu.
          </p>
        </section>
      </main>

      <footer className="border-t border-surface-border px-6 py-6 text-center text-xs text-muted">
        © {new Date().getFullYear()} NIX Platform
      </footer>
    </div>
  );
}
