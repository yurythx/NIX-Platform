import {
  Bell,
  Blocks,
  Bug,
  FileCheck,
  Globe,
  KeyRound,
  Link as LinkIcon,
  Lock,
  Package,
  ScrollText,
  Settings,
  ShieldCheck,
  UserCheck,
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
  "Plataforma modular que centraliza integrações, automações e notificações corporativas — construída com o OWASP Top 10 como checklist de engenharia, não como slide de venda.";

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
      "Diário Oficial hoje, e um padrão pronto para adicionar o próximo provedor sem tocar no núcleo da plataforma.",
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

// Mapeamento OWASP Top 10 -> prática concreta já implementada, não uma
// promessa (§ auditoria + docs/roadmap-secops-orchestrator.md, que
// documenta o restante em fase de planejamento — SAST/DAST/scanning de
// container ainda não fazem parte do produto, só do roadmap). Cada linha
// aqui foi conferida no código durante esta sessão, não copiada de um
// checklist genérico: A03 e A10, por exemplo, foram checados com grep no
// backend inteiro antes de escrever a frase.
const owaspPractices = [
  {
    code: "A01",
    icon: Lock,
    title: "Broken Access Control",
    description: "RBAC por permissão em cada rota sensível — nunca só a presença de um token.",
  },
  {
    code: "A02",
    icon: KeyRound,
    title: "Cryptographic Failures",
    description: "RS256 com chave própria para o login local, bcrypt, segredos nunca em texto puro.",
  },
  {
    code: "A03",
    icon: Bug,
    title: "Injection",
    description: "Toda consulta é parametrizada — zero concatenação de string em SQL no backend inteiro.",
  },
  {
    code: "A04",
    icon: Blocks,
    title: "Insecure Design",
    description: "Monólito modular com fronteiras de módulo e decisões de arquitetura documentadas (ADRs).",
  },
  {
    code: "A05",
    icon: Settings,
    title: "Security Misconfiguration",
    description: "CSP com nonce por requisição, containers non-root, headers de segurança em toda resposta.",
  },
  {
    code: "A06",
    icon: Package,
    title: "Vulnerable Components",
    description: "govulncheck, npm audit, Trivy e Dependabot rodando a cada mudança de código.",
  },
  {
    code: "A07",
    icon: UserCheck,
    title: "Auth Failures",
    description: "Bloqueio de conta, rate limit distribuído, e nunca um erro que revele se um usuário existe.",
  },
  {
    code: "A08",
    icon: FileCheck,
    title: "Data Integrity Failures",
    description: "Idempotência e outbox transacional — nenhum evento duplicado, nenhuma escrita perdida.",
  },
  {
    code: "A09",
    icon: ScrollText,
    title: "Logging & Monitoring",
    description: "Auditoria imutável de toda ação sensível, logs correlacionados por request id.",
  },
  {
    code: "A10",
    icon: Globe,
    title: "SSRF",
    description: "Nenhum endpoint aceita uma URL arbitrária vinda de quem chama.",
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
            único painel — construído como um monólito modular, com o OWASP Top 10 tratado como
            checklist de engenharia em cada linha de código, não como selo de marketing.
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
            <h2 className="text-2xl font-semibold text-foreground">
              Segurança por padrão — OWASP Top 10
            </h2>
            <p className="mx-auto mt-1 max-w-2xl text-sm text-muted">
              As dez categorias, e a prática concreta que já existe no código pra cada uma —
              conferido nesta base de código, não copiado de um checklist genérico.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {owaspPractices.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.code}
                  className="flex flex-col gap-2 rounded-xl border border-surface-border bg-surface p-4"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <Icon size={16} aria-hidden="true" />
                    </span>
                    <div>
                      <p className="font-mono text-xs font-semibold text-primary">{item.code}</p>
                      <p className="text-xs font-medium text-foreground">{item.title}</p>
                    </div>
                  </div>
                  <p className="text-xs text-muted">{item.description}</p>
                </div>
              );
            })}
          </div>
          <p className="text-center text-xs text-muted">
            Um item (assinatura de artefatos de build, parte de A08) ainda não existe — está
            documentado como pendência, não escondido. Veja{" "}
            <Link href="/sobre" className="text-primary hover:underline">
              a página Sobre
            </Link>{" "}
            para o detalhe completo e o roadmap de segurança.
          </p>
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
