import { Layers, Lock, Radar, RefreshCw } from "lucide-react";
import type { Metadata } from "next";
import { connection } from "next/server";
import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Logo } from "@/components/ui/Logo";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";

const description =
  "Princípios de arquitetura do NIX Platform, o mapeamento completo contra o OWASP Top 10 e como a plataforma é construída.";

export const metadata: Metadata = {
  title: "Sobre — NIX Platform",
  description,
  openGraph: { title: "Sobre o NIX Platform", description, type: "website" },
};

// Mesma matriz de docs/roadmap-secops-orchestrator.md — mantida em
// sincronia manualmente (o roadmap é o documento fonte, esta página é o
// resumo pro público). Cada célula da coluna "Hoje" foi conferida no
// código durante a auditoria de 2026-08 e a sessão seguinte, não copiada
// de um checklist genérico — em especial A03 (zero concatenação de
// string em SQL, checado com grep no backend inteiro) e A10 (nenhum
// endpoint aceita URL arbitrária do chamador, mesma checagem).
const owaspMapping = [
  { code: "A01", risk: "Broken Access Control", today: "RBAC por permissão em cada rota sensível — nunca só a presença de um token." },
  { code: "A02", risk: "Cryptographic Failures", today: "RS256 com chave própria para o login local, bcrypt, segredos via arquivo, nunca em texto puro." },
  { code: "A03", risk: "Injection", today: "100% consultas parametrizadas — conferido: zero concatenação de string em SQL em todo o backend." },
  { code: "A04", risk: "Insecure Design", today: "Monólito modular com fronteiras de módulo e decisões de arquitetura documentadas em ADRs." },
  { code: "A05", risk: "Security Misconfiguration", today: "CSP com nonce por requisição, containers non-root, headers de segurança em toda resposta." },
  { code: "A06", risk: "Vulnerable Components", today: "govulncheck, npm audit, Trivy e Dependabot rodando a cada mudança de código, no CI." },
  { code: "A07", risk: "Identification & Auth Failures", today: "Bloqueio de conta, rate limiting distribuído, erro sempre genérico (nunca revela se um usuário existe)." },
  { code: "A08", risk: "Software & Data Integrity Failures", today: "Idempotência e outbox transacional. Pendente: assinatura/SBOM de artefatos de build (ver roadmap)." },
  { code: "A09", risk: "Logging & Monitoring Failures", today: "Auditoria imutável (a tabela recusa UPDATE/DELETE), logs correlacionados por request id, métricas e tracing." },
  { code: "A10", risk: "SSRF", today: "Conferido: nenhum endpoint aceita uma URL arbitrária vinda de quem chama." },
];

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
          <Logo size={32} />
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

        <section className="flex flex-col gap-4">
          <div>
            <h2 className="text-xl font-semibold text-foreground">OWASP Top 10</h2>
            <p className="mt-1 text-sm text-muted">
              Tratado como checklist de engenharia desde o primeiro commit, não como algo
              adicionado depois de pronto. A coluna da direita descreve a prática de hoje — quando
              algo ainda está pendente, dizemos isso em vez de deixar de fora.
            </p>
          </div>
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Risco</TableHeaderCell>
                <TableHeaderCell>Prática hoje no NIX Platform</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {owaspMapping.map((item) => (
                <TableRow key={item.code}>
                  <TableCell className="whitespace-nowrap align-top font-medium text-foreground">
                    <span className="font-mono text-xs text-primary">{item.code}</span>{" "}
                    {item.risk}
                  </TableCell>
                  <TableCell className="text-muted">{item.today}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="text-sm text-muted">
            Estamos expandindo isso para varredura automatizada de código e dependências (SAST,
            scanning de containers, segredos vazados, testes dinâmicos) orquestrada pelo mesmo
            padrão que já usamos para o VirusTotal hoje — o plano completo, fase por fase, está em{" "}
            <code className="rounded bg-black/5 px-1 py-0.5 text-xs dark:bg-white/10">
              docs/roadmap-secops-orchestrator.md
            </code>{" "}
            no repositório.
          </p>
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
