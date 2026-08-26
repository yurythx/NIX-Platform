import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { Section } from "@/components/ui/Section";
import { PaginatedFindingsFeed } from "@/components/scanning/PaginatedFindingsFeed";
import { ScanList } from "@/components/scanning/ScanList";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { PaginationMeta, ScanFinding, ScanStatus } from "@/types/api";

// Segurança (revisão de exibição de resultados — pedido do usuário:
// "não seria melhor abrir uma tela inicial em segurança com os scans
// que já foram feitos, quais ferramentas foram usadas nesse scan e
// quais erros e warnings foram achados?"): esta página virou a TELA
// INICIAL de histórico — ScanList (cada execução, ferramentas usadas,
// erro/warning contados por severidade) é o primeiro conteúdo, não mais
// um formulário de disparo. "Novo scan" (botão em destaque) leva pra
// /seguranca/novo, que é literalmente a página que existia AQUI antes
// desta revisão (TriggerScanForm + Projetos + a tela de saúde das
// ferramentas, pedida junto).
//
// "Achados recentes" (a visão AGREGADA entre todos os scans) continua
// existindo, só que rebaixada pro fim da página — ainda útil pra achar
// "o que há de mais grave em qualquer lugar" sem abrir scan por scan,
// mas não é mais a primeira coisa que a tela mostra.
export default async function SegurancaPage() {
  let scans: ScanStatus[] = [];
  let scansError: string | null = null;
  try {
    const { data } = await serverApiGet<ScanStatus[]>("v1/scanning/scans?limit=20");
    scans = data;
  } catch (err) {
    scansError = err instanceof ApiError ? err.message : "Falha ao carregar scans recentes";
  }

  // Fase 14 (Maturidade de AppSec): só a PRIMEIRA página é buscada aqui
  // (Server Component, primeiro paint rápido) — páginas seguintes são
  // responsabilidade do PaginatedFindingsFeed (Client Component,
  // "Carregar mais"), que recebe findings/meta já prontos em vez de
  // buscar tudo de novo.
  let findings: ScanFinding[] = [];
  let findingsMeta: PaginationMeta | undefined;
  let findingsError: string | null = null;
  try {
    const { data, meta } = await serverApiGet<ScanFinding[]>("v1/scanning/findings?page=1&page_size=50");
    findings = data;
    findingsMeta = meta as PaginationMeta | undefined;
  } catch (err) {
    findingsError = err instanceof ApiError ? err.message : "Falha ao carregar achados";
  }

  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Segurança</h1>
          <p className="text-sm text-muted">
            Scans já disparados, as ferramentas usadas em cada um e os achados por severidade.
          </p>
        </div>
        <Link href="/seguranca/novo">
          <Button>Novo scan</Button>
        </Link>
      </div>

      <Section title="Scans recentes">
        {scansError ? <ErrorState message={scansError} /> : <ScanList scans={scans} />}
      </Section>

      <Section title="Achados recentes" description="Agregado de todos os scans, mais recentes primeiro.">
        {findingsError ? (
          <ErrorState message={findingsError} />
        ) : (
          <PaginatedFindingsFeed initialFindings={findings} initialMeta={findingsMeta} />
        )}
      </Section>
    </div>
  );
}
