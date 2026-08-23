import Link from "next/link";

import { Button } from "@/components/ui/Button";

// 404 no tema da aplicação (§ auditoria 2026-08) em vez da página padrão,
// não estilizada, do Next.js. Server Component simples — cobre tanto
// notFound() explícito quanto qualquer URL sem rota correspondente (o
// app/not-found.tsx da raiz é automaticamente o 404 global — ver a nota
// "Root app/not-found handles global unmatched URLs" na documentação do
// Next.js). Mesmo tom visual de EmptyState.tsx (borda tracejada, texto
// centralizado), mas fora da árvore de componentes do dashboard — esta
// página também é a primeira coisa que um visitante deslogado vê ao
// digitar uma URL errada, então usa Card em vez de EmptyState.
export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
      <p className="font-mono text-sm text-muted">404</p>
      <h1 className="text-2xl font-semibold text-foreground">Página não encontrada</h1>
      <p className="max-w-sm text-sm text-muted">
        O endereço que você tentou acessar não existe ou foi movido.
      </p>
      <Link href="/">
        <Button size="md" className="mt-2">
          Voltar para o início
        </Button>
      </Link>
    </div>
  );
}
