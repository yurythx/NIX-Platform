import { connection } from "next/server";
import Link from "next/link";

import { Button } from "@/components/ui/Button";

export default async function LandingPage() {
  // Força renderização dinâmica (não estática) — necessário para que o
  // Content-Security-Policy com nonce gerado a cada requisição em
  // proxy.ts seja efetivamente aplicado aos scripts desta página. Uma
  // página pré-renderizada em build-time é sempre o mesmo HTML, sem
  // nenhum nonce embutido, então o navegador bloquearia os próprios
  // scripts do framework.
  await connection();

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 p-6 text-center">
      <div>
        <h1 className="text-3xl font-semibold text-foreground">NIX Platform</h1>
        <p className="mt-2 max-w-md text-muted">
          Uma plataforma corporativa modular que centraliza integrações, automações e
          notificações num único painel extensível.
        </p>
      </div>
      <Link href="/dashboard">
        <Button size="md">Ir para o painel</Button>
      </Link>
    </div>
  );
}
