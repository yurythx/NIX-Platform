"use client"; // error.tsx é sempre um Client Component — exigência do próprio Next.js.

import { Button } from "@/components/ui/Button";

// Fallback de erro no tema da aplicação (§ auditoria 2026-08), substitui
// a página padrão não estilizada do Next.js quando um erro não tratado
// escapa de uma página. `retry` (estável desde o Next.js 16.3 — ver
// node_modules/next/dist/docs/.../error.md) tenta buscar/renderizar de
// novo o segmento que falhou, sem recarregar a página inteira; é o que a
// própria documentação recomenda em vez de `reset` para o caso comum de
// "tentar de novo". Mesmo tom de ErrorState.tsx (mesma mensagem "Algo deu
// errado" e rótulo "Tentar novamente"), mas fora da árvore do dashboard
// (um erro aqui pode ter acontecido antes do DashboardShell renderizar).
export default function GlobalError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center"
    >
      <p className="text-sm font-medium text-danger">Algo deu errado</p>
      <p className="max-w-sm text-sm text-muted">
        Um erro inesperado interrompeu esta página.
        {error.digest && (
          <>
            {" "}
            Código de referência: <code className="font-mono text-xs">{error.digest}</code>
          </>
        )}
      </p>
      <Button size="md" className="mt-2" onClick={() => retry()}>
        Tentar novamente
      </Button>
    </div>
  );
}
