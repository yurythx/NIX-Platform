import type { HTMLAttributes } from "react";

// Placeholder de carregamento (loading skeleton): um bloco cinza pulsante
// que ocupa o espaço do conteúdo real enquanto ele ainda não chegou.
// aria-hidden porque é puramente visual — leitores de tela não devem
// anunciá-lo.
export function Skeleton({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`animate-pulse rounded-md bg-black/10 dark:bg-white/10 ${className}`}
      aria-hidden="true"
      {...rest}
    />
  );
}
