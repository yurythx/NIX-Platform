import type { HTMLAttributes } from "react";

// Família de componentes de cartão do kit de UI — puramente estrutural
// (layout/tipografia), sem regra de negócio; cada peça (Header/Title/
// Description/Content) é opcional e composta pelo consumidor conforme a
// necessidade de cada tela.
export function Card({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`rounded-xl border border-surface-border bg-surface shadow-sm ${className}`}
      {...rest}
    />
  );
}

export function CardHeader({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`px-5 pt-5 ${className}`} {...rest} />;
}

export function CardTitle({ className = "", ...rest }: HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={`text-sm font-semibold text-foreground ${className}`} {...rest} />;
}

export function CardDescription({ className = "", ...rest }: HTMLAttributes<HTMLParagraphElement>) {
  return <p className={`text-sm text-muted ${className}`} {...rest} />;
}

export function CardContent({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`px-5 pb-5 pt-3 ${className}`} {...rest} />;
}
