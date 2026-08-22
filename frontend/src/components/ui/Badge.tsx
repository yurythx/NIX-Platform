import type { HTMLAttributes } from "react";

// Selo (badge) genérico do kit de UI — sem regra de negócio própria, só
// aplica a cor de acordo com o "tone" recebido. Usado, por exemplo, para
// destacar status curtos em tabelas/cards.
type Tone = "neutral" | "success" | "danger" | "warning" | "info";

const toneClasses: Record<Tone, string> = {
  neutral: "bg-black/5 text-foreground dark:bg-white/10",
  success: "bg-green-100 text-green-800 dark:bg-green-500/15 dark:text-green-400",
  danger: "bg-red-100 text-red-800 dark:bg-red-500/15 dark:text-red-400",
  warning: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  info: "bg-blue-100 text-blue-800 dark:bg-blue-500/15 dark:text-blue-400",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
}

export function Badge({ tone = "neutral", className = "", ...rest }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${toneClasses[tone]} ${className}`}
      {...rest}
    />
  );
}
