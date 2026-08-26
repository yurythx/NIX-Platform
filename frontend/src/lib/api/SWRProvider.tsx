"use client";

import { SWRConfig } from "swr";
import type { ReactNode } from "react";

import { defaultSWRConfig } from "@/lib/api/swr";

// SWRProvider: monta defaultSWRConfig uma única vez, no topo da área
// autenticada (app/(protected)/layout.tsx) — todo useApiQuery/useSWR
// dentro dela reaproveita o mesmo cache/dedup, mesmo em componentes que
// nunca se importam entre si (ex.: um card de status em /dashboard e a
// página de detalhe da mesma integração).
export function SWRProvider({ children }: { children: ReactNode }) {
  return <SWRConfig value={defaultSWRConfig}>{children}</SWRConfig>;
}
