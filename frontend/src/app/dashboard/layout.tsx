import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import type { ReactNode } from "react";

import { DashboardShell } from "@/components/layout/DashboardShell";
import { authOptions } from "@/lib/auth/options";

// Defesa em profundidade: o proxy.ts já redireciona visitantes não
// autenticados para fora de /dashboard/**, mas uma checagem também no
// layout garante que este grupo de rotas nunca é renderizado sem uma
// sessão válida, mesmo que o matcher do proxy seja malconfigurado no
// futuro.
export default async function DashboardLayout({ children }: { children: ReactNode }) {
  const session = await getServerSession(authOptions);
  if (!session || session.error) {
    redirect("/login");
  }

  const userLabel = session.user?.email ?? session.user?.name ?? "Autenticado";

  return <DashboardShell userLabel={userLabel}>{children}</DashboardShell>;
}
