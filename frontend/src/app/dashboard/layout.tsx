import { getServerSession } from "next-auth/next";
import { cookies } from "next/headers";
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

  // Mesmo cookie "nix-theme" que ThemeToggle.tsx escreve — lido aqui (não
  // só no layout raiz) porque ThemeToggle só existe dentro do dashboard;
  // ver o comentário em ThemeToggle.tsx sobre por que isto evita o flash
  // de tema errado sem precisar de um <script> inline (bloqueado pela CSP
  // com nonce — src/proxy.ts).
  const cookieStore = await cookies();
  const themeCookie = cookieStore.get("nix-theme")?.value;
  const initialTheme = themeCookie === "dark" || themeCookie === "light" ? themeCookie : undefined;

  return (
    <DashboardShell userLabel={userLabel} initialTheme={initialTheme}>
      {children}
    </DashboardShell>
  );
}
