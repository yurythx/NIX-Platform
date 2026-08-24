import { getServerSession } from "next-auth/next";
import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { authOptions } from "@/lib/auth/options";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Integration } from "@/types/api";

// Visão geral (§ Reestruturação de rotas): a partir de agora /dashboard
// serve SÓ isto — status do sistema e atalhos. Usuários, integrações e
// configuração dinâmica vivem em /configuracao.
//
// Server Component (§ Migração pra Server Components — auditoria
// 2026-08): busca a sessão e a lista de integrações no servidor, antes de
// qualquer HTML sair — nada de useEffect/skeleton manual aqui. Não há
// nada nesta página que precise reagir a estado do navegador; os
// "atalhos" abaixo são só <Link>, e loading.tsx (nesta mesma pasta) cobre
// o estado de carregamento via Suspense em vez de um skeleton escrito à
// mão.
export default async function DashboardOverviewPage() {
  const session = await getServerSession(authOptions);
  const firstName = (session?.user?.name ?? session?.user?.email ?? "").split(/[@\s]/)[0];

  let integrations: Integration[] | null = null;
  let errorMessage: string | null = null;
  try {
    const { data } = await serverApiGet<Integration[]>("v1/integrations");
    integrations = data;
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar";
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">
          {firstName ? `Olá, ${firstName}` : "Visão geral"}
        </h1>
        <p className="text-sm text-muted">Status do sistema e ações rápidas.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/seguranca">
          <Button variant="secondary" size="sm">
            Ver achados de segurança
          </Button>
        </Link>
        <Link href="/integracoes">
          <Button variant="secondary" size="sm">
            Ver integrações
          </Button>
        </Link>
        <Link href="/integracoes/diario-oficial">
          <Button variant="secondary" size="sm">
            Testar Diário Oficial
          </Button>
        </Link>
        <Link href="/configuracao/usuarios">
          <Button variant="secondary" size="sm">
            Ver usuários
          </Button>
        </Link>
        <Link href="/configuracao">
          <Button variant="secondary" size="sm">
            Ver configurações
          </Button>
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Status das integrações</CardTitle>
        </CardHeader>
        <CardContent>
          {errorMessage && <ErrorState message={errorMessage} />}
          {integrations && (
            <ul className="flex flex-col gap-3">
              {integrations.map((integration) => (
                <li key={integration.id} className="flex items-center justify-between">
                  <span className="text-sm">{integration.name}</span>
                  <StatusIndicator status={integration.status} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
