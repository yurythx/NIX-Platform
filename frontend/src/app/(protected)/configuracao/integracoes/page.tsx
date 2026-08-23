import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Integration } from "@/types/api";

// Mapeia a chave de uma integração para o endpoint de teste e/ou uma
// página de detalhe dedicada, sem embutir regra de negócio no próprio
// card genérico (IntegrationCard, que continua "use client" — o botão
// "Testar conexão" é genuinamente interativo).
const testPathByKey: Record<string, string> = {
  virustotal: "v1/integrations/secops/virustotal/test",
};

// Aba "Integrações" de /configuracao. Server Component (§ Migração pra
// Server Components) — busca a lista no servidor; loading.tsx cobre o
// carregamento via Suspense.
export default async function IntegracoesPage() {
  let integrations: Integration[] | null = null;
  let errorMessage: string | null = null;
  try {
    const { data } = await serverApiGet<Integration[]>("v1/integrations");
    integrations = data;
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar integrações";
  }

  return (
    <div className="flex flex-col gap-4">
      {errorMessage && <ErrorState message={errorMessage} />}

      {integrations && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {integrations.map((integration) =>
            integration.key === "diario-oficial" ? (
              <IntegrationCard
                key={integration.id}
                integration={integration}
                extra={
                  <Link href="/configuracao/integracoes/diario">
                    <Button size="sm" variant="ghost">
                      Detalhes
                    </Button>
                  </Link>
                }
              />
            ) : (
              <IntegrationCard
                key={integration.id}
                integration={integration}
                testPath={testPathByKey[integration.key]}
              />
            ),
          )}
        </div>
      )}
    </div>
  );
}
