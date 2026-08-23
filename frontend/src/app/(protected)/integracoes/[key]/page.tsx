import { notFound } from "next/navigation";

import { ErrorState } from "@/components/ui/ErrorState";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { integrationRegistry } from "@/lib/integrations/registry";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Integration } from "@/types/api";

// Página de detalhe de UMA integração (§ Integrações como menu próprio):
// genérica por chave (params.key), não uma rota por integração — a
// próxima integração que o NIX ganhar já cai aqui automaticamente, sem
// precisar de um novo arquivo de rota. "Configurar e testar" hoje
// significa: mostrar o status real (via IntegrationCard, que já sabe
// desenhar status/datas/último erro) e, se a integração tiver uma entrada
// em lib/integrations/registry.ts, o botão de testar conexão. Uma
// integração sem entrada no registro ainda renderiza aqui — só sem botão
// de teste, porque não há pra onde apontá-lo ainda.
export default async function IntegrationDetailPage({
  params,
}: {
  params: Promise<{ key: string }>;
}) {
  const { key } = await params;

  let integration: Integration | undefined;
  let errorMessage: string | null = null;
  try {
    const { data } = await serverApiGet<Integration[]>("v1/integrations");
    integration = data.find((i) => i.key === key);
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar";
  }

  if (!errorMessage && !integration) {
    notFound();
  }

  const registryEntry = integrationRegistry[key];

  return (
    <div className="flex flex-col gap-6">
      {errorMessage && <ErrorState message={errorMessage} />}

      {integration && (
        <>
          <div>
            <h1 className="text-xl font-semibold">{integration.name}</h1>
            <p className="text-sm text-muted">
              {registryEntry?.description ?? "Configuração e teste de conectividade desta integração."}
            </p>
          </div>

          <IntegrationCard integration={integration} testPath={registryEntry?.testPath} />
        </>
      )}
    </div>
  );
}
