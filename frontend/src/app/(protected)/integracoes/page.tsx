import Link from "next/link";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/ErrorState";
import { IntegrationCard } from "@/components/integrations/IntegrationCard";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Integration } from "@/types/api";

// Integrações (§ menu próprio, separado de Configurações): lista toda
// integração que o NIX Platform tem hoje e vai ganhando com o tempo —
// cada card leva pra uma página de detalhe genérica
// (integracoes/[key]/page.tsx) onde de fato se configura/testa aquela
// integração. A lista em si é só pra navegar; testar acontece na página
// de detalhe, não aqui (por isso nenhum card recebe testPath).
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
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Integrações</h1>
        <p className="text-sm text-muted">
          Sistemas externos aos quais o NIX Platform se conecta — clique em uma para configurar e
          testar.
        </p>
      </div>

      {errorMessage && <ErrorState message={errorMessage} />}

      {integrations && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {integrations.map((integration) => (
            <IntegrationCard
              key={integration.id}
              integration={integration}
              extra={
                <Link href={`/integracoes/${integration.key}`}>
                  <Button size="sm" variant="ghost">
                    Ver detalhes
                  </Button>
                </Link>
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}
