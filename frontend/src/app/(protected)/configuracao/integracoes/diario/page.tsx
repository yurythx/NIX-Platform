import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { DiarioTestButton } from "@/components/integrations/DiarioTestButton";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Integration } from "@/types/api";

// Detalhe da integração com o Diário Oficial, dentro da aba
// "Integrações" de /configuracao. Server Component (§ Migração pra
// Server Components) — busca o status no servidor; só o botão "Rodar
// teste agora" (DiarioTestButton) continua client, por ser genuinamente
// interativo.
export default async function DiarioOficialPage() {
  let integration: Integration | undefined;
  let errorMessage: string | null = null;
  try {
    const { data } = await serverApiGet<Integration[]>("v1/integrations");
    integration = data.find((i) => i.key === "diario-oficial");
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar";
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Diário Oficial</h1>
        <p className="text-sm text-muted">
          Executa uma verificação assíncrona de conectividade com o endpoint configurado do Diário
          Oficial.
        </p>
      </div>

      {errorMessage && <ErrorState message={errorMessage} />}

      {integration && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle>Status da conexão</CardTitle>
            <StatusIndicator status={integration.status} />
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
              <dt>Última verificação</dt>
              <dd>
                {integration.last_check_at
                  ? new Date(integration.last_check_at).toLocaleString()
                  : "Nunca"}
              </dd>
              <dt>Último sucesso</dt>
              <dd>
                {integration.last_success_at
                  ? new Date(integration.last_success_at).toLocaleString()
                  : "—"}
              </dd>
            </dl>
            {integration.last_error && (
              <p className="text-sm text-danger">{integration.last_error}</p>
            )}

            <DiarioTestButton />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
