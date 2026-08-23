import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ErrorState } from "@/components/ui/ErrorState";
import { FeatureFlagsPanel } from "@/components/settings/FeatureFlagsPanel";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { FeatureFlag } from "@/types/api";

// Aba "Sistema" (índice de /configuracao) — configuração dinâmica via
// feature flags. Server Component (§ Migração pra Server Components):
// busca a lista no servidor, incluindo o caso 403 (restrito a
// nix-admin), tratado aqui como um estado normal da UI — não repassado
// como erro genérico pra FeatureFlagsPanel, que só cuida da parte
// interativa (o toggle otimista) depois que a lista já chegou.
export default async function SistemaPage() {
  let flags: FeatureFlag[] | null = null;
  let forbidden = false;
  let errorMessage: string | null = null;

  try {
    const { data } = await serverApiGet<FeatureFlag[]>("v1/admin/feature-flags");
    flags = data;
  } catch (err) {
    if (err instanceof ApiError && err.status === 403) {
      forbidden = true;
    } else {
      errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar feature flags";
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Feature flags</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {forbidden && (
          <p className="text-sm text-muted">
            Restrito a administradores — sua conta não tem permissão para ver ou alterar feature
            flags.
          </p>
        )}
        {errorMessage && <ErrorState message={errorMessage} />}
        {flags && <FeatureFlagsPanel initialFlags={flags} />}
      </CardContent>
    </Card>
  );
}
