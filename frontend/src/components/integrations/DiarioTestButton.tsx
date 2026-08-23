"use client";

import { useState } from "react";

import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { TestJobResponse } from "@/types/api";

// Extraído de app/(protected)/configuracao/integracoes/diario/page.tsx
// (§ Migração pra Server Components) — o único pedaço genuinamente
// interativo daquela página; o resto (status, datas, último erro) agora é
// buscado no servidor e não precisa de "use client" nenhum.
export function DiarioTestButton() {
  const { showToast } = useToast();
  const [testing, setTesting] = useState(false);
  const [lastJobId, setLastJobId] = useState<string | null>(null);

  const runTest = async () => {
    setTesting(true);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/integrations/diario-oficial/test");
      setLastJobId(data.job_id);
      showToast({
        title: "Verificação do Diário Oficial enfileirada",
        description: `Job ${data.job_id.slice(0, 8)} — você será notificado quando terminar.`,
        tone: "info",
      });
    } catch (err) {
      showToast({
        title: "Não foi possível iniciar a verificação",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div>
      <Button loading={testing} onClick={() => void runTest()}>
        Rodar teste agora
      </Button>
      {lastJobId && (
        <p className="mt-2 text-xs text-muted">
          Último job disparado: <code>{lastJobId}</code> — o resultado chega como notificação.
        </p>
      )}
    </div>
  );
}
