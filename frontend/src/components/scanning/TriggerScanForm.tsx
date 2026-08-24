"use client";

import Link from "next/link";
import { useState, type FormEvent, type KeyboardEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { apiClient, ApiError } from "@/lib/api/client";
import { useToast } from "@/components/notifications/ToastProvider";
import { SCANNERS } from "@/lib/scanning/scannerRegistry";
import { useScanStatusPolling } from "@/lib/scanning/useScanStatusPolling";
import type { TestJobResponse } from "@/types/api";

import { ScanProgress } from "./ScanProgress";

// Dispara um scan novo (POST /api/v1/scanning/scans — Fase 7: mais de um
// scanner selecionado roda tudo em paralelo sob o mesmo job/scan_id) e
// acompanha o resultado aqui mesmo, via useScanStatusPolling — o painel
// de progresso (ScanProgress) mostra qual scanner está rodando agora,
// quanto falta, e — o pedido explícito do usuário — QUAL ferramenta
// encontrou um erro, de que TIPO foi e uma sugestão de COMO corrigir.
// Esse mesmo job também ganha sua própria página em
// /seguranca/[scanId] (link mostrado abaixo assim que o job_id existe) —
// "resultados separados por scan", não só um resultado que desaparece
// ao sair desta tela. NotificationCenter continua tratando o toast via
// WebSocket (scanning.scan.completed/failed) pra quem não ficar olhando
// esta tela até o fim — os dois não conflitam.
//
// Seleção de scanner em cards (não mais Toggle+label numa linha): pedido
// do usuário de "melhorar o layout do novo scan... uma descrição da
// ferramenta e pra que ela serve e como usa-la" — cada card já traz essa
// descrição (lib/scanning/scannerRegistry.ts, a mesma fonte que
// ScanProgress e ToolFindingsCards usam, pra nunca divergir em nome
// entre as telas), sem precisar abrir nenhum outro lugar pra entender o
// que cada scanner faz antes de escolher.
export function TriggerScanForm() {
  const { showToast } = useToast();
  const [selected, setSelected] = useState<Record<string, boolean>>({ trivy: true });
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const { status, polling } = useScanStatusPolling(jobId);

  const scanners = SCANNERS.filter((s) => selected[s.key]).map((s) => s.key);
  const zapSelected = selected.zap;

  function toggle(key: string) {
    setSelected((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function handleCardKeyDown(e: KeyboardEvent<HTMLDivElement>, key: string) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle(key);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (scanners.length === 0 || !target.trim()) return;

    setSubmitting(true);
    setJobId(null);
    try {
      const { data } = await apiClient.post<TestJobResponse>("v1/scanning/scans", {
        scanners,
        target: target.trim(),
      });
      showToast({
        title: "Scan disparado",
        description: `Job ${data.job_id.slice(0, 8)} — acompanhando o resultado abaixo.`,
        tone: "info",
      });
      setTarget("");
      setJobId(data.job_id);
    } catch (err) {
      showToast({
        title: "Não foi possível disparar o scan",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Novo scan</CardTitle>
        <CardDescription>Escolha um ou mais scanners e o alvo.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {SCANNERS.map((s) => {
              const checked = !!selected[s.key];
              return (
                <div
                  key={s.key}
                  role="switch"
                  aria-checked={checked}
                  aria-label={s.name}
                  tabIndex={0}
                  onClick={() => toggle(s.key)}
                  onKeyDown={(e) => handleCardKeyDown(e, s.key)}
                  className={`flex cursor-pointer flex-col gap-2 rounded-xl border p-4 text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                    checked
                      ? "border-primary bg-primary/10"
                      : "border-surface-border bg-surface hover:bg-black/5 dark:hover:bg-white/5"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="font-medium text-foreground">{s.name}</div>
                      <div className="text-xs text-muted">{s.category}</div>
                    </div>
                    <span
                      aria-hidden="true"
                      className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 text-xs ${
                        checked
                          ? "border-primary bg-primary text-primary-foreground"
                          : "border-surface-border"
                      }`}
                    >
                      {checked && "✓"}
                    </span>
                  </div>
                  <p className="text-sm text-muted">{s.description}</p>
                  <p className="text-xs text-muted">{s.usage}</p>
                </div>
              );
            })}
          </div>

          <Input
            label="Alvo"
            name="target"
            placeholder={
              zapSelected ? "https://staging.exemplo.com/" : "https://github.com/org/repo.git#main"
            }
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />

          <div>
            <Button type="submit" loading={submitting} disabled={scanners.length === 0}>
              Disparar scan
            </Button>
          </div>
        </form>

        {jobId && (
          <div className="mt-6 border-t border-surface-border pt-4">
            {status ? (
              <>
                <ScanProgress status={status} polling={polling} />
                <Link
                  href={`/seguranca/${jobId}`}
                  className="mt-3 inline-block text-sm text-primary hover:underline"
                >
                  Ver página deste scan →
                </Link>
              </>
            ) : (
              <p className="text-sm text-muted">Carregando o progresso do scan…</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
