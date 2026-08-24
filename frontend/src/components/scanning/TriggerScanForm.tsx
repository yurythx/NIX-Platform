"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { apiClient, ApiError } from "@/lib/api/client";
import { useToast } from "@/components/notifications/ToastProvider";
import { useScanStatusPolling } from "@/lib/scanning/useScanStatusPolling";
import type { TestJobResponse } from "@/types/api";

import { ScanProgress } from "./ScanProgress";

// Nomes de scanner registrados no backend (scanning.Service) — não há
// endpoint "listar scanners disponíveis", então esta lista é mantida
// manualmente em sincronia com docs/openapi.yaml, mesmo princípio já
// seguido por lib/integrations/registry.ts.
const SCANNERS = [
  { key: "trivy", label: "Trivy", hint: "dependências, Dockerfiles" },
  { key: "semgrep", label: "Semgrep", hint: "SAST" },
  { key: "sonarqube", label: "SonarQube", hint: "qualidade de código" },
  { key: "zap", label: "OWASP ZAP", hint: "DAST — ataca de verdade" },
] as const;

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
export function TriggerScanForm() {
  const { showToast } = useToast();
  const [selected, setSelected] = useState<Record<string, boolean>>({ trivy: true });
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const { status, polling } = useScanStatusPolling(jobId);

  const scanners = SCANNERS.filter((s) => selected[s.key]).map((s) => s.key);
  const zapSelected = selected.zap;

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
        <CardDescription>
          Escolha um ou mais scanners e o alvo. Trivy/Semgrep/SonarQube clonam uma URL git
          (ex.: <code>https://github.com/org/repo.git#main</code>); ZAP ataca uma URL http(s) de um
          serviço rodando de verdade — só funciona contra um host já autorizado
          (<code>SCANNING_ZAP_ALLOWED_HOSTS</code>), nunca produção.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-4">
            {SCANNERS.map((s) => (
              <label key={s.key} className="flex items-center gap-2 text-sm">
                <Toggle
                  checked={!!selected[s.key]}
                  onChange={(checked) => setSelected((prev) => ({ ...prev, [s.key]: checked }))}
                  label={s.label}
                />
                <span>
                  {s.label} <span className="text-muted">({s.hint})</span>
                </span>
              </label>
            ))}
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
          <div className="mt-6 border-t border-black/10 pt-4 dark:border-white/10">
            {status ? (
              <>
                <ScanProgress status={status} polling={polling} />
                <Link
                  href={`/seguranca/${jobId}`}
                  className="mt-3 inline-block text-sm text-blue-600 hover:underline dark:text-blue-400"
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
