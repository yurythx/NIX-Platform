"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { apiClient, ApiError } from "@/lib/api/client";
import { useToast } from "@/components/notifications/ToastProvider";
import type { ScanStatus, TestJobResponse } from "@/types/api";

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

// terminalStatuses são os únicos em que o polling de GetScanStatus para —
// "failed" (mid-retry, ver backend application.Service.ProcessScanJob)
// ainda pode virar "completed" numa nova tentativa, então NÃO é terminal
// aqui, mesmo sendo um status "de falha".
const TERMINAL_STATUSES = new Set(["completed", "dead_letter"]);

// POLL_INTERVAL_MS/MAX_POLLS: um scan pode levar de segundos a minutos
// (clone + análise) — poll a cada 3s por até 4 minutos antes de desistir
// e deixar de acompanhar (o job continua rodando no worker de qualquer
// forma; só esta tela para de esperar por ele. NotificationCenter, via
// WebSocket, ainda avisa quando terminar mesmo que o polling já tenha
// desistido).
const POLL_INTERVAL_MS = 3000;
const MAX_POLLS = 80;

// Dispara um scan novo (POST /api/v1/scanning/scans — Fase 7: mais de um
// scanner selecionado roda tudo em paralelo sob o mesmo job/scan_id) e,
// diferente da primeira versão deste formulário, acompanha o resultado
// aqui mesmo: faz polling de GET /api/v1/scanning/scans/{job_id} até o
// status virar terminal, mostrando não só se cada scanner teve sucesso
// mas — o pedido explícito do usuário — QUAL ferramenta encontrou um
// erro, de que TIPO foi o erro e uma sugestão de COMO corrigir (ver
// ScanResultPanel abaixo). NotificationCenter continua tratando o toast
// via WebSocket (scanning.scan.completed/failed) para quem não ficar
// olhando esta tela até o fim — os dois não conflitam.
export function TriggerScanForm() {
  const { showToast } = useToast();
  const [selected, setSelected] = useState<Record<string, boolean>>({ trivy: true });
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [polling, setPolling] = useState(false);
  const cancelledRef = useRef(false);

  const scanners = SCANNERS.filter((s) => selected[s.key]).map((s) => s.key);
  const zapSelected = selected.zap;

  useEffect(() => {
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  async function pollStatus(jobId: string, attempt: number) {
    if (cancelledRef.current) return;
    try {
      const { data } = await apiClient.get<ScanStatus>(`v1/scanning/scans/${jobId}`);
      if (cancelledRef.current) return;
      setStatus(data);
      if (TERMINAL_STATUSES.has(data.status) || attempt >= MAX_POLLS) {
        setPolling(false);
        return;
      }
      setTimeout(() => pollStatus(jobId, attempt + 1), POLL_INTERVAL_MS);
    } catch {
      // Uma falha ao CONSULTAR o status (rede, sessão expirada) não é o
      // scan tendo falhado — só para de acompanhar aqui; o job continua
      // rodando no worker normalmente.
      if (!cancelledRef.current) setPolling(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (scanners.length === 0 || !target.trim()) return;

    setSubmitting(true);
    setStatus(null);
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
      setPolling(true);
      void pollStatus(data.job_id, 0);
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

        {status && <ScanResultPanel status={status} polling={polling} />}
      </CardContent>
    </Card>
  );
}

// statusLabel traduz o status bruto do job (mesmo vocabulário de
// jobs.Status no backend) pro que faz sentido mostrar durante o
// acompanhamento de um scan — "failed" ali é sempre uma tentativa em
// retry, nunca o desfecho final (ver TERMINAL_STATUSES), então o rótulo
// deixa isso explícito em vez de soar definitivo.
const STATUS_LABEL: Record<string, string> = {
  queued: "Na fila",
  processing: "Rodando",
  completed: "Concluído",
  failed: "Tentando de novo (falhou, será reprocessado)",
  dead_letter: "Falhou definitivamente",
};

const STATUS_TONE: Record<string, "neutral" | "success" | "danger" | "warning" | "info"> = {
  queued: "neutral",
  processing: "info",
  completed: "success",
  failed: "warning",
  dead_letter: "danger",
};

// ScanResultPanel é a resposta direta ao pedido do usuário: mostra QUAL
// ferramenta encontrou um erro (scanner), de que TIPO foi o erro (code —
// a mesma taxonomia de internal/domain/errors.Code do backend, exposta
// como badge) e COMO corrigir (hint, já em texto pronto, calculado no
// backend a partir de code/scanner/message — ver
// scanning/transport/dto.go's remediationHint). succeeded_scanners
// aparece separado, em verde, pra deixar claro que nem toda entrada é um
// problema.
function ScanResultPanel({ status, polling }: { status: ScanStatus; polling: boolean }) {
  // O backend sempre manda succeeded_scanners/failed_scanners como listas
  // (nunca omitidas — ver transport/dto.go), mas o polling continua até o
  // componente desmontar OU o status virar terminal, então cai aqui
  // defensivamente pra nunca quebrar o render por causa de um payload
  // inesperado no meio do caminho.
  const succeeded = status.succeeded_scanners ?? [];
  const failed = status.failed_scanners ?? [];
  return (
    <div className="mt-6 flex flex-col gap-3 border-t border-black/10 pt-4 dark:border-white/10">
      <div className="flex items-center gap-2">
        <Badge tone={STATUS_TONE[status.status] ?? "neutral"}>
          {STATUS_LABEL[status.status] ?? status.status}
        </Badge>
        {polling && <span className="text-xs text-muted">atualizando automaticamente…</span>}
        <span className="text-xs text-muted">job {status.job_id.slice(0, 8)}</span>
      </div>

      {succeeded.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted">Concluído com sucesso:</span>
          {succeeded.map((name) => (
            <Badge key={name} tone="success">
              {name}
            </Badge>
          ))}
        </div>
      )}

      {failed.length > 0 && (
        <div className="flex flex-col gap-3">
          <span className="text-sm text-muted">
            {failed.length === 1 ? "1 scanner falhou:" : `${failed.length} scanners falharam:`}
          </span>
          {failed.map((failure, i) => (
            <div
              key={`${failure.scanner}-${i}`}
              className="flex flex-col gap-1 rounded-md border border-red-200 bg-red-50 p-3 text-sm dark:border-red-500/20 dark:bg-red-500/10"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-foreground">{failure.scanner}</span>
                <Badge tone="danger">{failure.code || "ERRO"}</Badge>
              </div>
              <p className="text-muted">{failure.message}</p>
              <p>
                <span className="font-medium text-foreground">Como corrigir: </span>
                {failure.hint}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
