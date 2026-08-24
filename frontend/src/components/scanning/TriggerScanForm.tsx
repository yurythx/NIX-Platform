"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { SCANNERS } from "@/lib/scanning/scannerRegistry";
import { useScanStatusPolling } from "@/lib/scanning/useScanStatusPolling";
import { useTriggerScan } from "@/lib/scanning/useTriggerScan";

import { ScanProgress } from "./ScanProgress";
import { ScannerPicker } from "./ScannerPicker";

// Dispara um scan avulso (POST /api/v1/scanning/scans via useTriggerScan
// — Fase 7: mais de um scanner selecionado roda tudo em paralelo sob o
// mesmo job/scan_id) e acompanha o resultado aqui mesmo, via
// useScanStatusPolling — o painel de progresso (ScanProgress) mostra qual
// scanner está rodando agora, quanto falta, e — o pedido explícito do
// usuário — QUAL ferramenta encontrou um erro, de que TIPO foi e uma
// sugestão de COMO corrigir. Esse mesmo job também ganha sua própria
// página em /seguranca/[scanId] (link mostrado abaixo assim que o job_id
// existe) — "resultados separados por scan", não só um resultado que
// desaparece ao sair desta tela. NotificationCenter continua tratando o
// toast via WebSocket (scanning.scan.completed/failed) pra quem não ficar
// olhando esta tela até o fim — os dois não conflitam.
//
// Seleção de scanner via ScannerPicker (§ unificação com ProjectCard —
// auditoria 2026-08): a mesma grade de cards que ProjectCard agora usa
// pra "Rodar de novo", nunca duas implementações divergentes do "que
// scanners existem" entre um scan avulso e um scan de projeto salvo.
export function TriggerScanForm() {
  const [selected, setSelected] = useState<Record<string, boolean>>({ trivy: true });
  const [target, setTarget] = useState("");
  const { trigger, submitting, jobId } = useTriggerScan();
  const { status, polling } = useScanStatusPolling(jobId);

  const scanners = SCANNERS.filter((s) => selected[s.key]).map((s) => s.key);
  const zapSelected = selected.zap;

  function toggle(key: string) {
    setSelected((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (scanners.length === 0 || !target.trim()) return;

    const newJobId = await trigger({ scanners, target: target.trim() });
    if (newJobId) setTarget("");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Novo scan</CardTitle>
        <CardDescription>Escolha um ou mais scanners e o alvo.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <ScannerPicker selected={selected} onToggle={toggle} />

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
