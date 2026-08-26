"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/Table";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import { useApiQuery } from "@/lib/api/swr";
import type { ProjectFindingHistory, TriageStatus } from "@/types/api";

import { SeverityBadge } from "./SeverityBadge";

// ProjectFindingHistoryPanel: Fase 12 (deduplicação por fingerprint) —
// pedido literal do roadmap: "achado X apareceu pela primeira vez no scan
// de 12/08, ainda presente no scan de 20/08" em vez de listar a mesma
// vulnerabilidade repetida uma vez por re-scan. Busca sob demanda (só
// quando o card expande — ver ProjectCard), nunca no carregamento inicial
// de /seguranca: a maioria dos projetos não vai ter esse painel aberto na
// maior parte do tempo.
//
// useApiQuery (SWR, § auditoria 2026-08) em vez de useEffect+useState
// manual: reabrir o mesmo card duas vezes na mesma sessão reaproveita o
// cache em vez de refazer a requisição, e o dedupe automático cobre o
// caso de dois cards do mesmo projeto abertos quase juntos.
//
// § Triagem (Fase 14 — Maturidade de AppSec): até aqui, "ainda presente"
// era o único sinal — nenhum jeito de um humano dizer "isto é falso
// positivo" ou "risco aceito por ora" sem o mesmo achado voltar a
// aparecer como pendente em todo re-scan seguinte. Vive AQUI, não em
// FindingsTable (a visão agregada de /seguranca, sem conceito de
// projeto/fingerprint estável), porque a triagem é escopada a
// (projeto, fingerprint) — o mesmo escopo que este painel já usa pro
// resto do agrupamento (ver backend's scanning_finding_triage,
// migration 000023).
const TRIAGE_LABELS: Record<Exclude<TriageStatus, "">, string> = {
  false_positive: "Falso positivo",
  wont_fix: "Não vou corrigir",
  risk_accepted: "Risco aceito",
};

export function ProjectFindingHistoryPanel({ projectId }: { projectId: string }) {
  const {
    data: history,
    error: swrError,
    mutate,
  } = useApiQuery<ProjectFindingHistory[]>(`v1/scanning/projects/${projectId}/findings-history`);
  const { showToast } = useToast();

  const [triaging, setTriaging] = useState<ProjectFindingHistory | null>(null);
  const [status, setStatus] = useState<Exclude<TriageStatus, "">>("risk_accepted");
  const [reason, setReason] = useState("");
  // expiresAt: "" (input type="date" vazio) = sem prazo — o mesmo padrão
  // opcional que o backend já usa (expires_at nil). Nunca obrigatório,
  // ao contrário de reason.
  const [expiresAt, setExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [reopeningFingerprint, setReopeningFingerprint] = useState<string | null>(null);

  // openTriageDialog: pré-preenche com a triagem JÁ existente quando h
  // já foi triado (ex.: "Renovar…" num achado com prazo vencido) —
  // reaplicar sem mexer em nada reenvia a mesma decisão, só com um prazo
  // novo se o usuário editar a data.
  function openTriageDialog(h: ProjectFindingHistory) {
    setTriaging(h);
    setStatus(h.triage_status || "risk_accepted");
    setReason(h.triage_reason ?? "");
    setExpiresAt("");
  }

  async function submitTriage() {
    if (!triaging) return;
    if (reason.trim() === "") {
      showToast({ title: "Motivo é obrigatório", description: "Registre por que este achado não precisa de ação agora.", tone: "danger" });
      return;
    }
    setSubmitting(true);
    try {
      // expiresAt (input type="date", YYYY-MM-DD) vira fim do dia
      // escolhido em ISO 8601 — "23:59:59 daquele dia", não meia-noite:
      // um prazo "até 30/08" que vencesse à meia-noite do PRÓPRIO 30/08
      // surpreenderia quem escolheu essa data esperando o dia inteiro
      // válido.
      const body: { status: string; reason: string; expires_at?: string } = { status, reason };
      if (expiresAt) {
        body.expires_at = new Date(`${expiresAt}T23:59:59`).toISOString();
      }
      await apiClient.put(`v1/scanning/projects/${projectId}/findings/${triaging.fingerprint}/triage`, body);
      await mutate();
      setTriaging(null);
      showToast({ title: "Achado triado", description: TRIAGE_LABELS[status], tone: "info" });
    } catch (err) {
      showToast({ title: "Não foi possível triar o achado", description: err instanceof ApiError ? err.message : "Erro inesperado", tone: "danger" });
    } finally {
      setSubmitting(false);
    }
  }

  async function reopen(h: ProjectFindingHistory) {
    setReopeningFingerprint(h.fingerprint);
    try {
      await apiClient.delete(`v1/scanning/projects/${projectId}/findings/${h.fingerprint}/triage`);
      await mutate();
      showToast({ title: "Achado reaberto", tone: "info" });
    } catch (err) {
      showToast({ title: "Não foi possível reabrir o achado", description: err instanceof ApiError ? err.message : "Erro inesperado", tone: "danger" });
    } finally {
      setReopeningFingerprint(null);
    }
  }

  if (swrError) {
    return (
      <p className="text-sm text-danger">
        {swrError instanceof ApiError ? swrError.message : "Falha ao carregar o histórico"}
      </p>
    );
  }
  if (history === undefined) {
    return <p className="text-sm text-muted">Carregando histórico…</p>;
  }
  if (history.length === 0) {
    return (
      <EmptyState
        title="Nenhum achado no histórico"
        description="Nenhum scan deste projeto encontrou problema algum até agora."
      />
    );
  }

  return (
    <>
      <div className="mb-2 flex justify-end">
        <a
          href={`/api/backend/v1/scanning/projects/${projectId}/findings-history.csv`}
          className="text-sm text-primary hover:underline"
        >
          Exportar CSV →
        </a>
      </div>
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell>Severidade</TableHeaderCell>
            <TableHeaderCell>Achado</TableHeaderCell>
            <TableHeaderCell>Primeira vez</TableHeaderCell>
            <TableHeaderCell>Última vez</TableHeaderCell>
            <TableHeaderCell>Scans</TableHeaderCell>
            <TableHeaderCell>Status</TableHeaderCell>
            <TableHeaderCell>Triagem</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {history.map((h) => (
            <TableRow key={h.fingerprint}>
              <TableCell>
                <SeverityBadge severity={h.severity} />
              </TableCell>
              <TableCell>
                <div className="font-medium text-foreground">{h.tool.name}</div>
                <div className="max-w-md truncate text-muted" title={h.description}>
                  {h.description}
                </div>
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted">
                {new Date(h.first_seen_at).toLocaleDateString()}
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted">
                {new Date(h.last_seen_at).toLocaleDateString()}
              </TableCell>
              <TableCell className="text-muted">{h.scan_count}</TableCell>
              <TableCell>
                <Badge tone={h.still_present ? "danger" : "success"}>
                  {h.still_present ? "Ainda presente" : "Corrigido"}
                </Badge>
              </TableCell>
              <TableCell>
                {h.triage_status ? (
                  <div className="flex flex-col items-start gap-1">
                    {h.triage_expired ? (
                      <Badge tone="danger" title={h.triage_reason}>
                        Vencida: {TRIAGE_LABELS[h.triage_status]}
                      </Badge>
                    ) : (
                      <Badge
                        tone="warning"
                        title={h.triage_expires_at ? `${h.triage_reason} — até ${new Date(h.triage_expires_at).toLocaleDateString()}` : h.triage_reason}
                      >
                        {TRIAGE_LABELS[h.triage_status]}
                        {h.triage_expires_at && ` (até ${new Date(h.triage_expires_at).toLocaleDateString()})`}
                      </Badge>
                    )}
                    <div className="flex gap-2">
                      {h.triage_expired && (
                        <button type="button" className="text-xs text-primary hover:underline" onClick={() => openTriageDialog(h)}>
                          Renovar…
                        </button>
                      )}
                      <button
                        type="button"
                        className="text-xs text-primary hover:underline disabled:opacity-50"
                        disabled={reopeningFingerprint === h.fingerprint}
                        onClick={() => void reopen(h)}
                      >
                        Reabrir
                      </button>
                    </div>
                  </div>
                ) : (
                  <button type="button" className="text-xs text-primary hover:underline" onClick={() => openTriageDialog(h)}>
                    Triar…
                  </button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog
        open={triaging !== null}
        onClose={() => setTriaging(null)}
        // title vazio quando fechado (não "Triar achado" fixo) — mesmo
        // padrão de FindingsTable's Dialog: o <dialog> nativo renderiza o
        // título incondicionalmente no DOM, só showModal()/close() reage
        // a `open`, então um título fixo continuaria "visível" pro
        // testing-library mesmo com o diálogo fechado.
        title={triaging ? "Triar achado" : ""}
        description={triaging?.description}
      >
        {triaging && (
          <div className="flex flex-col gap-3 text-sm">
            <label className="flex flex-col gap-1">
              <span className="font-medium text-foreground">Status</span>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as Exclude<TriageStatus, "">)}
                className="rounded-md border border-surface-border bg-surface px-3 py-1.5 text-foreground"
              >
                <option value="risk_accepted">Risco aceito</option>
                <option value="wont_fix">Não vou corrigir</option>
                <option value="false_positive">Falso positivo</option>
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="font-medium text-foreground">Motivo (obrigatório)</span>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
                placeholder="Por que este achado não precisa de ação agora? Fica registrado na auditoria."
                className="rounded-md border border-surface-border bg-surface px-3 py-1.5 text-foreground placeholder:text-muted"
              />
            </label>
            <label className="flex flex-col gap-1" htmlFor="triage-expires-at">
              {/* htmlFor explícito (não só o wrapping implícito que o
                  resto deste diálogo usa) — o texto de ajuda logo abaixo
                  do input, dentro do MESMO <label>, faria o nome
                  acessível de uma associação implícita incluir as duas
                  frases concatenadas; getByLabelText (accessible name)
                  esperaria por esse texto duplo, não só "Revisar até
                  (opcional)". */}
              <span id="triage-expires-at-label" className="font-medium text-foreground">
                Revisar até (opcional)
              </span>
              <input
                id="triage-expires-at"
                aria-labelledby="triage-expires-at-label"
                type="date"
                value={expiresAt}
                min={new Date().toISOString().slice(0, 10)}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="rounded-md border border-surface-border bg-surface px-3 py-1.5 text-foreground"
              />
              <span className="text-xs text-muted">
                Sem prazo, a triagem vale pra sempre. Com prazo, o achado volta a contar como aberto
                automaticamente depois dessa data.
              </span>
            </label>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" size="sm" onClick={() => setTriaging(null)} disabled={submitting}>
                Cancelar
              </Button>
              <Button size="sm" onClick={() => void submitTriage()} loading={submitting}>
                Salvar
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}
