"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { TriageStatus } from "@/types/api";

// TriageControls: extraído de ProjectFindingHistoryPanel (revisão de
// exibição de resultados) pra ser reaproveitado também no painel de
// detalhe mestre-detalhe de FindingsTable — a mesma ação de
// triar/reabrir/renovar, os mesmos dois endpoints
// (PUT/DELETE .../triage), só chamada de dois lugares agora. Nenhuma
// lógica nova em relação ao que já existia; só deixou de estar
// hard-coded dentro de uma tabela só.
export const TRIAGE_LABELS: Record<Exclude<TriageStatus, "">, string> = {
  false_positive: "Falso positivo",
  wont_fix: "Não vou corrigir",
  risk_accepted: "Risco aceito",
};

export interface TriageControlsProps {
  projectId: string;
  fingerprint: string;
  status: TriageStatus;
  reason?: string;
  expiresAt?: string;
  expired?: boolean;
  // onChanged: quem usa decide como revalidar os dados depois de
  // triar/reabrir — ProjectFindingHistoryPanel passa o mutate() do SWR
  // que já tinha; FindingsTable (mestre-detalhe) passa o mutate() da sua
  // própria busca de findings-history (ver seu comentário sobre por que
  // ela busca isso também quando projectId está presente). Tipado como
  // "devolve qualquer coisa" (não só void): a KeyedMutator do SWR
  // devolve os dados revalidados, não void — este componente nunca lê
  // esse retorno, só espera a Promise resolver antes de seguir.
  onChanged: () => unknown;
}

export function TriageControls({ projectId, fingerprint, status, reason, expiresAt, expired, onChanged }: TriageControlsProps) {
  const { showToast } = useToast();
  const [open, setOpen] = useState(false);
  const [formStatus, setFormStatus] = useState<Exclude<TriageStatus, "">>("risk_accepted");
  const [formReason, setFormReason] = useState("");
  const [formExpiresAt, setFormExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [reopening, setReopening] = useState(false);

  // openDialog: pré-preenche com a triagem JÁ existente quando status já
  // não é vazio (ex.: "Renovar…" num achado com prazo vencido) —
  // reaplicar sem mexer em nada reenvia a mesma decisão, só com um prazo
  // novo se o usuário editar a data.
  function openDialog() {
    setFormStatus(status || "risk_accepted");
    setFormReason(reason ?? "");
    setFormExpiresAt("");
    setOpen(true);
  }

  async function submit() {
    if (formReason.trim() === "") {
      showToast({ title: "Motivo é obrigatório", description: "Registre por que este achado não precisa de ação agora.", tone: "danger" });
      return;
    }
    setSubmitting(true);
    try {
      // formExpiresAt (input type="date", YYYY-MM-DD) vira fim do dia
      // escolhido em ISO 8601 — "23:59:59 daquele dia", não meia-noite:
      // um prazo "até 30/08" que vencesse à meia-noite do PRÓPRIO 30/08
      // surpreenderia quem escolheu essa data esperando o dia inteiro
      // válido.
      const body: { status: string; reason: string; expires_at?: string } = { status: formStatus, reason: formReason };
      if (formExpiresAt) {
        body.expires_at = new Date(`${formExpiresAt}T23:59:59`).toISOString();
      }
      await apiClient.put(`v1/scanning/projects/${projectId}/findings/${fingerprint}/triage`, body);
      await onChanged();
      setOpen(false);
      showToast({ title: "Achado triado", description: TRIAGE_LABELS[formStatus], tone: "info" });
    } catch (err) {
      showToast({ title: "Não foi possível triar o achado", description: err instanceof ApiError ? err.message : "Erro inesperado", tone: "danger" });
    } finally {
      setSubmitting(false);
    }
  }

  async function reopen() {
    setReopening(true);
    try {
      await apiClient.delete(`v1/scanning/projects/${projectId}/findings/${fingerprint}/triage`);
      await onChanged();
      showToast({ title: "Achado reaberto", tone: "info" });
    } catch (err) {
      showToast({ title: "Não foi possível reabrir o achado", description: err instanceof ApiError ? err.message : "Erro inesperado", tone: "danger" });
    } finally {
      setReopening(false);
    }
  }

  return (
    <>
      <div className="flex flex-col items-start gap-1">
        {status ? (
          <>
            {expired ? (
              <Badge tone="danger" title={reason}>
                Vencida: {TRIAGE_LABELS[status]}
              </Badge>
            ) : (
              <Badge tone="warning" title={expiresAt ? `${reason} — até ${new Date(expiresAt).toLocaleDateString()}` : reason}>
                {TRIAGE_LABELS[status]}
                {expiresAt && ` (até ${new Date(expiresAt).toLocaleDateString()})`}
              </Badge>
            )}
            <div className="flex gap-2">
              {expired && (
                <button type="button" className="text-xs text-primary hover:underline" onClick={openDialog}>
                  Renovar…
                </button>
              )}
              <button
                type="button"
                className="text-xs text-primary hover:underline disabled:opacity-50"
                disabled={reopening}
                onClick={() => void reopen()}
              >
                Reabrir
              </button>
            </div>
          </>
        ) : (
          <button type="button" className="text-xs text-primary hover:underline" onClick={openDialog}>
            Triar…
          </button>
        )}
      </div>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        // title vazio quando fechado (não "Triar achado" fixo) — o
        // <dialog> nativo renderiza o título incondicionalmente no DOM,
        // só showModal()/close() reage a `open`, então um título fixo
        // continuaria "visível" pro testing-library mesmo com o diálogo
        // fechado.
        title={open ? "Triar achado" : ""}
      >
        <div className="flex flex-col gap-3 text-sm">
          <label className="flex flex-col gap-1">
            <span className="font-medium text-foreground">Status</span>
            <select
              value={formStatus}
              onChange={(e) => setFormStatus(e.target.value as Exclude<TriageStatus, "">)}
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
              value={formReason}
              onChange={(e) => setFormReason(e.target.value)}
              rows={3}
              placeholder="Por que este achado não precisa de ação agora? Fica registrado na auditoria."
              className="rounded-md border border-surface-border bg-surface px-3 py-1.5 text-foreground placeholder:text-muted"
            />
          </label>
          <label className="flex flex-col gap-1" htmlFor="triage-expires-at">
            {/* htmlFor explícito (não só o wrapping implícito) — o texto
                de ajuda logo abaixo do input, dentro do MESMO <label>,
                faria o nome acessível de uma associação implícita
                incluir as duas frases concatenadas. */}
            <span id="triage-expires-at-label" className="font-medium text-foreground">
              Revisar até (opcional)
            </span>
            <input
              id="triage-expires-at"
              aria-labelledby="triage-expires-at-label"
              type="date"
              value={formExpiresAt}
              min={new Date().toISOString().slice(0, 10)}
              onChange={(e) => setFormExpiresAt(e.target.value)}
              className="rounded-md border border-surface-border bg-surface px-3 py-1.5 text-foreground"
            />
            <span className="text-xs text-muted">
              Sem prazo, a triagem vale pra sempre. Com prazo, o achado volta a contar como aberto
              automaticamente depois dessa data.
            </span>
          </label>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" size="sm" onClick={() => setOpen(false)} disabled={submitting}>
              Cancelar
            </Button>
            <Button size="sm" onClick={() => void submit()} loading={submitting}>
              Salvar
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
