"use client";

import { useState, type FormEvent } from "react";

import { useToast } from "@/components/notifications/ToastProvider";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input } from "@/components/ui/Input";
import { apiClient } from "@/lib/api/client";
import { ApiError, useApiQuery } from "@/lib/api/swr";
import type { MonitoredTerm } from "@/types/api";

type Criteria = "oab" | "processo" | "texto";

const CRITERIA_LABEL: Record<Criteria, string> = {
  oab: "OAB",
  processo: "Nº do processo",
  texto: "Texto livre",
};

// MonitoredTermsPanel — MVP real de monitoramento do Diário Oficial via
// DJEN (docs/roadmap-secops-orchestrator.md, "Diário Oficial —
// monitoramento real via DJEN"): cadastro/lista/remoção do que o usuário
// quer acompanhar (o mesmo cadastro central que Jusbrasil/Escavador/
// Turivius oferecem). Client Component (não Server Component + refresh)
// de propósito — mesmo raciocínio de ScannerHealthPanel: criar/remover
// um termo é uma ação rápida que precisa de feedback imediato na mesma
// lista, sem depender de um round-trip de navegação.
export function MonitoredTermsPanel() {
  const { data: terms, error, isLoading, mutate } = useApiQuery<MonitoredTerm[]>("v1/diario-oficial/monitored-terms");
  const { showToast } = useToast();

  const [criteria, setCriteria] = useState<Criteria>("oab");
  const [label, setLabel] = useState("");
  const [oabNumber, setOabNumber] = useState("");
  const [oabState, setOabState] = useState("");
  const [processNumber, setProcessNumber] = useState("");
  const [freeText, setFreeText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [deletingID, setDeletingID] = useState<string | null>(null);

  function resetForm() {
    setLabel("");
    setOabNumber("");
    setOabState("");
    setProcessNumber("");
    setFreeText("");
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!label.trim()) return;

    setSubmitting(true);
    try {
      await apiClient.post("v1/diario-oficial/monitored-terms", {
        label: label.trim(),
        oab_number: criteria === "oab" ? oabNumber.trim() : undefined,
        oab_uf: criteria === "oab" ? oabState.trim().toUpperCase() : undefined,
        process_number: criteria === "processo" ? processNumber.trim() : undefined,
        free_text: criteria === "texto" ? freeText.trim() : undefined,
      });
      showToast({ title: "Termo cadastrado", description: label.trim(), tone: "info" });
      resetForm();
      void mutate();
    } catch (err) {
      showToast({
        title: "Não foi possível cadastrar o termo",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(term: MonitoredTerm) {
    setDeletingID(term.id);
    try {
      await apiClient.delete(`v1/diario-oficial/monitored-terms/${term.id}`);
      showToast({ title: "Termo removido", description: term.label, tone: "info" });
      void mutate();
    } catch (err) {
      showToast({
        title: "Não foi possível remover o termo",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setDeletingID(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4 rounded-lg border border-surface-border p-4">
        <Input
          label="Nome"
          name="label"
          placeholder="ex.: Dr. Fulano — OAB/MG 419"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          required
        />

        <div className="flex gap-2 border-b border-surface-border">
          {(Object.keys(CRITERIA_LABEL) as Criteria[]).map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setCriteria(c)}
              className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                criteria === c
                  ? "border-primary text-primary"
                  : "border-transparent text-muted hover:text-foreground"
              }`}
            >
              {CRITERIA_LABEL[c]}
            </button>
          ))}
        </div>

        {criteria === "oab" && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[2fr_1fr]">
            <Input
              label="Número da OAB"
              name="oab_number"
              placeholder="419"
              value={oabNumber}
              onChange={(e) => setOabNumber(e.target.value)}
              required
            />
            <Input
              label="UF"
              name="oab_uf"
              placeholder="MG"
              maxLength={2}
              value={oabState}
              onChange={(e) => setOabState(e.target.value)}
              required
            />
          </div>
        )}
        {criteria === "processo" && (
          <Input
            label="Número do processo"
            name="process_number"
            placeholder="somente dígitos, ex.: 50015349420258130351"
            value={processNumber}
            onChange={(e) => setProcessNumber(e.target.value)}
            required
          />
        )}
        {criteria === "texto" && (
          <Input
            label="Texto livre"
            name="free_text"
            placeholder="ex.: nome da parte/empresa"
            value={freeText}
            onChange={(e) => setFreeText(e.target.value)}
            required
          />
        )}

        <div>
          <Button type="submit" loading={submitting}>
            Monitorar
          </Button>
        </div>
      </form>

      {error ? (
        <p className="text-sm text-danger">
          {error instanceof ApiError ? error.message : "Falha ao carregar termos monitorados"}
        </p>
      ) : isLoading && !terms ? (
        <p className="text-sm text-muted">Carregando…</p>
      ) : !terms || terms.length === 0 ? (
        <EmptyState
          title="Nenhum termo monitorado ainda"
          description="Cadastre um OAB, número de processo ou texto livre acima — o worker sincroniza contra o DJEN a cada 6h."
        />
      ) : (
        <ul className="flex flex-col divide-y divide-surface-border rounded-lg border border-surface-border bg-surface">
          {terms.map((term) => (
            <li key={term.id} className="flex items-center justify-between gap-3 p-3">
              <div className="min-w-0">
                <div className="truncate font-medium text-foreground">{term.label}</div>
                <div className="truncate text-xs text-muted">
                  {term.oab_number
                    ? `OAB ${term.oab_number}/${term.oab_uf}`
                    : term.process_number
                      ? `Processo ${term.process_number}`
                      : term.free_text}
                  {" · "}
                  {term.last_synced_at
                    ? `última sincronização ${new Date(term.last_synced_at).toLocaleString()}`
                    : "ainda não sincronizado"}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <Badge tone={term.active ? "success" : "neutral"}>{term.active ? "Ativo" : "Pausado"}</Badge>
                <button
                  type="button"
                  onClick={() => void handleDelete(term)}
                  disabled={deletingID === term.id}
                  className="text-xs text-danger hover:underline disabled:opacity-50"
                >
                  Remover
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
