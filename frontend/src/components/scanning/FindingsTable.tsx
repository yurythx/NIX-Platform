"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, useSyncExternalStore, type KeyboardEvent } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { useToast } from "@/components/notifications/ToastProvider";
import { buildAIPrompt } from "@/lib/scanning/aiPrompt";
import { remediationFor } from "@/lib/scanning/remediation";
import { scannerMeta } from "@/lib/scanning/scannerRegistry";
import { useApiQuery } from "@/lib/api/swr";
import type { ProjectFindingHistory, ScanFinding, ScanSeverity } from "@/types/api";

import { SeverityBadge } from "./SeverityBadge";
import { SeverityDistributionBar } from "./SeverityDistributionBar";
import { TriageControls } from "./TriageControls";

// Ordem de exibição dos filtros de severidade — sempre da mais grave pra
// menos grave, igual à ordem que qualquer painel de segurança usa.
const SEVERITY_ORDER: ScanSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_RANK: Record<ScanSeverity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

type SortKey = "severity" | "date-desc" | "date-asc" | "file";

// urlFindingId: lido via useSyncExternalStore (não useState+useEffect) —
// a primitiva que o próprio React recomenda pra "estado que vive fora do
// React" (aqui, a query string), sem o padrão setState-dentro-de-efeito
// que a regra de lint react-hooks/set-state-in-effect desencoraja (mesmo
// raciocínio de lib/theme/usePrefersDark.ts). subscribe reage a
// popstate (voltar/avançar do navegador), não só ao mount — voltar pro
// achado anterior com o botão "Voltar" do navegador funciona de graça.
function subscribeToPopstate(callback: () => void): () => void {
  window.addEventListener("popstate", callback);
  return () => window.removeEventListener("popstate", callback);
}
function getFindingIdFromURL(): string | null {
  return new URLSearchParams(window.location.search).get("finding");
}
// SSR não tem query string de navegador nenhuma — null é o valor certo
// (equivalente a "nenhum ?finding= ainda", useSyncExternalStore
// reconcilia com o valor real assim que hidrata, sem aviso de mismatch).
function getServerFindingId(): null {
  return null;
}

function sortFindings(list: ScanFinding[], sortKey: SortKey): ScanFinding[] {
  const copy = [...list];
  switch (sortKey) {
    case "severity":
      copy.sort(
        (a, b) =>
          SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      );
      break;
    case "date-desc":
      copy.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      break;
    case "date-asc":
      copy.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
      break;
    case "file":
      copy.sort((a, b) => (a.file || "").localeCompare(b.file || ""));
      break;
  }
  return copy;
}

// FindingsTable (revisão de exibição de resultados — pedido do usuário:
// "quero focar em como esses resultados são mostrados, quero a melhor
// prática"): reescrita de um modal por-cima-da-tabela pra uma view
// MESTRE-DETALHE (lista + painel de detalhe lado a lado, como GitHub
// Advanced Security/Snyk/GitLab Secure fazem) — o modal anterior
// obrigava fechar → clicar → abrir de novo pra passar pro próximo
// achado, sem seta de teclado, sem link direto pra UM achado específico.
// Continua tudo client-side sobre a lista já carregada (nenhum filtro
// chama a API de novo), mesmo princípio de antes.
//
// showScanLink liga o painel de detalhe de volta pra página do scan
// inteiro (/seguranca/[scanId]) — só faz sentido na visão AGREGADA de
// /seguranca; a própria página de um scan específico já é essa página.
//
// projectId (novo — ScanStatusResponse ganhou project_id nesta mesma
// revisão): quando presente, o painel de detalhe também mostra
// TriageControls pro achado selecionado — busca
// GET .../projects/{projectId}/findings-history (o mesmo dado que
// ProjectFindingHistoryPanel já usa) só pra saber, por fingerprint, se
// cada achado já foi triado. Ausente (scan avulso, ou visão agregada
// sem um projeto único) — nenhuma chamada extra, TriageControls
// simplesmente não aparece, mesma restrição que ProjectFindingHistoryPanel
// já tinha (a triagem é escopada a projeto).
export function FindingsTable({
  findings,
  showScanLink = false,
  projectId,
}: {
  findings: ScanFinding[];
  showScanLink?: boolean;
  projectId?: string;
}) {
  const [severityFilter, setSeverityFilter] = useState<Set<ScanSeverity>>(new Set());
  const [scannerFilter, setScannerFilter] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [groupByTarget, setGroupByTarget] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  // manualSelectedId: só o que o próprio usuário escolheu NESTA sessão
  // (clique, Enter, seta, Anterior/Próximo) — null enquanto ele ainda
  // não escolheu nada, caso em que a seleção efetiva (ver
  // `selectedId` abaixo) cai pro que já estava em ?finding= na URL, ou
  // pro primeiro achado da lista. Nunca "corrigido" por um efeito
  // observando a lista mudar — a derivação abaixo já resolve isso
  // puramente durante o render, sem setState escondido.
  const [manualSelectedId, setManualSelectedId] = useState<string | null>(null);
  const urlFindingId = useSyncExternalStore(subscribeToPopstate, getFindingIdFromURL, getServerFindingId);
  const { showToast } = useToast();

  // history/projectId (Fase 14, continuação desta revisão): busca sob
  // demanda, só quando projectId está presente — useApiQuery aceita
  // path null pra "não busca nada" (ver lib/api/swr.ts).
  const { data: history, mutate: mutateHistory } = useApiQuery<ProjectFindingHistory[]>(
    projectId ? `v1/scanning/projects/${projectId}/findings-history` : null,
  );
  const historyByFingerprint = useMemo(() => {
    const map = new Map<string, ProjectFindingHistory>();
    for (const h of history ?? []) map.set(h.fingerprint, h);
    return map;
  }, [history]);

  async function copyAIPrompt(finding: ScanFinding) {
    try {
      await navigator.clipboard.writeText(buildAIPrompt(finding));
      showToast({ title: "Prompt copiado", description: "Cole numa IA de sua preferência.", tone: "info" });
    } catch {
      showToast({ title: "Não foi possível copiar", tone: "danger" });
    }
  }

  // severityCounts/availableScanners: calculados sobre TODOS os achados
  // (nunca sobre o resultado já filtrado) — os selos de contagem
  // continuam mostrando "quantos existem no total", não "quantos sobram
  // depois do filtro atual".
  const severityCounts = useMemo(() => {
    const counts: Record<ScanSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of findings) counts[f.severity] += 1;
    return counts;
  }, [findings]);

  const availableScanners = useMemo(
    () => Array.from(new Set(findings.map((f) => f.scanner))).sort(),
    [findings],
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    const list = findings.filter((f) => {
      if (severityFilter.size > 0 && !severityFilter.has(f.severity)) return false;
      if (scannerFilter.size > 0 && !scannerFilter.has(f.scanner)) return false;
      if (term) {
        const haystack = `${f.finding_id} ${f.description} ${f.file} ${f.owasp_category} ${f.target}`.toLowerCase();
        if (!haystack.includes(term)) return false;
      }
      return true;
    });
    return sortFindings(list, sortKey);
  }, [findings, severityFilter, scannerFilter, search, sortKey]);

  const groups = useMemo(() => {
    if (!groupByTarget) return null;
    const byTarget = new Map<string, ScanFinding[]>();
    for (const f of filtered) {
      const list = byTarget.get(f.target) ?? [];
      list.push(f);
      byTarget.set(f.target, list);
    }
    // Alvo com o achado mais recente primeiro — mesma convenção de
    // recência que ScanList/ScanCard já usam em toda a plataforma.
    return Array.from(byTarget.entries()).sort(
      ([, a], [, b]) => new Date(b[0]?.created_at ?? "").getTime() - new Date(a[0]?.created_at ?? "").getTime(),
    );
  }, [filtered, groupByTarget]);

  // orderedFindings: a lista FLAT, na ordem de exibição real (respeita
  // agrupamento por alvo quando ligado) — usada tanto pra renderizar a
  // lista quanto pra Anterior/Próximo no painel de detalhe, os dois
  // precisam concordar na mesma ordem.
  const orderedFindings = useMemo(() => (groups ? groups.flatMap(([, list]) => list) : filtered), [groups, filtered]);

  // selectedId: derivado, nunca guardado em estado próprio — a ordem de
  // prioridade é (1) o que o usuário escolheu nesta sessão, (2) o que já
  // estava em ?finding= na URL (deep link, inclusive num F5), (3) o
  // primeiro achado da lista atual. Calculado PURAMENTE durante o
  // render (nenhum useEffect "corrigindo" a seleção quando o filtro
  // muda) — um candidato que saiu da lista (filtro mudou, ou o id não
  // existe) cai pro primeiro achado igual a qualquer outro caso sem
  // seleção válida, sem precisar de um estado de sincronização à parte.
  const selectedId = useMemo(() => {
    const candidate = manualSelectedId ?? urlFindingId;
    if (candidate && orderedFindings.some((f) => f.id === candidate)) return candidate;
    return orderedFindings[0]?.id ?? null;
  }, [manualSelectedId, urlFindingId, orderedFindings]);

  const selectedIndex = orderedFindings.findIndex((f) => f.id === selectedId);
  const selected = selectedIndex >= 0 ? orderedFindings[selectedIndex] : undefined;

  // Sincronização de volta pra URL: um efeito de verdade (atualiza um
  // SISTEMA EXTERNO — a URL do navegador — a partir do estado React
  // mais recente, exatamente o uso que a documentação do React recomenda
  // pra useEffect, ao contrário de setState dentro de efeito).
  // history.replaceState (não pushState, não o router do Next.js):
  // reflete a seleção na URL pra dar de compartilhar/atualizar a página
  // sem recarregar nem empilhar uma entrada de histórico por clique.
  useEffect(() => {
    const url = new URL(window.location.href);
    if (selectedId) url.searchParams.set("finding", selectedId);
    else url.searchParams.delete("finding");
    window.history.replaceState(null, "", url);
  }, [selectedId]);

  function toggleSeverity(s: ScanSeverity) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function toggleScanner(s: string) {
    setScannerFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function goToOffset(offset: number) {
    if (selectedIndex < 0) return;
    const next = orderedFindings[selectedIndex + offset];
    if (next) setManualSelectedId(next.id);
  }

  function handleRowKeyDown(e: KeyboardEvent<HTMLDivElement>, finding: ScanFinding) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setManualSelectedId(finding.id);
    }
  }

  if (findings.length === 0) {
    return (
      <EmptyState
        title="Nenhum achado ainda"
        description="Nenhum scan rodou até agora, ou nenhum problema foi encontrado nos scans mais recentes."
      />
    );
  }

  function renderRow(finding: ScanFinding) {
    const isSelected = finding.id === selectedId;
    return (
      <div
        key={finding.id}
        onClick={() => setManualSelectedId(finding.id)}
        onKeyDown={(e) => handleRowKeyDown(e, finding)}
        role="option"
        aria-selected={isSelected}
        tabIndex={0}
        aria-label={`Ver detalhes do achado ${finding.finding_id}`}
        className={`flex cursor-pointer flex-col gap-1 rounded-md border-l-4 px-3 py-2 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
          isSelected
            ? "border-l-primary bg-primary/10"
            : "border-l-transparent hover:bg-black/5 dark:hover:bg-white/5"
        }`}
      >
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="truncate text-sm font-medium text-foreground">{finding.finding_id}</span>
        </div>
        <p className="truncate text-xs text-muted">{finding.description}</p>
        <p className="truncate text-xs text-muted">
          {finding.scanner}
          {finding.file && ` · ${finding.file}${finding.line > 0 ? `:${finding.line}` : ""}`}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {SEVERITY_ORDER.map((sev) => {
            const count = severityCounts[sev];
            const active = severityFilter.has(sev);
            if (count === 0) return null;
            return (
              <button
                key={sev}
                type="button"
                aria-pressed={active}
                aria-label={`Filtrar por severidade ${sev} (${count})`}
                onClick={() => toggleSeverity(sev)}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                  active
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-surface-border bg-surface text-muted hover:text-foreground"
                }`}
              >
                {sev}
                <span className={active ? "text-primary" : "text-muted"}>{count}</span>
              </button>
            );
          })}

          {availableScanners.length > 1 &&
            availableScanners.map((key) => {
              const active = scannerFilter.has(key);
              return (
                <button
                  key={key}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleScanner(key)}
                  className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                    active
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-surface-border bg-surface text-muted hover:text-foreground"
                  }`}
                >
                  {scannerMeta(key).name}
                </button>
              );
            })}
        </div>

        <SeverityDistributionBar counts={severityCounts} />

        <div className="flex flex-wrap items-center gap-3">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por ID, descrição, arquivo ou categoria…"
            aria-label="Buscar achados"
            className="min-w-0 flex-1 rounded-md border border-surface-border bg-surface px-3 py-1.5 text-sm text-foreground placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary sm:max-w-xs"
          />
          <label className="flex items-center gap-1.5 text-sm text-muted">
            Ordenar
            <select
              value={sortKey}
              onChange={(e) => setSortKey(e.target.value as SortKey)}
              aria-label="Ordenar achados"
              className="rounded-md border border-surface-border bg-surface px-2 py-1 text-sm text-foreground"
            >
              <option value="severity">Mais grave primeiro</option>
              <option value="date-desc">Mais recente primeiro</option>
              <option value="date-asc">Mais antigo primeiro</option>
              <option value="file">Arquivo (A-Z)</option>
            </select>
          </label>
          {showScanLink && (
            <label className="flex items-center gap-1.5 text-sm text-muted">
              <input
                type="checkbox"
                checked={groupByTarget}
                onChange={(e) => setGroupByTarget(e.target.checked)}
                className="accent-primary"
              />
              Agrupar por alvo
            </label>
          )}
          <span className="text-xs text-muted">
            {filtered.length} de {findings.length} achado{findings.length === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title="Nenhum achado corresponde aos filtros"
          description="Ajuste ou limpe os filtros de severidade/ferramenta/busca acima pra ver os achados de novo."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[380px_1fr]">
          <div
            role="listbox"
            aria-label="Lista de achados"
            onKeyDown={(e) => {
              // Seta pra baixo/cima navega pro achado seguinte/anterior
              // sem precisar clicar nos botões "Anterior/Próximo" do
              // painel de detalhe — mesmo atalho que qualquer lista
              // mestre-detalhe (e-mail, Gmail, GitHub) já tem.
              if (e.key === "ArrowDown") {
                e.preventDefault();
                goToOffset(1);
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                goToOffset(-1);
              }
            }}
            className="flex flex-col gap-3 lg:max-h-[70vh] lg:overflow-y-auto lg:pr-2">
            {groups
              ? groups.map(([target, groupFindings]) => (
                  <div key={target}>
                    <div className="mb-1 flex items-center gap-2 px-1">
                      <span className="truncate text-xs font-semibold uppercase tracking-wide text-muted" title={target}>
                        {target}
                      </span>
                      <span className="shrink-0 text-xs text-muted">({groupFindings.length})</span>
                    </div>
                    <div className="flex flex-col gap-1">{groupFindings.map(renderRow)}</div>
                  </div>
                ))
              : <div className="flex flex-col gap-1">{filtered.map(renderRow)}</div>}
          </div>

          <section aria-label="Detalhe do achado" className="lg:max-h-[70vh] lg:overflow-y-auto">
            {selected ? (
              <div className="flex flex-col gap-3 rounded-lg border border-surface-border bg-surface p-4 text-sm">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h2 className="text-base font-semibold text-foreground">{selected.finding_id}</h2>
                    <p className="text-xs text-muted">
                      {selected.scanner} · {selected.severity}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <button
                      type="button"
                      onClick={() => goToOffset(-1)}
                      disabled={selectedIndex <= 0}
                      aria-label="Achado anterior"
                      className="rounded-md border border-surface-border px-2 py-1 text-xs text-foreground hover:bg-black/5 disabled:opacity-40 dark:hover:bg-white/5"
                    >
                      ← Anterior
                    </button>
                    <button
                      type="button"
                      onClick={() => goToOffset(1)}
                      disabled={selectedIndex < 0 || selectedIndex >= orderedFindings.length - 1}
                      aria-label="Próximo achado"
                      className="rounded-md border border-surface-border px-2 py-1 text-xs text-foreground hover:bg-black/5 disabled:opacity-40 dark:hover:bg-white/5"
                    >
                      Próximo →
                    </button>
                  </div>
                </div>

                {/* Dados da ferramenta — nome de exibição + link pra abrir
                    esse achado (ou a regra/CVE por trás dele) na própria
                    ferramenta, quando o backend consegue montar um. */}
                <div className="flex flex-wrap items-center gap-2 rounded-md bg-black/5 p-2 dark:bg-white/5">
                  <span className="font-medium text-foreground">{selected.tool?.name ?? selected.scanner}</span>
                  {selected.tool?.url && (
                    <a
                      href={selected.tool.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      Abrir na ferramenta →
                    </a>
                  )}
                </div>

                {projectId && selected.fingerprint && (
                  <TriageControls
                    projectId={projectId}
                    fingerprint={selected.fingerprint}
                    status={historyByFingerprint.get(selected.fingerprint)?.triage_status ?? ""}
                    reason={historyByFingerprint.get(selected.fingerprint)?.triage_reason}
                    expiresAt={historyByFingerprint.get(selected.fingerprint)?.triage_expires_at}
                    expired={historyByFingerprint.get(selected.fingerprint)?.triage_expired}
                    onChanged={mutateHistory}
                  />
                )}

                <div>
                  <div className="font-medium text-foreground">Descrição</div>
                  <p className="text-muted">{selected.description}</p>
                </div>
                {selected.owasp_category && (
                  <div>
                    <div className="font-medium text-foreground">Categoria OWASP</div>
                    <p className="text-muted">{selected.owasp_category}</p>
                  </div>
                )}
                {selected.file && (
                  <div>
                    <div className="font-medium text-foreground">Local</div>
                    <p className="text-muted">
                      {selected.file}
                      {selected.line > 0 ? `:${selected.line}` : ""}
                    </p>
                  </div>
                )}
                {selected.snippet && (
                  <div>
                    <div className="font-medium text-foreground">Trecho do código</div>
                    <SnippetBlock snippet={selected.snippet} highlightLine={selected.line} />
                  </div>
                )}
                <div>
                  <div className="font-medium text-foreground">Como corrigir</div>
                  <p className="text-muted">{remediationFor(selected)}</p>
                </div>
                <div>
                  <Button size="sm" variant="secondary" onClick={() => copyAIPrompt(selected)}>
                    Copiar prompt pra IA
                  </Button>
                </div>
                <div className="text-xs text-muted">Encontrado em {new Date(selected.created_at).toLocaleString()}</div>
                {showScanLink && (
                  <Link href={`/seguranca/${selected.scan_id}`} className="text-primary hover:underline">
                    Ver o scan completo →
                  </Link>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted">Selecione um achado à esquerda.</p>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

// SnippetBlock renderiza o snippet capturado pelo backend (Fase 12) —
// cada linha vem prefixada com o número REAL do arquivo, ex. "10: foo()"
// (ver captureSnippet no backend, git_clone.go), nunca a posição dentro
// do snippet: a linha do achado nem sempre é a primeira/central (perto
// do início/fim do arquivo, o contexto fica truncado assimetricamente).
// Faz o parsing inverso desse prefixo só pra decidir qual linha destacar
// como "a do achado" — o texto exibido continua vindo do backend, nunca
// reformatado.
const SNIPPET_LINE_PATTERN = /^(\d+): (.*)$/;

function SnippetBlock({ snippet, highlightLine }: { snippet: string; highlightLine: number }) {
  const lines = snippet.split("\n");
  return (
    <pre className="overflow-x-auto rounded-md border border-surface-border bg-black/5 p-3 text-xs dark:bg-white/5">
      <code>
        {lines.map((raw, i) => {
          const match = raw.match(SNIPPET_LINE_PATTERN);
          const lineNumber = match ? Number(match[1]) : null;
          const content = match ? match[2] : raw;
          const isTarget = lineNumber === highlightLine;
          return (
            <div
              key={i}
              className={`flex gap-3 px-1 ${isTarget ? "bg-danger/10 text-foreground" : "text-muted"}`}
            >
              <span className="w-8 shrink-0 select-none text-right opacity-60">{lineNumber ?? ""}</span>
              <span className="whitespace-pre">{content}</span>
            </div>
          );
        })}
      </code>
    </pre>
  );
}
