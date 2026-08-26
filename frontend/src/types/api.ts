// Formatos compartilhados que espelham os DTOs do backend (§27/§32/§33/§74).
// Mantidos manualmente em sincronia com docs/openapi.yaml — qualquer novo
// campo exposto pela API precisa ser refletido aqui para o frontend
// enxergá-lo com tipagem.

export interface User {
  id: string;
  username: string;
  email: string;
  display_name: string;
  active: boolean;
  created_at: string;
  last_seen_at?: string;
}

export type IntegrationStatus = "unknown" | "online" | "offline" | "degraded" | "disabled";

export interface Integration {
  id: string;
  key: string;
  name: string;
  type: string;
  enabled: boolean;
  status: IntegrationStatus;
  last_check_at?: string;
  last_success_at?: string;
  last_error?: string;
}

export type JobStatus = "queued" | "processing" | "completed" | "failed" | "dead_letter";

export interface TestJobResponse {
  job_id: string;
  status: JobStatus;
}

export interface PaginationMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

// GET /api/v1/admin/feature-flags (restrito a nix-admin) — ver docs/openapi.yaml.
export interface FeatureFlag {
  key: string;
  enabled: boolean;
  description?: string;
}

// Scanning (§ roadmap de segurança — docs/roadmap-secops-orchestrator.md):
// POST /api/v1/scanning/scans, GET /api/v1/scanning/scans/{scanID}/findings,
// GET /api/v1/scanning/findings.
export type ScanSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

// FindingTool: pedido do usuário — "quero que esse detalhe [do achado]
// tenha os dados da ferramenta". Name é o nome de exibição (ex.:
// "SonarQube", não o slug "sonarqube" já usado em ScanFinding.scanner);
// url, quando o backend consegue montar (nem toda ferramenta/achado
// permite), abre esse achado (ou pelo menos a regra/CVE por trás dele)
// direto na ferramenta que encontrou — ver transport/dto.go's toolLink.
export interface FindingTool {
  name: string;
  url?: string;
}

export interface ScanFinding {
  id: string;
  scan_id: string;
  scanner: string;
  target: string;
  finding_id: string;
  owasp_category: string;
  severity: ScanSeverity;
  description: string;
  file: string;
  line: number;
  // snippet (Fase 12): vazio pra achados de antes desta fase, ou pra um
  // achado sem file/line específico (ex.: uma vulnerabilidade de
  // dependência do Trivy) — nunca tratado como erro, só "sem trecho
  // disponível" (ver FindingsTable's Dialog).
  snippet?: string;
  // fingerprint (Fase 12): SHA-256 de scanner+finding_id+file+line,
  // estável entre re-scans do MESMO alvo — usado pra deduplicar achados
  // ao longo do histórico de um projeto, nunca exibido cru na UI.
  fingerprint: string;
  created_at: string;
  tool: FindingTool;
}

// GET /api/v1/scanning/projects/{projectID}/findings-history (Fase 12 —
// deduplicação por fingerprint): UM achado deduplicado ENTRE re-scans do
// MESMO projeto — "apareceu pela primeira vez em X, ainda presente em Y".
// TriageStatus (Fase 14 — Maturidade de AppSec): "" é o estado implícito
// "aberto, nunca triado" — nunca um quarto valor de string solto, sempre
// um dos três abaixo ou vazio. Mesmos três nomes que
// domain.TriageStatus usa no backend.
export type TriageStatus = "" | "false_positive" | "wont_fix" | "risk_accepted";

export interface ProjectFindingHistory {
  fingerprint: string;
  scanner: string;
  owasp_category: string;
  severity: ScanSeverity;
  description: string;
  file: string;
  line: number;
  first_seen_at: string;
  last_seen_at: string;
  scan_count: number;
  still_present: boolean;
  tool: FindingTool;
  triage_status: TriageStatus;
  triage_reason?: string;
  // triage_expires_at/triage_expired (Fase 14, continuação — expiração
  // de triagem): ambos ausentes quando não há prazo (ou não há
  // triagem). Um achado com triage_expired=true continua carregando
  // triage_status/triage_reason (a decisão fica registrada), mas volta
  // a contar como aberto — ver still_present acima, que é ortogonal.
  triage_expires_at?: string;
  triage_expired?: boolean;
}

// GET /api/v1/scanning/posture (Fase 14 — Maturidade de AppSec) — o card
// de postura de segurança do dashboard.
export interface ProjectPosture {
  project_id: string;
  project_name: string;
  open_critical: number;
  open_high: number;
}

// PaginationMeta é o formato de "meta" no envelope {data, error, meta} —
// devolvido por GET /api/v1/scanning/findings desde a Fase 14
// (Maturidade de AppSec: paginação de verdade, ver
// internal/domain/pagination.Meta no backend).
export interface PaginationMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface SecurityPosture {
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  triaged_count: number;
  projects_scanned: number;
  top_vulnerable: ProjectPosture[];
}

// GET /api/v1/scanning/posture/history (Fase 14, continuação —
// tendência histórica) — um ponto da série temporal que alimenta o
// gráfico de tendência do dashboard. date é "YYYY-MM-DD" (string, não
// timestamp — só a data importa, ver o backend's domain.PostureSnapshot).
export interface PostureSnapshot {
  date: string;
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  triaged_count: number;
  projects_scanned: number;
}

// GET/POST /api/v1/scanning/projects (Fase 10 — Projeto persistente +
// upload .zip). Target vem vazio pra um projeto "upload" (nunca teve alvo
// git) — use source_type, não a ausência de target, pra decidir como
// exibir o card. LastScan é opcional: nil pra um projeto ainda nunca
// escaneado.
export interface Project {
  id: string;
  name: string;
  source_type: "git" | "upload";
  target?: string;
  created_at: string;
  last_scan?: ScanStatus;
}

// GET /api/v1/scanning/scans/{scanID}/packages — inventário (Fase 11 —
// Syft), sempre vazio pra um scan que não pediu o scanner "syft". Nunca
// aparece em ScanFinding: Syft não produz achado, produz inventário (ver
// docs/roadmap-secops-orchestrator.md, seção "Extensão").
export interface ScanPackage {
  name: string;
  version: string;
  type: string;
  license: string;
}

// GET /api/v1/scanning/scans/{scanID} — consultado pela UI logo depois de
// disparar um scan (TriggerScanForm), via polling até status virar
// terminal, pra saber qual scanner falhou, de que tipo foi o erro (code,
// a mesma taxonomia de internal/domain/errors.Code do backend) e como
// corrigir (hint, já pronto em texto — calculado no backend a partir de
// code/scanner/message, ver transport/dto.go's remediationHint). Antes
// desta consulta existir, essa informação só aparecia no log do
// backend-worker.
export interface ScannerFailure {
  scanner: string;
  code: string;
  message: string;
  hint: string;
}

// ScannerRunStatus: "running" enquanto o scanner ainda não retornou —
// funciona mesmo com o job inteiro ainda em "processing"/"queued", o que
// dá o progresso EM TEMPO REAL (qual teste está rodando agora, quanto
// falta) pedido explicitamente pelo usuário.
export type ScannerRunStatus = "running" | "succeeded" | "failed";

export interface ScannerRun {
  scanner: string;
  status: ScannerRunStatus;
  started_at: string;
  finished_at?: string;
  duration_ms?: number;
  findings_count?: number;
  error?: string;
  // progress_detail: sub-progresso em texto livre (ex.: "ataque ativo:
  // 42%") — só o ZAP preenche isto hoje (spider + scan ativo podem levar
  // minutos), e só enquanto status === "running"; ausente pra todo outro
  // scanner e depois que este termina.
  progress_detail?: string;
}

export interface ScanStatus {
  job_id: string;
  status: JobStatus;
  target: string;
  // project_id (revisão de exibição de resultados): ausente pra um scan
  // avulso — presente quando este scan foi disparado a partir de um
  // Project (Fase 10). Usado pra saber se os achados deste scan podem
  // ser triados (a triagem é escopada a projeto, ver TriageStatus).
  project_id?: string;
  requested_scanners: string[];
  succeeded_scanners: string[] | null;
  failed_scanners: ScannerFailure[];
  scanner_runs: ScannerRun[];
  // progress_percent: fração dos scanners PEDIDOS que já chegaram a um
  // estado terminal — sempre 100 quando status já é
  // completed/failed/dead_letter, mesmo pra um scan antigo sem nenhuma
  // linha em scanner_runs (ver transport/dto.go's scanProgressPercent).
  progress_percent: number;
  attempts: number;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  // findings_by_severity (revisão de exibição de resultados — "quais
  // erros e warnings foram achados" na tela de histórico de scans):
  // ausente pra um scan que ainda não persistiu achado nenhum. Chaves
  // são CRITICAL/HIGH/MEDIUM/LOW — nunca todas presentes, só as que têm
  // pelo menos 1 achado (ver o backend's toScanStatusResponse).
  findings_by_severity?: Partial<Record<ScanSeverity, number>>;
}

// GET /api/v1/scanning/scanners/health (revisão de exibição de
// resultados — "quero ter uma tela onde mostra a saúde das
// ferramentas... antes de iniciá-las").
export interface ScannerHealth {
  scanner: string;
  healthy: boolean;
  message?: string;
  checked_at: string;
}
