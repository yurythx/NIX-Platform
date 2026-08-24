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
  created_at: string;
  tool: FindingTool;
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
}

export interface ScanStatus {
  job_id: string;
  status: JobStatus;
  target: string;
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
}
