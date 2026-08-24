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

export interface ScanStatus {
  job_id: string;
  status: JobStatus;
  target: string;
  requested_scanners: string[];
  succeeded_scanners: string[] | null;
  failed_scanners: ScannerFailure[];
  attempts: number;
  created_at: string;
  started_at?: string;
  finished_at?: string;
}
