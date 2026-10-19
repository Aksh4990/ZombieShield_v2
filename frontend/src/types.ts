export type Lifecycle = 'ACTIVE' | 'DEPRECATED' | 'SHADOW' | 'ZOMBIE' | 'DECOMMISSIONED'
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Role = 'viewer' | 'analyst' | 'admin'

export interface Session { token: string; username: string; role: Role }

export interface ApiSummary {
  id: string
  organization: string
  service_name: string
  host: string
  http_method: string
  endpoint_path: string
  display_path: string
  version: string
  sources: string[]
  in_current_spec: boolean
  in_current_code: boolean
  in_runtime: boolean
  previously_in_spec: boolean
  previously_in_code: boolean
  spec_deprecated: boolean
  superseded_by: string | null
  owner: string | null
  lifecycle_state: Lifecycle
  classification_reason: string | null
  risk_score: number | null
  risk_level: RiskLevel | null
  request_count: number
  unique_clients: number
  vulnerability_count: number
  kev_count: number
  attack_request_count: number
  anomalous_client_count: number
  ml_legacy_score: number | null
  ml_sensitivity_score: number | null
  first_seen: string
  last_seen: string
  last_runtime_seen: string | null
}

export interface Evidence { id: string; kind: string; source: string; summary: string; details: Record<string, unknown>; observed_at: string }
export interface Decision { id: string; api_id: string; action: 'MONITOR' | 'REMEDIATE' | 'ESCALATE'; status: string; reason: string; decided_at: string }
export interface RiskFactor { factor: string; points: number; evidence: string }
export interface Control { status: string; summary: string; evidence: Record<string, unknown> }
export interface OwaspItem { id: string; name: string; reason: string }
export interface MlExplanation { model: string; score: number; threshold: number; flagged: boolean; signals: string[]; trained_on: string }

export interface ServiceVulnerability {
  id: string; aliases: string[]; summary: string; severity: string; cvss_score: number | null; in_kev: boolean
  kev_date_added: string | null; epss: number | null; epss_percentile: number | null; url: string
  component: string; version: string; ecosystem: string; manifest: string; fixed_versions: string[]; match_reason: string
}

export interface ApiDetail extends ApiSummary {
  current_sources: string[]
  spec_security: string[]
  spec_version: string | null
  code_location: string | null
  removed_in_commit: string | null
  removed_at: string | null
  removal_note: string | null
  is_registered: boolean
  manually_deprecated: boolean
  manually_removed: boolean
  notes: string | null
  error_count: number
  unauth_success_count: number
  ml_explanation: MlExplanation[]
  risk_breakdown: RiskFactor[]
  risk_explanation: string | null
  owasp_categories: string[]
  security_controls: Record<string, Control | OwaspItem[] | string>
  classified_at: string | null
  evidence: Evidence[]
  vulnerabilities: ServiceVulnerability[]
  decision: Decision | null
}

export interface Stage { key: string; name: string; status: string; started_at?: string; finished_at?: string; result?: Record<string, unknown>; error?: string }
export interface PipelineRun {
  id: string; status: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED'; triggered_by: string; options: Record<string, unknown>
  stages: Stage[]; summary: Record<string, unknown>; error: string | null; started_at: string; finished_at: string | null
}

export interface RemediationAction {
  id: string; api_id: string; kind: string; title: string; rationale: string; priority: string
  rule: { kind: string; host: string; method: string; path: string; path_regex: string; params: Record<string, unknown> }
  config_snippet: string; status: string; proposed_at: string; approved_by: string | null; approved_at: string | null
  applied_at: string | null; verified_at: string | null; verification_note: string | null
  api: { method: string; path: string; service: string; host: string; lifecycle_state: Lifecycle; risk_score: number | null } | null
  verification?: { passed: boolean; note: string }
  gateway?: { files: string[]; rules: number; skipped_other_hosts: number }
}

export interface Summary {
  total_apis: number
  lifecycle: Record<Lifecycle, number>
  by_source: Record<string, number>
  undocumented_in_use: number
  vulnerabilities: number
  kev_vulnerabilities: number
  requests_observed: number
  payload_attacks: number
  anomalous_windows: number
  decisions: Record<string, number>
  risk_levels: Partial<Record<RiskLevel, number>>
  remediation: Record<string, number>
  services: Record<string, Partial<Record<Lifecycle, number>>>
  attention: { id: string; method: string; path: string; service: string; state: Lifecycle; reason: string | null; requests: number; kev: number; risk_score: number | null; risk_level: RiskLevel | null }[]
  last_run: { id: string; status: string; started_at: string; finished_at: string | null } | null
}

export interface Source {
  id: string; name: string; kind: 'openapi' | 'git' | 'runtime_log' | 'sbom'; location: string; organization: string
  service_name: string | null; host: string; options: Record<string, unknown>; enabled: boolean
  last_run_at: string | null; last_status: string | null; created_at: string
}

export interface Component { id: string; service_name: string; ecosystem: string; name: string; version: string; purl: string; manifest: string; direct: boolean }
export interface Vulnerability {
  id: string; aliases: string[]; summary: string; severity: string; cvss_score: number | null; cvss_vector: string | null
  published: string | null; in_kev: boolean; kev_date_added: string | null; epss: number | null; epss_percentile: number | null; url: string
  affected: { service: string; component: string; version: string; ecosystem: string }[]
}

export interface RequestRow {
  id: number; ts: string; api_id: string | null; method: string; path: string; status: number; latency_ms: number | null
  client_hash: string | null; authenticated: boolean | null; service_name: string | null; payload_label: string | null; payload_score: number | null
}
export interface Bucket { t: string; total: number; errors: number; attacks: number; zombie: number; shadow: number; probes: number }
export interface Anomaly {
  id: string; client_hash: string; window_start: string; window_end: string; score: number; pattern: string
  features: Record<string, number>; reasons: string[]; top_endpoints: string[]
}

export interface AuditEntry { id: string; at: string; username: string; action: string; target_type: string | null; target_id: string | null; details: Record<string, unknown> }
export interface User { id: string; username: string; role: Role; created_at: string }

export interface Prf { precision: number; recall: number; f1: number; tp?: number; fp?: number; fn?: number; support?: number }
export interface ValidationRow { service: string; method: string; path: string; expected: string; predicted: string; correct: boolean; note: string | null; reason: string | null }
export interface ValidationRun {
  id: string; at: string; ground_truth: string
  metrics: {
    endpoints: number; accuracy: number; macro_f1: number; not_found: number
    unmanaged_zombie_or_shadow: Prf; zombie: Prf; per_class: Record<string, Prf>
    confusion_matrix: { rows_actual: string[]; columns_predicted: string[]; values: number[][] }
  }
  details: { rows: ValidationRow[] }
}
