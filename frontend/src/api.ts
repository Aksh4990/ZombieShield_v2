import type {
  Anomaly, ApiDetail, ApiSummary, AuditEntry, Bucket, Component, PipelineRun, RemediationAction, RequestRow, Role,
  Session, Source, Summary, User, ValidationRun, Vulnerability,
} from './types'

export const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? 'http://localhost:8000'
const SESSION_KEY = 'zombieshield.session'

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

let session: Session | null = null
const listeners = new Set<(s: Session | null) => void>()

export function loadSession(): Session | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    session = raw ? (JSON.parse(raw) as Session) : null
  } catch { session = null }
  return session
}

export function setSession(next: Session | null): void {
  session = next
  try {
    if (next) localStorage.setItem(SESSION_KEY, JSON.stringify(next))
    else localStorage.removeItem(SESSION_KEY)
  } catch { /* storage unavailable: the session lives for this tab only */ }
  listeners.forEach(fn => fn(next))
}

export function onSessionChange(fn: (s: Session | null) => void): () => void {
  listeners.add(fn)
  return () => { listeners.delete(fn) }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(session ? { Authorization: `Bearer ${session.token}` } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(0, `Can't reach the ZombieShield backend at ${API_BASE}. Check that the backend container is running.`)
  }
  if (response.status === 401 && session) {
    setSession(null)
    throw new ApiError(401, 'Your session expired. Sign in again.')
  }
  if (!response.ok) {
    const data = await response.json().catch(() => null) as { detail?: unknown } | null
    const detail = typeof data?.detail === 'string' ? data.detail
      : Array.isArray(data?.detail) ? (data!.detail as { msg?: string }[]).map(d => d.msg).join('; ')
      : `Request failed (${response.status})`
    throw new ApiError(response.status, detail)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

const get = <T,>(path: string) => call<T>('GET', path)
const post = <T,>(path: string, body: unknown = {}) => call<T>('POST', path, body)

const qs = (params: Record<string, string | number | boolean | undefined | null>) => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
  return entries.length ? '?' + new URLSearchParams(entries.map(([k, v]) => [k, String(v)])).toString() : ''
}

export const api = {
  login: (username: string, password: string) =>
    post<{ access_token: string; username: string; role: Role }>('/auth/login', { username, password }),
  summary: () => get<Summary>('/dashboard/summary'),
  apis: (params: { q?: string; lifecycle_state?: string; service?: string; sort?: string; limit?: number } = {}) =>
    get<ApiSummary[]>('/apis' + qs({ limit: 2000, ...params })),
  apiDetail: (id: string) => get<ApiDetail>(`/apis/${id}`),
  updateApi: (id: string, changes: Partial<Pick<ApiDetail, 'owner' | 'notes' | 'is_registered' | 'manually_deprecated' | 'manually_removed'>>) =>
    call<ApiSummary>('PATCH', `/apis/${id}`, changes),
  services: () => get<string[]>('/services'),

  runs: () => get<PipelineRun[]>('/pipeline/runs?limit=20'),
  run: (id: string) => get<PipelineRun>(`/pipeline/runs/${id}`),
  startRun: (logsFromStart: boolean) => post<PipelineRun>('/pipeline/run', { logs_from_start: logsFromStart }),
  extensions: () => get<Record<string, { module: string; implemented: boolean }>>('/pipeline/extensions'),

  remediation: (params: { status?: string; api_id?: string } = {}) => get<RemediationAction[]>('/remediation' + qs(params)),
  remediationStep: (id: string, step: string, note?: string) => post<RemediationAction>(`/remediation/${id}/${step}`, note ? { note } : {}),
  gatewayConfig: () => get<{ rules: number; files: Record<string, string> }>('/remediation/gateway-config'),

  vulnerabilities: () => get<Vulnerability[]>('/threat-intel/vulnerabilities'),
  components: () => get<Component[]>('/threat-intel/components'),

  recentRequests: (limit = 100, afterId?: number) => get<RequestRow[]>('/traffic/recent' + qs({ limit, after_id: afterId })),
  timeseries: (minutes = 60, bucketSeconds = 60) => get<Bucket[]>('/traffic/timeseries' + qs({ minutes, bucket_seconds: bucketSeconds })),
  anomalies: () => get<Anomaly[]>('/traffic/anomalies'),
  models: () => get<Record<string, { loaded: boolean; metrics: Record<string, unknown> | null }>>('/ml/models'),

  sources: () => get<Source[]>('/sources'),
  createSource: (body: Partial<Source>) => post<Source>('/sources', body),
  updateSource: (id: string, body: Partial<Source>) => call<Source>('PUT', `/sources/${id}`, body),
  deleteSource: (id: string) => call<void>('DELETE', `/sources/${id}`),
  runSource: (id: string) => post<{ results: Record<string, unknown>[]; apis_added: number }>(`/sources/${id}/run`),
  uploadOpenApi: (body: { document: string; name: string; host: string; service_name?: string }) =>
    post<{ results: Record<string, unknown>[]; apis_added: number }>('/discovery/openapi', body),
  uploadLog: (body: { log_content: string; name: string; host: string; service_name?: string }) =>
    post<{ results: Record<string, unknown>[]; apis_added: number }>('/discovery/runtime-log', body),

  validationRuns: () => get<ValidationRun[]>('/validation/runs'),
  runValidation: (truth: unknown) => post<ValidationRun>('/validation/run', truth),

  audit: (limit = 200) => get<AuditEntry[]>(`/audit?limit=${limit}`),
  users: () => get<User[]>('/users'),
  createUser: (body: { username: string; password: string; role: Role }) => post<User>('/users', body),
}
