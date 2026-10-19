import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import type { Lifecycle, RiskLevel, Role, Session } from './types'

// ---------- formatting ----------
export const LIFECYCLES: Lifecycle[] = ['ACTIVE', 'DEPRECATED', 'SHADOW', 'ZOMBIE', 'DECOMMISSIONED']
export const LIFECYCLE_TEXT: Record<Lifecycle, { label: string; hint: string }> = {
  ACTIVE: { label: 'Active', hint: 'In the current spec or code' },
  DEPRECATED: { label: 'Deprecated', hint: 'Marked deprecated, still defined' },
  SHADOW: { label: 'Shadow', hint: 'Called, but never documented or implemented in scanned code' },
  ZOMBIE: { label: 'Zombie', hint: 'Removed from code or spec, still receiving traffic' },
  DECOMMISSIONED: { label: 'Decommissioned', hint: 'Removed and no recent traffic' },
}
export const RISK_LEVELS: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
/** Backend timestamps are UTC; SQLite returns them without an offset, so add one before parsing. */
export function parseTs(iso: string): Date {
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z')
}
export function ago(iso: string | null | undefined): string {
  if (!iso) return '–'
  const seconds = (parseTs(iso).getTime() - Date.now()) / 1000
  const abs = Math.abs(seconds)
  if (abs < 45) return 'just now'
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour')
  if (abs < 86400 * 45) return rtf.format(Math.round(seconds / 86400), 'day')
  return parseTs(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}
export const when = (iso: string | null | undefined) =>
  iso ? parseTs(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '–'
export const n = (value: number | null | undefined) => (value ?? 0).toLocaleString()
export const pct = (value: number | null | undefined, digits = 0) => value == null ? '–' : `${(value * 100).toFixed(digits)}%`
export function duration(start?: string | null, end?: string | null): string {
  if (!start) return ''
  const ms = (end ? parseTs(end).getTime() : Date.now()) - parseTs(start).getTime()
  const s = Math.max(0, Math.round(ms / 1000))
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`
}
export const humanize = (key: string) => key.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase())

// ---------- routing (hash based, no dependency) ----------
export function useRoute(): string[] {
  const read = () => (window.location.hash.replace(/^#\/?/, '').split('?')[0] || 'overview').split('/').map(decodeURIComponent)
  const [parts, setParts] = useState(read)
  useEffect(() => {
    const onChange = () => { setParts(read()); window.scrollTo(0, 0) }
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return parts
}
export function queryParam(name: string): string | null {
  const query = window.location.hash.split('?')[1]
  return query ? new URLSearchParams(query).get(name) : null
}
export const go = (path: string) => { window.location.hash = '#/' + path }

// ---------- data hooks ----------
export function useAsync<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const counter = useRef(0)
  const reload = useCallback(async (quiet = false) => {
    const ticket = ++counter.current
    if (!quiet) setLoading(true)
    try {
      const value = await load()
      if (ticket === counter.current) { setData(value); setError(null) }
    } catch (exc) {
      if (ticket === counter.current) setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      if (ticket === counter.current) setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => { void reload() }, [reload])
  return { data, error, loading, reload, setData }
}

export function useInterval(fn: () => void, ms: number | null) {
  const saved = useRef(fn)
  saved.current = fn
  useEffect(() => {
    if (ms == null) return
    const id = window.setInterval(() => { if (!document.hidden) saved.current() }, ms)
    return () => window.clearInterval(id)
  }, [ms])
}

// ---------- session + toasts ----------
export const SessionContext = createContext<Session | null>(null)
export const useSession = () => useContext(SessionContext)
const ROLE_ORDER: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }
export function useCan(role: Role): boolean {
  const session = useSession()
  return !!session && ROLE_ORDER[session.role] >= ROLE_ORDER[role]
}

type Toast = { text: string; kind: 'ok' | 'error' }
export const ToastContext = createContext<(text: string, kind?: Toast['kind']) => void>(() => {})
export const useToast = () => useContext(ToastContext)
export function ToastHost({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<Toast | null>(null)
  const timer = useRef<number | undefined>(undefined)
  const show = useCallback((text: string, kind: Toast['kind'] = 'ok') => {
    setToast({ text, kind })
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setToast(null), kind === 'error' ? 8000 : 4000)
  }, [])
  return (
    <ToastContext.Provider value={show}>
      {children}
      {toast && <div className={`toast ${toast.kind}`} role="status" aria-live="polite">{toast.text}</div>}
    </ToastContext.Provider>
  )
}

// ---------- small components ----------
export function StateTag({ state }: { state: Lifecycle }) {
  return <span className={`state ${state} c-${state}`} title={LIFECYCLE_TEXT[state].hint}>{LIFECYCLE_TEXT[state].label}</span>
}

export function RiskPill({ score, level }: { score: number | null; level: RiskLevel | string | null }) {
  if (score == null || !level) return <span className="faint small">not scored</span>
  return (
    <span className={`risk c-${level}`} title={`${level.toLowerCase()} risk`}>
      <span className="risk-score">{Math.round(score)}</span>
      <span className="risk-bar" aria-hidden><span style={{ width: `${Math.min(100, score)}%` }} /></span>
    </span>
  )
}

export const Method = ({ m }: { m: string }) => <span className={`method ${m}`}>{m}</span>
export const Status = ({ s }: { s: string }) => <span className={`status ${s}`}>{humanize(s.toLowerCase())}</span>

export function Endpoint({ method, path, sub }: { method: string; path: string; sub?: ReactNode }) {
  return (
    <div className="row top" style={{ gap: 8 }}>
      <Method m={method} />
      <div className="grow">
        <div className="path">{path}</div>
        {sub && <div className="cell-sub">{sub}</div>}
      </div>
    </div>
  )
}

export function ErrorNotice({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="notice error row">
      <span className="grow">{error}</span>
      {onRetry && <button className="btn small" onClick={onRetry}>Try again</button>}
    </div>
  )
}

export const Loading = ({ label = 'Loading…' }: { label?: string }) => <div className="empty" aria-busy="true">{label}</div>

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div style={{ color: 'var(--text)', fontWeight: 600 }}>{title}</div>
      {children && <div className="small" style={{ marginTop: 4, maxWidth: '60ch', marginInline: 'auto' }}>{children}</div>}
      {action}
    </div>
  )
}

export function PageHead({ title, lead, children }: { title: string; lead?: ReactNode; children?: ReactNode }) {
  useEffect(() => { document.title = `${title} · ZombieShield` }, [title])
  return (
    <div className="page-head">
      <div className="grow">
        <h1>{title}</h1>
        {lead && <p className="lead">{lead}</p>}
      </div>
      {children}
    </div>
  )
}

export function Panel({ title, aside, children, flush }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className={`panel${flush ? ' flush' : ''}`}>
      {(title || aside) && <div className="panel-head">{title && <h2 className="grow">{title}</h2>}{aside}</div>}
      <div className="panel-body">{children}</div>
    </section>
  )
}

export function LifecycleStrip({ counts, total, linkTo = true }: { counts: Partial<Record<Lifecycle, number>>; total: number; linkTo?: boolean }) {
  const states = LIFECYCLES.filter(s => (counts[s] ?? 0) > 0)
  return (
    <div>
      <div className="strip" role="img" aria-label={LIFECYCLES.map(s => `${counts[s] ?? 0} ${LIFECYCLE_TEXT[s].label}`).join(', ')}>
        {total === 0 && <div style={{ flex: 1, background: 'var(--raised)' }} />}
        {states.map(s => {
          const share = (counts[s] ?? 0) / Math.max(1, total)
          const style = { flex: counts[s], background: `var(--${s.toLowerCase()})` }
          const label = share > 0.07 ? `${Math.round(share * 100)}%` : ''
          return linkTo
            ? <a key={s} href={`#/inventory?state=${s}`} style={style} title={`${counts[s]} ${LIFECYCLE_TEXT[s].label}`}>{label}</a>
            : <div key={s} style={style}>{label}</div>
        })}
      </div>
      <div className="strip-legend">
        {LIFECYCLES.map(s => (
          <a key={s} href={`#/inventory?state=${s}`} style={{ ['--c' as string]: `var(--${s.toLowerCase()})` }}>
            <div className="legend-n">{n(counts[s])}</div>
            <div className="legend-label">{LIFECYCLE_TEXT[s].label}</div>
            <div className="faint small">{LIFECYCLE_TEXT[s].hint}</div>
          </a>
        ))}
      </div>
    </div>
  )
}

export function Confirm({ open, title, body, confirmLabel, danger, withNote, onConfirm, onClose }: {
  open: boolean; title: string; body: ReactNode; confirmLabel: string; danger?: boolean; withNote?: boolean
  onConfirm: (note: string) => void; onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [note, setNote] = useState('')
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) { setNote(''); d.showModal() }
    if (!open && d.open) d.close()
  }, [open])
  return (
    <dialog ref={ref} onClose={onClose} aria-labelledby="confirm-title">
      <form method="dialog" onSubmit={e => { e.preventDefault(); onConfirm(note) }}>
        <div className="panel-body stack">
          <h2 id="confirm-title">{title}</h2>
          <div className="muted">{body}</div>
          {withNote && (
            <label className="field">Note for the audit log (optional)
              <input type="text" value={note} onChange={e => setNote(e.target.value)} maxLength={2000} />
            </label>
          )}
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className={`btn ${danger ? 'danger' : 'primary'}`} autoFocus>{confirmLabel}</button>
          </div>
        </div>
      </form>
    </dialog>
  )
}
