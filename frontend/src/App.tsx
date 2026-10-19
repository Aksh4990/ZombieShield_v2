import { useEffect, useState, type FormEvent } from 'react'
import { api, loadSession, onSessionChange, setSession } from './api'
import type { Session, Summary } from './types'
import { LIFECYCLES, SessionContext, ToastHost, useInterval, useRoute } from './ui'
import Overview from './pages/Overview'
import Inventory from './pages/Inventory'
import ApiDetailPage from './pages/ApiDetail'
import Pipeline from './pages/Pipeline'
import Remediation from './pages/Remediation'
import Threats from './pages/Threats'
import Traffic from './pages/Traffic'
import Sources from './pages/Sources'
import Validation from './pages/Validation'
import Admin from './pages/Admin'

export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <path d="M16 2.5 27 6.6v8.2c0 7.2-4.6 12.3-11 14.7C9.6 27.1 5 22 5 14.8V6.6z" fill="none" stroke="var(--text)" strokeWidth="2" strokeLinejoin="round" />
      <path d="M16 9.5v13" stroke="var(--line-strong)" strokeWidth="1.5" />
      <circle cx="16" cy="15.5" r="3.6" fill="var(--zombie)" />
    </svg>
  )
}

const NAV: { key: string; label: string; adminOnly?: boolean }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'inventory', label: 'API inventory' },
  { key: 'remediation', label: 'Remediation' },
  { key: 'threats', label: 'Vulnerabilities' },
  { key: 'traffic', label: 'Traffic' },
  { key: 'pipeline', label: 'Pipeline' },
  { key: 'sources', label: 'Sources' },
  { key: 'validation', label: 'Models & validation' },
  { key: 'admin', label: 'Users & audit', adminOnly: true },
]

function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { document.title = 'Sign in · ZombieShield' }, [])
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      const res = await api.login(username, password)
      setSession({ token: res.access_token, username: res.username, role: res.role })
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally { setBusy(false) }
  }
  const strip = [['active', 6], ['deprecated', 1.2], ['shadow', 1.6], ['zombie', 0.8], ['decommissioned', 1]] as const
  return (
    <main className="login">
      <form className="login-card panel" onSubmit={submit}>
        <div className="panel-body stack" style={{ padding: 28 }}>
          <div className="login-strip" aria-hidden>{strip.map(([k, f]) => <i key={k} style={{ ['--f' as string]: f, ['--c' as string]: `var(--${k})` }} />)}</div>
          <div className="row"><Logo size={34} /><div><div className="brand-name" style={{ fontSize: 20 }}>ZombieShield</div><div className="muted small">Find the APIs you forgot you were running</div></div></div>
          <label className="field">Username<input type="text" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required autoFocus /></label>
          <label className="field">Password<input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required /></label>
          {error && <div className="notice error">{error}</div>}
          <button className="btn primary" type="submit" disabled={busy} style={{ justifyContent: 'center', padding: '8px 12px' }}>{busy ? 'Signing in…' : 'Sign in'}</button>
          <p className="faint small">Accounts are created by an administrator. Lab defaults are set in the backend's <code>.env</code>.</p>
        </div>
      </form>
    </main>
  )
}

export default function App() {
  const [session, setLocalSession] = useState<Session | null>(() => loadSession())
  useEffect(() => onSessionChange(setLocalSession), [])
  if (!session) return <ToastHost><Login /></ToastHost>
  return (
    <SessionContext.Provider value={session}>
      <ToastHost><Shell session={session} /></ToastHost>
    </SessionContext.Provider>
  )
}

function Shell({ session }: { session: Session }) {
  const route = useRoute()
  const [navOpen, setNavOpen] = useState(false)
  const [summary, setSummary] = useState<Summary | null>(null)
  const refreshCounts = () => { api.summary().then(setSummary).catch(() => {}) }
  useEffect(refreshCounts, [route[0]])
  useInterval(refreshCounts, 30000)
  useEffect(() => setNavOpen(false), [route.join('/')])

  const page = route[0]
  const active = page === 'apis' ? 'inventory' : page
  const counts: Record<string, { value: number; alert?: boolean } | undefined> = summary ? {
    inventory: { value: summary.total_apis },
    remediation: { value: summary.remediation?.PROPOSED ?? 0, alert: (summary.remediation?.PROPOSED ?? 0) > 0 },
    threats: { value: summary.vulnerabilities, alert: summary.kev_vulnerabilities > 0 },
  } : {}

  let content
  switch (page) {
    case 'inventory': content = <Inventory />; break
    case 'apis': content = <ApiDetailPage id={route[1]} />; break
    case 'pipeline': content = <Pipeline />; break
    case 'remediation': content = <Remediation />; break
    case 'threats': content = <Threats />; break
    case 'traffic': content = <Traffic />; break
    case 'sources': content = <Sources />; break
    case 'validation': content = <Validation />; break
    case 'admin': content = <Admin />; break
    default: content = <Overview summary={summary} reloadSummary={refreshCounts} />
  }

  return (
    <div className={`shell${navOpen ? ' nav-open' : ''}`}>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand"><Logo /><div><div className="brand-name">ZombieShield</div><div className="brand-sub">API lifecycle security</div></div></div>
        {summary && summary.total_apis > 0 && (
          <a href="#/overview" className="strip" style={{ height: 6, margin: '0 8px' }} aria-label="Inventory by lifecycle">
            {LIFECYCLES.filter(s => summary.lifecycle[s]).map(s => <div key={s} style={{ flex: summary.lifecycle[s], background: `var(--${s.toLowerCase()})`, padding: 0 }} />)}
          </a>
        )}
        <nav className="nav">
          {NAV.filter(item => !item.adminOnly || session.role === 'admin').map(item => {
            const c = counts[item.key]
            return (
              <a key={item.key} href={`#/${item.key}`} aria-current={active === item.key ? 'page' : undefined}>
                {item.label}
                {c && c.value > 0 && <span className={`count${c.alert ? ' alert' : ''}`}>{c.value}</span>}
              </a>
            )
          })}
        </nav>
        <div className="sidebar-foot stack tight">
          <div><strong>{session.username}</strong> <span className="faint">· {session.role}</span></div>
          <button className="btn small" onClick={() => setSession(null)}>Sign out</button>
        </div>
      </aside>
      <div style={{ minWidth: 0 }}>
        <div className="mobile-bar">
          <button className="btn small" onClick={() => setNavOpen(o => !o)} aria-expanded={navOpen}>Menu</button>
          <Logo size={22} /><strong>ZombieShield</strong>
        </div>
        <main className="main" onClick={() => navOpen && setNavOpen(false)}>{content}</main>
      </div>
    </div>
  )
}
