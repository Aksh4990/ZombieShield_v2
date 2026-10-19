import { useState, type FormEvent } from 'react'
import { api } from '../api'
import type { Role } from '../types'
import { ErrorNotice, Loading, PageHead, Panel, useAsync, useCan, useToast, when } from '../ui'

export default function Admin() {
  const isAdmin = useCan('admin')
  if (!isAdmin) return <><PageHead title="Users & audit" /><ErrorNotice error="This page needs the admin role." /></>
  return (
    <div className="stack loose">
      <PageHead title="Users & audit" lead="Who can use ZombieShield, and a record of every sign-in, pipeline run and gateway change." />
      <div className="grid side">
        <AuditLog />
        <Users />
      </div>
    </div>
  )
}

function AuditLog() {
  const { data, error, reload } = useAsync(() => api.audit(300), [])
  const [filter, setFilter] = useState('')
  const rows = (data ?? []).filter(e => !filter || e.action.startsWith(filter))
  const prefixes = [...new Set((data ?? []).map(e => e.action.split('.')[0]))].sort()
  return (
    <Panel title="Audit log" aside={
      <select value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter audit log">
        <option value="">All actions</option>{prefixes.map(p => <option key={p} value={p}>{p}</option>)}
      </select>} flush>
      {error ? <div style={{ padding: 16 }}><ErrorNotice error={error} onRetry={() => reload()} /></div> : !data ? <Loading /> : (
        <div className="table-wrap" style={{ maxHeight: 640 }}>
          <table>
            <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Details</th></tr></thead>
            <tbody>{rows.map(e => (
              <tr key={e.id}>
                <td className="small muted nowrap">{when(e.at)}</td>
                <td className="small">{e.username}</td>
                <td className="mono small">{e.action}</td>
                <td className="small muted" style={{ overflowWrap: 'anywhere' }}>
                  {Object.entries(e.details ?? {}).filter(([, v]) => v !== null && v !== '').map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ')}
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

function Users() {
  const toast = useToast()
  const { data, error, reload } = useAsync(() => api.users(), [])
  const [form, setForm] = useState<{ username: string; password: string; role: Role }>({ username: '', password: '', role: 'viewer' })
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setFormError(null)
    try { await api.createUser(form); toast(`Created ${form.username}`); setForm({ username: '', password: '', role: 'viewer' }); void reload(true) }
    catch (exc) { setFormError(exc instanceof Error ? exc.message : String(exc)) } finally { setBusy(false) }
  }
  return (
    <div className="stack">
      <Panel title="Users" flush>
        {error ? <div style={{ padding: 16 }}><ErrorNotice error={error} /></div> : !data ? <Loading /> : (
          <table><tbody>{data.map(u => <tr key={u.id}><td><strong>{u.username}</strong><div className="cell-sub">since {when(u.created_at)}</div></td><td className="right small muted">{u.role}</td></tr>)}</tbody></table>
        )}
      </Panel>
      <form className="panel" onSubmit={submit}><div className="panel-body stack">
        <h3>Add a user</h3>
        <label className="field">Username<input type="text" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required minLength={3} pattern="[A-Za-z0-9_.\-]+" /></label>
        <label className="field">Password (at least 10 characters)<input type="password" autoComplete="new-password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required minLength={10} /></label>
        <label className="field">Role
          <select value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value as Role }))}>
            <option value="viewer">Viewer: read only</option><option value="analyst">Analyst: run the pipeline, verify rules</option><option value="admin">Admin: approve and apply gateway rules</option>
          </select>
        </label>
        {formError && <div className="notice error">{formError}</div>}
        <div><button className="btn primary" disabled={busy}>{busy ? 'Creating…' : 'Create user'}</button></div>
      </div></form>
    </div>
  )
}
