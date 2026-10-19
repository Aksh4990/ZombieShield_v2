import { useState, type FormEvent } from 'react'
import { api } from '../api'
import type { Source } from '../types'
import { ago, Confirm, Empty, ErrorNotice, Loading, PageHead, Panel, useAsync, useCan, useToast } from '../ui'

const KIND_TEXT: Record<Source['kind'], { label: string; location: string; hint: string }> = {
  git: { label: 'Git repository', location: 'Folder name under the discovery repositories directory', hint: 'Routes in code, OpenAPI files, dependency manifests and the git history of removed routes' },
  openapi: { label: 'OpenAPI file', location: 'Path to an OpenAPI 3 or Swagger 2 file on the backend', hint: 'Documented operations, deprecation flags and declared security' },
  runtime_log: { label: 'Gateway log', location: 'Path to an access log on the backend', hint: 'Live traffic: JSON gateway logs, nginx or Apache combined format' },
  sbom: { label: 'SBOM', location: 'Path to a CycloneDX file or folder', hint: 'Dependencies for threat intelligence' },
}

function summariseResults(results: Record<string, unknown>[]): string {
  return results.map(r => `${r.source ?? ''}: ${r.discovered ?? 0} found, ${r.added ?? 0} new${r.retired ? `, ${r.retired} retired` : ''}`).join('; ')
}

export default function Sources() {
  const canEdit = useCan('analyst')
  const toast = useToast()
  const { data, error, loading, reload } = useAsync(() => api.sources(), [])
  const [adding, setAdding] = useState(false)
  const [running, setRunning] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<Source | null>(null)

  const runOne = async (s: Source) => {
    setRunning(s.id)
    try {
      const res = await api.runSource(s.id)
      toast(`${s.name}: ${summariseResults(res.results) || 'done'}`)
      void reload(true)
    } catch (exc) { toast(exc instanceof Error ? exc.message : String(exc), 'error') } finally { setRunning(null) }
  }
  const toggle = async (s: Source) => {
    try {
      const { id, last_run_at, last_status, created_at, ...rest } = s
      void id; void last_run_at; void last_status; void created_at
      await api.updateSource(s.id, { ...rest, enabled: !s.enabled })
      void reload(true)
    } catch (exc) { toast(exc instanceof Error ? exc.message : String(exc), 'error') }
  }
  const remove = async (s: Source) => {
    setDeleting(null)
    try { await api.deleteSource(s.id); toast(`Removed source ${s.name}`); void reload(true) }
    catch (exc) { toast(exc instanceof Error ? exc.message : String(exc), 'error') }
  }

  return (
    <div className="stack loose">
      <PageHead title="Sources" lead="Where ZombieShield looks for APIs. Every pipeline run reads all enabled sources; you can also read one source on its own.">
        {canEdit && <button className="btn primary" onClick={() => setAdding(v => !v)} aria-expanded={adding}>{adding ? 'Close' : 'Add source'}</button>}
      </PageHead>

      {adding && <AddSource onAdded={() => { setAdding(false); void reload(true) }} />}

      <section className="panel flush"><div className="panel-body table-wrap">
        {error ? <div style={{ padding: 16 }}><ErrorNotice error={error} onRetry={() => reload()} /></div> : loading && !data ? <Loading />
          : !data?.length ? <Empty title="No sources configured">Add a git repository, an OpenAPI file or a gateway log so the pipeline has something to read.</Empty>
          : (
            <table>
              <thead><tr><th>Source</th><th>Location</th><th>Service · host</th><th>Last read</th><th /></tr></thead>
              <tbody>
                {data.map(s => (
                  <tr key={s.id} style={s.enabled ? undefined : { opacity: 0.55 }}>
                    <td><strong>{s.name}</strong><div className="cell-sub">{KIND_TEXT[s.kind]?.label ?? s.kind}{s.enabled ? '' : ' · disabled'}{s.options?.follow ? ' · followed live' : ''}</div></td>
                    <td className="mono small" style={{ maxWidth: 320, overflowWrap: 'anywhere' }}>{s.location}</td>
                    <td className="small">{s.service_name ?? <span className="faint">from data</span>}<div className="cell-sub">{s.host}</div></td>
                    <td className="small" style={{ maxWidth: 280 }}>
                      {!s.last_run_at ? <span className="faint">never</span> : s.last_status?.startsWith('ERROR') ? <span className="status FAILED">failed</span> : <span className="status SUCCEEDED">read</span>}
                      <span className="faint"> {ago(s.last_run_at)}</span>
                      {s.last_status && s.last_status !== 'ok' && <div className="cell-sub">{s.last_status.replace(/^ERROR:\s*/, '')}</div>}
                    </td>
                    <td className="right">
                      {canEdit && <div className="row" style={{ justifyContent: 'flex-end' }}>
                        <button className="btn small" disabled={!!running || !s.enabled} onClick={() => runOne(s)}>{running === s.id ? 'Reading…' : 'Read now'}</button>
                        <button className="btn small ghost" onClick={() => toggle(s)}>{s.enabled ? 'Disable' : 'Enable'}</button>
                        <button className="btn small ghost" onClick={() => setDeleting(s)} aria-label={`Remove ${s.name}`}>Remove</button>
                      </div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div></section>

      {canEdit && <ManualUpload />}

      {deleting && <Confirm open title={`Remove ${deleting.name}?`} danger confirmLabel="Remove source"
        body="The source is no longer read by the pipeline. APIs it already discovered stay in the inventory with their evidence."
        onConfirm={() => remove(deleting)} onClose={() => setDeleting(null)} />}
    </div>
  )
}

function AddSource({ onAdded }: { onAdded: () => void }) {
  const toast = useToast()
  const [kind, setKind] = useState<Source['kind']>('git')
  const [form, setForm] = useState({ name: '', location: '', service_name: '', host: '', organization: 'zombieshield-lab', follow: true })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm(f => ({ ...f, [k]: e.target.value }))
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError(null)
    try {
      await api.createSource({
        name: form.name, kind, location: form.location, organization: form.organization,
        service_name: form.service_name || null, host: form.host || 'api.local',
        options: kind === 'runtime_log' ? { follow: form.follow } : {}, enabled: true,
      })
      toast(`Added source ${form.name}`); onAdded()
    } catch (exc) { setError(exc instanceof Error ? exc.message : String(exc)) } finally { setBusy(false) }
  }
  return (
    <form className="panel" onSubmit={submit}><div className="panel-body stack">
      <h2>Add a source</h2>
      <div className="seg" role="group" aria-label="Source type">
        {(Object.keys(KIND_TEXT) as Source['kind'][]).map(k => <button type="button" key={k} aria-pressed={kind === k} onClick={() => setKind(k)}>{KIND_TEXT[k].label}</button>)}
      </div>
      <p className="muted small">{KIND_TEXT[kind].hint}</p>
      <div className="grid two">
        <label className="field">Name<input type="text" value={form.name} onChange={set('name')} required maxLength={255} /></label>
        <label className="field">{KIND_TEXT[kind].location}<input type="text" value={form.location} onChange={set('location')} required className="mono" /></label>
        <label className="field">Service name (optional)<input type="text" value={form.service_name} onChange={set('service_name')} /></label>
        <label className="field">Host the APIs are served on<input type="text" value={form.host} onChange={set('host')} placeholder="api.local" /></label>
      </div>
      {kind === 'runtime_log' && <label className="check"><input type="checkbox" checked={form.follow} onChange={e => setForm(f => ({ ...f, follow: e.target.checked }))} /> Follow the log live between pipeline runs</label>}
      {error && <div className="notice error">{error}</div>}
      <div><button className="btn primary" disabled={busy}>{busy ? 'Adding…' : 'Add source'}</button></div>
    </div></form>
  )
}

function ManualUpload() {
  const toast = useToast()
  const [kind, setKind] = useState<'openapi' | 'log'>('openapi')
  const [text, setText] = useState('')
  const [host, setHost] = useState('api.local')
  const [service, setService] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const readFile = (file: File | undefined) => { if (file) file.text().then(setText) }
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError(null); setResult(null)
    try {
      const base = { name: kind === 'openapi' ? 'manual-openapi' : 'manual-log', host, service_name: service || undefined }
      const res = kind === 'openapi' ? await api.uploadOpenApi({ ...base, document: text }) : await api.uploadLog({ ...base, log_content: text })
      setResult(`${res.apis_added} new APIs. ${summariseResults(res.results)}`); toast('Upload read into the inventory')
    } catch (exc) { setError(exc instanceof Error ? exc.message : String(exc)) } finally { setBusy(false) }
  }
  return (
    <Panel title="Read a file once" aside={
      <div className="seg" role="group" aria-label="Upload type">
        <button type="button" aria-pressed={kind === 'openapi'} onClick={() => setKind('openapi')}>OpenAPI document</button>
        <button type="button" aria-pressed={kind === 'log'} onClick={() => setKind('log')}>Access log</button>
      </div>}>
      <form className="stack" onSubmit={submit}>
        <p className="muted small">Adds what it finds to the inventory without creating a source. Run the pipeline afterwards to classify and score it.</p>
        <div className="row wrap">
          <input type="file" accept={kind === 'openapi' ? '.json,.yaml,.yml' : '.log,.txt,.json,.jsonl'} onChange={e => readFile(e.target.files?.[0])} aria-label="Choose a file" />
          <label className="field" style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>Host<input type="text" value={host} onChange={e => setHost(e.target.value)} style={{ width: 150 }} /></label>
          <label className="field" style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>Service<input type="text" value={service} onChange={e => setService(e.target.value)} style={{ width: 150 }} /></label>
        </div>
        <textarea rows={8} value={text} onChange={e => setText(e.target.value)} placeholder={kind === 'openapi' ? 'Paste an OpenAPI 3 or Swagger 2 document (JSON or YAML)' : 'Paste access log lines (JSON per line, or nginx/Apache combined format)'} aria-label="File contents" />
        {error && <div className="notice error">{error}</div>}
        {result && <div className="notice ok">{result}</div>}
        <div><button className="btn primary" disabled={busy || !text.trim()}>{busy ? 'Reading…' : 'Read into inventory'}</button></div>
      </form>
    </Panel>
  )
}
