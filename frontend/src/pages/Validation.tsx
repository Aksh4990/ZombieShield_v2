import { useState, type FormEvent } from 'react'
import { api } from '../api'
import type { Prf, ValidationRun } from '../types'
import { Empty, ErrorNotice, Loading, PageHead, Panel, pct, StateTag, useAsync, useCan, useToast, when } from '../ui'
import type { Lifecycle } from '../types'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const TEMPLATE = JSON.stringify({
  name: 'Sock Shop ground truth',
  endpoints: [
    { service: 'catalogue', method: 'GET', path: '/catalogue/{id}', expected: 'ACTIVE', note: 'documented and implemented' },
    { service: 'front-end', method: 'PUT', path: '/cart/{id}', expected: 'DECOMMISSIONED', note: 'removed in 2017' },
  ],
}, null, 2)

export default function Validation() {
  const models = useAsync(() => api.models(), [])
  return (
    <div className="stack loose">
      <PageHead title="Models & validation" lead="How the machine-learning models were trained and evaluated, and how ZombieShield's lifecycle labels compare with a hand-made ground truth." />
      {models.error ? <ErrorNotice error={models.error} /> : !models.data ? <Loading /> : (
        <div className="grid three">
          <PayloadCard m={models.data.payload?.metrics as Json | null} loaded={models.data.payload?.loaded} />
          <EndpointCard m={models.data.endpoint?.metrics as Json | null} loaded={models.data.endpoint?.loaded} />
          <AnomalyCard m={models.data.anomaly?.metrics as Json | null} />
        </div>
      )}
      <GroundTruth />
    </div>
  )
}

const Metric = ({ label, value }: { label: string; value: string }) => <><dt>{label}</dt><dd className="num">{value}</dd></>
const Loaded = ({ on }: { on?: boolean }) => <span className={on ? 'status SUCCEEDED' : 'status FAILED'}>{on ? 'loaded' : 'not loaded'}</span>

function PayloadCard({ m, loaded }: { m: Json | null; loaded?: boolean }) {
  const selected = (m?.comparison as Json[] | undefined)?.find(c => c.selected)
  return (
    <Panel title="Attack payload classifier" aside={<Loaded on={loaded} />}>
      {!m ? <p className="muted">No metrics file found.</p> : (
        <div className="stack">
          <p className="muted small">{m.selected_model}, decision threshold {m.decision_threshold}. Trained on HTTP CSIC 2010 and HttpParams.</p>
          <dl className="kv small">
            {selected?.csic2010_test && <><Metric label="CSIC test precision" value={pct(selected.csic2010_test.precision, 1)} /><Metric label="CSIC test recall" value={pct(selected.csic2010_test.recall, 1)} /></>}
            {selected?.httpparams_test && <Metric label="HttpParams test F1" value={pct(selected.httpparams_test.f1, 1)} />}
            {m.cross_dataset_generalisation && <Metric label="Cross-dataset F1" value={pct(m.cross_dataset_generalisation.f1, 1)} />}
          </dl>
          <Limitations items={m.limitations} />
        </div>
      )}
    </Panel>
  )
}

function EndpointCard({ m, loaded }: { m: Json | null; loaded?: boolean }) {
  const task = (key: string) => { const t = m?.tasks?.[key]; return t ? (t.comparison as Json[]).find(c => c.selected) ?? t.comparison?.[0] : null }
  const legacy = task('legacy'), sensitive = task('sensitive')
  return (
    <Panel title="Endpoint intelligence" aside={<Loaded on={loaded} />}>
      {!m ? <p className="muted">No metrics file found.</p> : (
        <div className="stack">
          <p className="muted small">Trained on {m.dataset?.operations?.toLocaleString()} operations from {m.dataset?.providers} public API providers; evaluated on providers held out entirely.</p>
          <dl className="kv small">
            {legacy && <Metric label="Legacy ROC-AUC" value={legacy.roc_auc?.toFixed(2)} />}
            {sensitive && <Metric label="Sensitive-data ROC-AUC" value={sensitive.roc_auc?.toFixed(2)} />}
            {m.dataset?.deprecated_rate != null && <Metric label="Deprecated base rate" value={pct(m.dataset.deprecated_rate, 1)} />}
          </dl>
          <Limitations items={m.limitations} />
        </div>
      )}
    </Panel>
  )
}

function AnomalyCard({ m }: { m: Json | null }) {
  return (
    <Panel title="Traffic anomaly detector" aside={<Loaded on />}>
      <div className="stack">
        <p className="muted small">{m?.model}. {m?.training}.</p>
        {Array.isArray(m?.features) && <p className="small">Features: {(m!.features as string[]).join(', ')}.</p>}
      </div>
    </Panel>
  )
}

const Limitations = ({ items }: { items?: string[] }) => items?.length ? (
  <details className="small"><summary className="muted" style={{ cursor: 'pointer' }}>Limitations</summary>
    <ul style={{ margin: '6px 0 0', paddingLeft: 18 }} className="muted">{items.map((l, i) => <li key={i}>{l}</li>)}</ul>
  </details>
) : null

function GroundTruth() {
  const canRun = useCan('analyst')
  const toast = useToast()
  const runs = useAsync(() => api.validationRuns(), [])
  const [text, setText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const shown = runs.data?.find(r => r.id === selected) ?? runs.data?.[0]

  const submit = async (e: FormEvent) => {
    e.preventDefault(); setError(null)
    let truth: unknown
    try { truth = JSON.parse(text) } catch { setError('That is not valid JSON. Check for missing commas or quotes.'); return }
    setBusy(true)
    try {
      const run = await api.runValidation(truth)
      toast(`Validated ${run.metrics.endpoints} endpoints: accuracy ${pct(run.metrics.accuracy, 1)}`)
      setSelected(run.id); void runs.reload(true)
    } catch (exc) { setError(exc instanceof Error ? exc.message : String(exc)) } finally { setBusy(false) }
  }

  return (
    <div className="stack">
      <h2>Lifecycle validation</h2>
      <div className="grid side">
        <div className="stack">
          {runs.error ? <ErrorNotice error={runs.error} /> : !runs.data ? <Loading /> : !shown
            ? <section className="panel"><Empty title="No validation runs yet">Label a set of endpoints by hand, independently of ZombieShield's output, then compare.</Empty></section>
            : <RunResult run={shown} />}
        </div>
        <div className="stack">
          {canRun && (
            <form className="panel" onSubmit={submit}><div className="panel-body stack">
              <h3>Run a validation</h3>
              <p className="muted small">Ground truth JSON with <code>service</code>, <code>method</code>, <code>path</code> and <code>expected</code> lifecycle per endpoint. The Sock Shop template is in <code>sockshop/ground_truth.template.json</code>.</p>
              <input type="file" accept=".json" aria-label="Choose a ground-truth file" onChange={e => e.target.files?.[0]?.text().then(setText)} />
              <textarea rows={8} value={text} onChange={e => setText(e.target.value)} placeholder={TEMPLATE} aria-label="Ground truth JSON" />
              {error && <div className="notice error">{error}</div>}
              <div className="row"><button className="btn primary" disabled={busy || !text.trim()}>{busy ? 'Comparing…' : 'Compare with inventory'}</button>
                <button type="button" className="btn ghost" onClick={() => setText(TEMPLATE)}>Insert example</button></div>
            </div></form>
          )}
          {runs.data && runs.data.length > 1 && (
            <Panel title="Earlier runs" flush>
              <table><tbody>{runs.data.map(r => (
                <tr key={r.id} className="clickable" onClick={() => setSelected(r.id)} style={r.id === shown?.id ? { background: 'var(--raised)' } : undefined}>
                  <td className="small">{r.ground_truth}<div className="cell-sub">{when(r.at)}</div></td>
                  <td className="right num small">{pct(r.metrics.accuracy, 1)}</td>
                </tr>
              ))}</tbody></table>
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}

const prf = (p?: Prf) => p ? `P ${pct(p.precision)} · R ${pct(p.recall)} · F1 ${pct(p.f1)}` : '–'

function RunResult({ run }: { run: ValidationRun }) {
  const m = run.metrics
  const cm = m.confusion_matrix
  return (
    <>
      <section className="panel"><div className="panel-body stack">
        <div className="row"><h3 className="grow">{run.ground_truth}</h3><span className="faint small">{when(run.at)}</span></div>
        <div className="stats">
          <div className="stat"><span className="n">{pct(m.accuracy, 1)}</span><span className="l">accuracy over {m.endpoints} endpoints</span></div>
          <div className="stat"><span className="n">{pct(m.macro_f1, 1)}</span><span className="l">macro F1</span></div>
          <div className="stat"><span className="n">{pct(m.unmanaged_zombie_or_shadow.f1, 1)}</span><span className="l">zombie-or-shadow F1</span></div>
          <div className={`stat${m.not_found ? ' alert' : ''}`}><span className="n">{m.not_found}</span><span className="l">not in inventory</span></div>
        </div>
        <p className="small muted">Zombie or shadow: {prf(m.unmanaged_zombie_or_shadow)}. Zombie only: {prf(m.zombie)}.</p>
      </div></section>
      <section className="panel"><div className="panel-body stack">
        <h3>Confusion matrix</h3>
        <div className="table-wrap">
          <table className="matrix">
            <thead><tr><th>Actual \ predicted</th>{cm.columns_predicted.map(c => <th key={c}>{c === 'NOT_FOUND' ? 'Not found' : <StateTag state={c as Lifecycle} />}</th>)}</tr></thead>
            <tbody>{cm.rows_actual.map((r, i) => (
              <tr key={r}><th style={{ position: 'static' }}><StateTag state={r as Lifecycle} /></th>
                {cm.values[i].map((v, j) => <td key={j} className={i === j ? 'diag' : ''} style={!v ? { color: 'var(--faint)' } : i !== j ? { color: 'var(--bad)' } : undefined}>{v}</td>)}
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div></section>
      <section className="panel flush"><div className="panel-body table-wrap">
        <table>
          <thead><tr><th>Endpoint</th><th>Expected</th><th>ZombieShield</th></tr></thead>
          <tbody>{run.details.rows.map((row, i) => (
            <tr key={i}>
              <td><span className="method">{row.method}</span> <span className="path small">{row.path}</span><div className="cell-sub">{row.service}{row.note ? ` · ${row.note}` : ''}</div></td>
              <td><StateTag state={row.expected as Lifecycle} /></td>
              <td>{row.predicted === 'NOT_FOUND' ? <span className="status FAILED">not found</span> : <StateTag state={row.predicted as Lifecycle} />}
                {!row.correct && <span className="chip bad" style={{ marginLeft: 6 }}>mismatch</span>}
                {row.reason && <div className="cell-sub" style={{ maxWidth: '60ch' }}>{row.reason}</div>}</td>
            </tr>
          ))}</tbody>
        </table>
      </div></section>
    </>
  )
}
