import { useEffect, useState } from 'react'
import { api } from '../api'
import type { PipelineRun, Stage } from '../types'
import { ago, duration, Empty, ErrorNotice, Loading, PageHead, Panel, Status, useAsync, useCan, useInterval, useToast, when } from '../ui'

const STAGE_HELP: Record<string, string> = {
  discovery: 'Reads specs, source code, git history and gateway logs into the inventory',
  endpoint_ml: 'Scores each endpoint for legacy and sensitive-data likelihood',
  lifecycle: 'Classifies active, deprecated, shadow, zombie and decommissioned',
  threat_intel: 'Matches dependencies against OSV, CISA KEV and EPSS',
  anomaly: 'Finds unusual client behaviour in traffic windows',
  controls: 'Checks authentication, authorization, validation and rate limiting evidence',
  risk: 'Scores each endpoint 0–100 with the evidence behind every point',
  decisions: 'Recommends monitor, remediate or escalate',
  remediation: 'Proposes gateway rules for a person to approve',
}

function summarise(stage: Stage): string {
  if (stage.error) return stage.error
  const r = stage.result
  if (!r || !Object.keys(r).length) return ''
  const pick = (obj: Record<string, unknown>) => Object.entries(obj)
    .filter(([k, v]) => k !== 'results' && v !== null && (typeof v !== 'object' || (v && Object.keys(v as object).length <= 6)))
    .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${typeof v === 'object' ? Object.entries(v as object).map(([a, b]) => `${a} ${b}`).join(', ') : v}`)
  return pick(r).join(' · ')
}

export default function Pipeline() {
  const canRun = useCan('analyst')
  const toast = useToast()
  const runs = useAsync(() => api.runs(), [])
  const ext = useAsync(() => api.extensions(), [])
  const [selected, setSelected] = useState<string | null>(null)
  const [current, setCurrent] = useState<PipelineRun | null>(null)
  const [fromStart, setFromStart] = useState(false)
  const [busy, setBusy] = useState(false)

  const shownId = selected ?? runs.data?.[0]?.id ?? null
  useEffect(() => {
    if (!shownId) { setCurrent(null); return }
    api.run(shownId).then(setCurrent).catch(() => {})
  }, [shownId])
  const live = current && ['QUEUED', 'RUNNING'].includes(current.status)
  useInterval(() => {
    if (!current) return
    api.run(current.id).then(run => {
      setCurrent(run)
      if (!['QUEUED', 'RUNNING'].includes(run.status)) { void runs.reload(true); toast(run.status === 'SUCCEEDED' ? 'Pipeline run finished' : 'Pipeline run failed', run.status === 'SUCCEEDED' ? 'ok' : 'error') }
    }).catch(() => {})
  }, live ? 1500 : null)

  const start = async () => {
    setBusy(true)
    try {
      const run = await api.startRun(fromStart)
      setSelected(run.id); setCurrent(run); void runs.reload(true)
    } catch (exc) { toast(exc instanceof Error ? exc.message : String(exc), 'error') } finally { setBusy(false) }
  }

  const anyRunning = runs.data?.some(r => ['QUEUED', 'RUNNING'].includes(r.status))

  return (
    <div className="stack loose">
      <PageHead title="Pipeline" lead="One run takes every source through discovery, classification, threat intelligence, risk and remediation. Nothing changes on the gateway without approval.">
        {canRun && (
          <div className="row wrap">
            <label className="check" title="Re-read runtime logs from the beginning instead of continuing where the last run stopped. Requests already ingested would be counted again.">
              <input type="checkbox" checked={fromStart} onChange={e => setFromStart(e.target.checked)} /> Re-read logs from the start
            </label>
            <button className="btn primary" onClick={start} disabled={busy || !!anyRunning}>{anyRunning ? 'Run in progress' : busy ? 'Starting…' : 'Run pipeline'}</button>
          </div>
        )}
      </PageHead>

      <div className="grid side">
        <section className="panel flush">
          <div className="panel-head">
            <h2 className="grow">{current ? <>Run started {ago(current.started_at)}</> : 'Run'}</h2>
            {current && <><Status s={current.status} /><span className="faint small">{duration(current.started_at, current.finished_at)}</span></>}
          </div>
          <div className="panel-body" style={{ padding: '10px 0 0' }}>
            {runs.error ? <div style={{ padding: 16 }}><ErrorNotice error={runs.error} onRetry={() => runs.reload()} /></div>
              : !current ? (runs.loading ? <Loading /> : <Empty title="No runs yet">{canRun ? 'Start the first run to build the inventory.' : 'An analyst can start the first run.'}</Empty>)
              : (
                <>
                  {current.error && <div style={{ padding: '0 16px 10px' }}><ErrorNotice error={current.error.split('\n')[0]} /></div>}
                  <ol className="stages">
                    {current.stages.map(stage => (
                      <li key={stage.key}>
                        <span className={`stage-icon ${stage.status}`} aria-hidden />
                        <div><strong>{stage.name}</strong><div className="faint small">{STAGE_HELP[stage.key]}</div></div>
                        <div className="small"><Status s={stage.status} /><div className="faint">{duration(stage.started_at, stage.finished_at)}</div></div>
                        <div className="stage-result">{summarise(stage)}</div>
                      </li>
                    ))}
                  </ol>
                </>
              )}
          </div>
        </section>

        <div className="stack">
          <Panel title="History" flush>
            {!runs.data?.length ? <p className="muted small" style={{ padding: 16 }}>No runs yet.</p> : (
              <table>
                <tbody>
                  {runs.data.map(r => (
                    <tr key={r.id} className="clickable" onClick={() => setSelected(r.id)} aria-selected={r.id === shownId}
                      style={r.id === shownId ? { background: 'var(--raised)' } : undefined}>
                      <td><Status s={r.status} /><div className="cell-sub">{when(r.started_at)}</div></td>
                      <td className="right small muted">{r.triggered_by}<div className="cell-sub">{duration(r.started_at, r.finished_at)}</div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel title="Stage modules">
            {ext.data ? (
              <ul className="stack tight" style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                {Object.entries(ext.data).map(([key, v]) => (
                  <li key={key} className="row small"><span className="grow">{key.replace(/_/g, ' ')}</span><span className={v.implemented ? 'status SUCCEEDED' : 'status SKIPPED'}>{v.implemented ? 'installed' : 'not installed'}</span></li>
                ))}
              </ul>
            ) : <p className="muted small">Loading…</p>}
          </Panel>
        </div>
      </div>
    </div>
  )
}
