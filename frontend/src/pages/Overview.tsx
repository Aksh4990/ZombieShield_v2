import { useState } from 'react'
import { api } from '../api'
import type { Lifecycle, Summary } from '../types'
import {
  ago, Empty, Endpoint, go, LIFECYCLES, LifecycleStrip, Loading, n, PageHead, Panel, RISK_LEVELS, RiskPill, StateTag, Status,
  useCan, useToast,
} from '../ui'

export default function Overview({ summary, reloadSummary }: { summary: Summary | null; reloadSummary: () => void }) {
  const canRun = useCan('analyst')
  const toast = useToast()
  const [starting, setStarting] = useState(false)

  const startRun = async () => {
    setStarting(true)
    try {
      await api.startRun(false)
      toast('Pipeline run started')
      go('pipeline')
    } catch (exc) {
      toast(exc instanceof Error ? exc.message : String(exc), 'error')
      reloadSummary()
    } finally { setStarting(false) }
  }

  if (!summary) return <><PageHead title="Overview" /><Loading /></>

  const unmanaged = (summary.lifecycle.ZOMBIE ?? 0) + (summary.lifecycle.SHADOW ?? 0)
  const lead = summary.total_apis === 0
    ? 'Nothing discovered yet. Run the pipeline to scan your sources.'
    : unmanaged > 0
      ? `${n(unmanaged)} of ${n(summary.total_apis)} endpoints are outside your managed API surface: zombie or shadow.`
      : `All ${n(summary.total_apis)} endpoints are documented or deliberately retired.`
  const riskTotal = RISK_LEVELS.reduce((acc, l) => acc + (summary.risk_levels?.[l] ?? 0), 0)
  const running = summary.last_run && ['QUEUED', 'RUNNING'].includes(summary.last_run.status)

  return (
    <div className="stack loose">
      <PageHead title="API surface" lead={lead}>
        {canRun && (
          <button className="btn primary" onClick={startRun} disabled={starting || !!running}>
            {running ? 'Pipeline running…' : starting ? 'Starting…' : 'Run pipeline'}
          </button>
        )}
      </PageHead>

      {summary.total_apis === 0 ? (
        <Panel>
          <Empty title="No APIs in the inventory yet"
            action={<div className="row" style={{ justifyContent: 'center' }}>
              <a className="btn" href="#/sources">Check sources</a>
              {canRun && <button className="btn primary" onClick={startRun} disabled={starting}>Run pipeline</button>}
            </div>}>
            ZombieShield builds the inventory from your API specs, source code and git history, and gateway logs.
          </Empty>
        </Panel>
      ) : (
        <section aria-label="Inventory by lifecycle">
          <LifecycleStrip counts={summary.lifecycle} total={summary.total_apis} />
        </section>
      )}

      <div className="grid side">
        <Panel title="Needs attention" aside={<a href="#/inventory" className="small">Full inventory</a>} flush>
          {summary.attention.length === 0 ? (
            <Empty title="Nothing needs attention">No zombie, shadow, high-risk or known-exploited endpoints right now.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Endpoint</th><th>Lifecycle</th><th className="right">Risk</th><th className="right">Requests</th></tr></thead>
                <tbody>
                  {summary.attention.map(a => (
                    <tr key={a.id} className="clickable" onClick={() => go(`apis/${a.id}`)}>
                      <td>
                        <Endpoint method={a.method} path={a.path} sub={<>{a.service}{a.kev ? <span className="chip bad" style={{ marginLeft: 6 }}>known exploited</span> : null}</>} />
                        {a.reason && <div className="cell-sub" style={{ maxWidth: '70ch' }}>{a.reason}</div>}
                      </td>
                      <td><StateTag state={a.state} /></td>
                      <td className="right"><a href={`#/apis/${a.id}`} onClick={e => e.stopPropagation()}><RiskPill score={a.risk_score} level={a.risk_level} /></a></td>
                      <td className="right num">{n(a.requests)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <div className="stack">
          <Panel title="Risk">
            {riskTotal === 0 ? <p className="muted small">Not scored yet. Risk is assessed in the pipeline's risk stage.</p> : (
              <div className="stack tight">
                {RISK_LEVELS.map(level => {
                  const count = summary.risk_levels?.[level] ?? 0
                  return (
                    <a key={level} href={`#/inventory?risk=${level}`} className={`c-${level}`} style={{ color: 'inherit' }}>
                      <div className="row small"><span className="grow" style={{ color: 'var(--c)', fontWeight: 600 }}>{level[0] + level.slice(1).toLowerCase()}</span><span className="num">{count}</span></div>
                      <div className="risk-bar" style={{ width: '100%', height: 6 }}><span style={{ width: `${(count / riskTotal) * 100}%` }} /></div>
                    </a>
                  )
                })}
              </div>
            )}
          </Panel>

          <Panel title="Remediation" aside={<a href="#/remediation" className="small">Review</a>}>
            {Object.keys(summary.remediation ?? {}).length === 0
              ? <p className="muted small">No gateway changes proposed.</p>
              : <div className="stats">{Object.entries(summary.remediation).map(([status, count]) => (
                  <div key={status} className="stat"><span className="n">{count}</span><span className="l"><Status s={status} /></span></div>
                ))}</div>}
          </Panel>

          <Panel title="Last pipeline run" aside={<a href="#/pipeline" className="small">Details</a>}>
            {summary.last_run ? (
              <div className="row"><Status s={summary.last_run.status} /><span className="muted small">started {ago(summary.last_run.started_at)}</span></div>
            ) : <p className="muted small">The pipeline has not run yet.</p>}
          </Panel>
        </div>
      </div>

      <Panel title="Evidence">
        <div className="stats">
          <Stat n={summary.requests_observed} l="requests observed" />
          <Stat n={summary.undocumented_in_use} l="undocumented but in use" />
          <Stat n={summary.payload_attacks} l="attack payloads seen" alert={summary.payload_attacks > 0} />
          <Stat n={summary.anomalous_windows} l="anomalous traffic windows" />
          <Stat n={summary.vulnerabilities} l="dependency vulnerabilities" />
          <Stat n={summary.kev_vulnerabilities} l="known exploited (CISA KEV)" alert={summary.kev_vulnerabilities > 0} />
        </div>
      </Panel>

      {Object.keys(summary.services).length > 0 && (
        <Panel title="By service" flush>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Service</th><th style={{ width: '45%' }}>Lifecycle mix</th>{LIFECYCLES.map(s => <th key={s} className="right"><StateTag state={s} /></th>)}</tr></thead>
              <tbody>
                {Object.entries(summary.services).map(([service, counts]) => {
                  const total = LIFECYCLES.reduce((a, s) => a + (counts[s] ?? 0), 0)
                  return (
                    <tr key={service} className="clickable" onClick={() => go(`inventory?service=${encodeURIComponent(service)}`)}>
                      <td><strong>{service}</strong><div className="cell-sub">{total} endpoints</div></td>
                      <td>
                        <div className="strip" style={{ height: 10, marginTop: 6 }} aria-hidden>
                          {LIFECYCLES.filter(s => counts[s]).map(s => <div key={s} style={{ flex: counts[s], background: `var(--${s.toLowerCase()})`, padding: 0 }} />)}
                        </div>
                      </td>
                      {LIFECYCLES.map((s: Lifecycle) => <td key={s} className="right num">{counts[s] ? counts[s] : <span className="faint">0</span>}</td>)}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  )
}

const Stat = ({ n: value, l, alert }: { n: number; l: string; alert?: boolean }) => (
  <div className={`stat${alert ? ' alert' : ''}`}><span className="n">{n(value)}</span><span className="l">{l}</span></div>
)
