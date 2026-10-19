import { useState } from 'react'
import { api } from '../api'
import type { Bucket, RequestRow } from '../types'
import { ago, Empty, ErrorNotice, humanize, Loading, Method, n, PageHead, Panel, parseTs, useAsync, useInterval, when } from '../ui'

const SERIES: { key: keyof Bucket; label: string; color: string }[] = [
  { key: 'zombie', label: 'To zombie endpoints', color: 'var(--zombie)' },
  { key: 'shadow', label: 'To shadow endpoints', color: 'var(--shadow)' },
  { key: 'attacks', label: 'Attack payloads', color: 'var(--risk-critical)' },
  { key: 'probes', label: '404 probes', color: 'var(--decommissioned)' },
]

function TrafficChart({ buckets }: { buckets: Bucket[] }) {
  const W = 900, H = 200, pad = { l: 36, r: 8, t: 10, b: 22 }
  const max = Math.max(1, ...buckets.map(b => b.total))
  const bw = (W - pad.l - pad.r) / Math.max(1, buckets.length)
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / max)
  const ticks = [0, Math.round(max / 2), max]
  const labelEvery = Math.max(1, Math.ceil(buckets.length / 8))
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Requests per bucket, peak ${max}`}>
      {ticks.map(t => <g key={t}><line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="var(--line)" /><text x={pad.l - 6} y={y(t) + 3} textAnchor="end">{t}</text></g>)}
      {buckets.map((b, i) => {
        const x = pad.l + i * bw + 1
        const w = Math.max(1, bw - 2)
        let base = b.total
        const parts = SERIES.map(s => ({ ...s, v: Math.min(Number(b[s.key]) || 0, base) }))
        return (
          <g key={b.t}>
            <rect x={x} y={y(b.total)} width={w} height={y(0) - y(b.total)} fill="var(--line-strong)"><title>{`${parseTs(b.t).toLocaleTimeString()}: ${b.total} requests`}</title></rect>
            {parts.map(p => {
              if (!p.v) return null
              const top = base; base -= p.v
              return <rect key={p.key} x={x} y={y(top)} width={w} height={y(base) - y(top)} fill={p.color}><title>{`${p.label}: ${p.v}`}</title></rect>
            })}
            {i % labelEvery === 0 && <text x={x + w / 2} y={H - 6} textAnchor="middle">{parseTs(b.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</text>}
          </g>
        )
      })}
    </svg>
  )
}

export default function Traffic() {
  const [minutes, setMinutes] = useState(60)
  const series = useAsync(() => api.timeseries(minutes, minutes <= 60 ? 60 : minutes <= 360 ? 300 : 900), [minutes])
  const anomalies = useAsync(() => api.anomalies(), [])
  const recent = useAsync(() => api.recentRequests(100), [])
  const [live, setLive] = useState(true)

  useInterval(async () => {
    const rows = recent.data ?? []
    const newest = rows[0]?.id
    try {
      const fresh = await api.recentRequests(100, newest)
      if (fresh.length) recent.setData([...fresh.reverse(), ...rows].slice(0, 200) as RequestRow[])
    } catch { /* keep the current view */ }
  }, live && recent.data ? 3000 : null)
  useInterval(() => { void series.reload(true) }, live ? 30000 : null)

  return (
    <div className="stack loose">
      <PageHead title="Traffic" lead="Requests seen at the gateway after data minimisation: no raw client addresses, query strings or headers are stored." />

      <Panel title="Requests over time" aside={
        <div className="seg" role="group" aria-label="Time range">
          {[[60, '1 hour'], [360, '6 hours'], [1440, '24 hours']].map(([m, l]) => (
            <button key={m} aria-pressed={minutes === m} onClick={() => setMinutes(m as number)}>{l}</button>
          ))}
        </div>}>
        {series.error ? <ErrorNotice error={series.error} /> : !series.data ? <Loading /> : series.data.length === 0
          ? <Empty title="No traffic yet">Requests appear once a runtime log source has been read. Gateway logs are followed every few seconds.</Empty>
          : <div className="stack"><TrafficChart buckets={series.data} />
              <div className="legend"><span style={{ ['--c' as string]: 'var(--line-strong)' }}><i />Other requests</span>{SERIES.map(s => <span key={s.key} style={{ ['--c' as string]: s.color }}><i />{s.label}</span>)}</div>
              <p className="faint small">Times are relative to the most recent logged request.</p>
            </div>}
      </Panel>

      <div className="grid two">
        <Panel title="Anomalous clients" aside={<span className="faint small">IsolationForest on per-client windows</span>} flush>
          {anomalies.error ? <div style={{ padding: 16 }}><ErrorNotice error={anomalies.error} /></div> : !anomalies.data ? <Loading />
            : anomalies.data.length === 0 ? <Empty title="No anomalies">The detector needs at least 10 traffic windows to learn a baseline.</Empty>
            : (
              <div className="table-wrap" style={{ maxHeight: 520 }}>
                <table>
                  <thead><tr><th>Client</th><th>Pattern</th><th className="right">Score</th></tr></thead>
                  <tbody>{anomalies.data.map(a => (
                    <tr key={a.id}>
                      <td><span className="mono small">{a.client_hash.slice(0, 10)}</span><div className="cell-sub">{when(a.window_start)}</div></td>
                      <td><strong className="small">{humanize(a.pattern.toLowerCase())}</strong>
                        {a.reasons.slice(0, 2).map((r, i) => <div key={i} className="cell-sub">{r}</div>)}
                        {a.top_endpoints.length > 0 && <div className="cell-sub mono">{a.top_endpoints.slice(0, 3).join('  ')}</div>}
                      </td>
                      <td className="right num">{a.score.toFixed(2)}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
        </Panel>

        <Panel title="Recent requests" aside={<label className="check small"><input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} /> Live</label>} flush>
          {recent.error ? <div style={{ padding: 16 }}><ErrorNotice error={recent.error} /></div> : !recent.data ? <Loading />
            : recent.data.length === 0 ? <Empty title="No requests logged" />
            : (
              <div className="table-wrap" style={{ maxHeight: 520 }}>
                <table>
                  <thead><tr><th>Request</th><th className="right">Status</th><th>When</th></tr></thead>
                  <tbody>{recent.data.map(r => (
                    <tr key={r.id}>
                      <td>
                        <div className="row" style={{ gap: 8 }}><Method m={r.method} /><span className="path small">{r.path}</span></div>
                        <div className="cell-sub">
                          {r.service_name}{r.authenticated === false ? ' · no credentials' : ''}
                          {r.payload_label && r.payload_label !== 'normal' && <span className="chip bad" style={{ marginLeft: 6 }}>{r.payload_label}</span>}
                          {!r.api_id && <span className="faint"> · not an API (static file or probe)</span>}
                        </div>
                      </td>
                      <td className="right num" style={{ color: r.status >= 500 ? 'var(--bad)' : r.status >= 400 ? 'var(--warn)' : undefined }}>{r.status}</td>
                      <td className="small muted nowrap">{ago(r.ts)}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          {recent.data && recent.data.length > 0 && <div className="faint small" style={{ padding: '8px 16px' }}>{n(recent.data.length)} most recent</div>}
        </Panel>
      </div>
    </div>
  )
}
