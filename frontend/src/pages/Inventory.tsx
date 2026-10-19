import { useMemo, useState } from 'react'
import { api } from '../api'
import type { ApiSummary, Lifecycle, RiskLevel } from '../types'
import {
  ago, Empty, Endpoint, ErrorNotice, go, LIFECYCLE_TEXT, LIFECYCLES, Loading, n, PageHead, queryParam, RISK_LEVELS, RiskPill,
  StateTag, useAsync,
} from '../ui'

const SORTS = { risk: 'Risk', traffic: 'Traffic', last_seen: 'Last seen', path: 'Path', service: 'Service' } as const

export function EvidenceFlags({ api: a }: { api: ApiSummary }) {
  const flag = (on: boolean, label: string, title: string, was = false) =>
    <span className={`chip${on ? ' on' : ''}`} title={title} style={on ? undefined : { opacity: was ? 0.8 : 0.35, textDecoration: was ? 'line-through' : undefined }}>{label}</span>
  return (
    <span className="flags">
      {flag(a.in_current_spec, 'spec', a.in_current_spec ? 'In the current API specification' : a.previously_in_spec ? 'Was in an earlier specification' : 'Not in any specification', a.previously_in_spec)}
      {flag(a.in_current_code, 'code', a.in_current_code ? 'Implemented in current source code' : a.previously_in_code ? 'Removed from source code (git history)' : 'Not found in source code', a.previously_in_code)}
      {flag(a.in_runtime, 'traffic', a.in_runtime ? 'Seen in gateway traffic' : 'Not seen in traffic')}
    </span>
  )
}

export default function Inventory() {
  const [q, setQ] = useState('')
  const [state, setState] = useState<Lifecycle | ''>((queryParam('state') as Lifecycle) ?? '')
  const [risk, setRisk] = useState<RiskLevel | ''>((queryParam('risk') as RiskLevel) ?? '')
  const [service, setService] = useState(queryParam('service') ?? '')
  const [sort, setSort] = useState<keyof typeof SORTS>('risk')
  const { data, error, loading, reload } = useAsync(() => api.apis({ sort }), [sort])

  const services = useMemo(() => [...new Set((data ?? []).map(a => a.service_name))].sort(), [data])
  const counts = useMemo(() => {
    const c: Partial<Record<Lifecycle, number>> = {}
    for (const a of data ?? []) if ((!service || a.service_name === service)) c[a.lifecycle_state] = (c[a.lifecycle_state] ?? 0) + 1
    return c
  }, [data, service])
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (data ?? []).filter(a =>
      (!state || a.lifecycle_state === state) && (!risk || a.risk_level === risk) && (!service || a.service_name === service) &&
      (!needle || `${a.http_method} ${a.display_path} ${a.endpoint_path} ${a.service_name} ${a.owner ?? ''}`.toLowerCase().includes(needle)))
  }, [data, q, state, risk, service])

  return (
    <div className="stack">
      <PageHead title="API inventory" lead="Every endpoint found in specs, source code, git history and runtime traffic, merged into one record each." />
      <section className="panel flush">
        <div className="toolbar">
          <input type="search" placeholder="Search path, service or owner" value={q} onChange={e => setQ(e.target.value)} aria-label="Search endpoints" style={{ width: 260 }} />
          <div className="seg" role="group" aria-label="Filter by lifecycle">
            <button aria-pressed={state === ''} onClick={() => setState('')}>All <span className="faint">{data ? (service ? Object.values(counts).reduce((a, b) => a + (b ?? 0), 0) : data.length) : ''}</span></button>
            {LIFECYCLES.map(s => (
              <button key={s} aria-pressed={state === s} onClick={() => setState(state === s ? '' : s)} style={{ ['--c' as string]: `var(--${s.toLowerCase()})` }}>
                <span className="dot" />{LIFECYCLE_TEXT[s].label} <span className="faint">{counts[s] ?? 0}</span>
              </button>
            ))}
          </div>
          <select value={risk} onChange={e => setRisk(e.target.value as RiskLevel | '')} aria-label="Filter by risk">
            <option value="">Any risk</option>
            {RISK_LEVELS.map(l => <option key={l} value={l}>{l[0] + l.slice(1).toLowerCase()} risk</option>)}
          </select>
          <select value={service} onChange={e => setService(e.target.value)} aria-label="Filter by service">
            <option value="">All services</option>
            {services.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="spacer" />
          <label className="small muted row" style={{ gap: 6 }}>Sort
            <select value={sort} onChange={e => setSort(e.target.value as keyof typeof SORTS)}>
              {Object.entries(SORTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
        </div>
        {error ? <div className="panel-body"><ErrorNotice error={error} onRetry={() => reload()} /></div>
          : loading && !data ? <Loading />
          : rows.length === 0 ? (
            data && data.length === 0
              ? <Empty title="The inventory is empty" action={<a className="btn" href="#/pipeline">Go to pipeline</a>}>Run the pipeline to discover APIs from your sources.</Empty>
              : <Empty title="No endpoints match these filters" action={<button className="btn" onClick={() => { setQ(''); setState(''); setRisk(''); setService('') }}>Clear filters</button>} />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Endpoint</th><th>Lifecycle</th><th>Found in</th><th className="right">Risk</th>
                    <th className="right">Requests</th><th className="right">Clients</th><th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(a => (
                    <tr key={a.id} className="clickable" onClick={() => go(`apis/${a.id}`)}>
                      <td>
                        <Endpoint method={a.http_method} path={a.display_path} sub={<>
                          {a.service_name}{a.owner ? ` · owner ${a.owner}` : ''}
                          {a.kev_count > 0 && <span className="chip bad" style={{ marginLeft: 6 }}>known exploited</span>}
                          {a.attack_request_count > 0 && <span className="chip warn" style={{ marginLeft: 6 }}>{a.attack_request_count} attack payloads</span>}
                        </>} />
                      </td>
                      <td><StateTag state={a.lifecycle_state} /></td>
                      <td><EvidenceFlags api={a} /></td>
                      <td className="right"><a href={`#/apis/${a.id}`} onClick={e => e.stopPropagation()} aria-label={`Open ${a.http_method} ${a.display_path}`}><RiskPill score={a.risk_score} level={a.risk_level} /></a></td>
                      <td className="right num">{n(a.request_count)}</td>
                      <td className="right num">{n(a.unique_clients)}</td>
                      <td className="nowrap muted small">{ago(a.last_runtime_seen ?? a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        {rows.length > 0 && <div className="faint small" style={{ padding: '10px 16px', borderTop: '1px solid var(--line)' }}>Showing {rows.length} of {data?.length ?? 0} endpoints</div>}
      </section>
    </div>
  )
}
