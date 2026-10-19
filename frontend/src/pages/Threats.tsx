import { useMemo, useState } from 'react'
import { api } from '../api'
import { Empty, ErrorNotice, Loading, PageHead, parseTs, pct, useAsync } from '../ui'

export default function Threats() {
  const [tab, setTab] = useState<'vulns' | 'components'>('vulns')
  const vulns = useAsync(() => api.vulnerabilities(), [])
  const comps = useAsync(() => api.components(), [])
  const [service, setService] = useState('')
  const services = useMemo(() => [...new Set((comps.data ?? []).map(c => c.service_name))].sort(), [comps.data])
  const vulnRows = (vulns.data ?? []).filter(v => !service || v.affected.some(a => a.service === service))
  const compRows = (comps.data ?? []).filter(c => !service || c.service_name === service)
  const kev = (vulns.data ?? []).filter(v => v.in_kev).length

  return (
    <div className="stack loose">
      <PageHead title="Vulnerabilities" lead="Dependencies found in each service's manifests, matched against OSV advisories and enriched with CISA's Known Exploited list and FIRST EPSS exploit probabilities." />
      <div className="row wrap">
        <div className="tabs" role="tablist" style={{ marginBottom: 0, flex: 1 }}>
          <button role="tab" aria-selected={tab === 'vulns'} onClick={() => setTab('vulns')}>Advisories<span className="count">{vulns.data?.length ?? ''}</span></button>
          <button role="tab" aria-selected={tab === 'components'} onClick={() => setTab('components')}>Dependencies<span className="count">{comps.data?.length ?? ''}</span></button>
        </div>
        <select value={service} onChange={e => setService(e.target.value)} aria-label="Filter by service">
          <option value="">All services</option>
          {services.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      {kev > 0 && tab === 'vulns' && <div className="notice error">{kev} advisory{kev > 1 ? 'ies are' : ' is'} on CISA's Known Exploited Vulnerabilities list. Endpoints of the affected services are escalated.</div>}

      {tab === 'vulns' ? (
        <section className="panel flush"><div className="panel-body table-wrap">
          {vulns.error ? <div style={{ padding: 16 }}><ErrorNotice error={vulns.error} onRetry={() => vulns.reload()} /></div>
            : !vulns.data ? <Loading />
            : vulnRows.length === 0 ? <Empty title="No known vulnerabilities">No dependency matched a published advisory. Threat intelligence runs as part of the pipeline.</Empty>
            : (
              <table>
                <thead><tr><th>Advisory</th><th>Affected</th><th>Severity</th><th className="right">CVSS</th><th className="right">EPSS</th><th>Published</th></tr></thead>
                <tbody>
                  {vulnRows.map(v => (
                    <tr key={v.id}>
                      <td style={{ maxWidth: 520 }}>
                        <a className="mono" href={v.url} target="_blank" rel="noreferrer">{v.id}</a>
                        {v.aliases.filter(a => a.startsWith('CVE-')).slice(0, 1).map(a => <span key={a} className="faint mono small" style={{ marginLeft: 8 }}>{a}</span>)}
                        {v.in_kev && <span className="chip bad" style={{ marginLeft: 6 }}>CISA KEV</span>}
                        <div className="cell-sub">{v.summary}</div>
                      </td>
                      <td>{v.affected.map((a, i) => <div key={i} className="small"><span className="mono">{a.component}</span> <span className="faint">{a.version}</span><div className="cell-sub">{a.service}</div></div>)}</td>
                      <td><span className={`status c-${v.severity}`} style={{ color: 'var(--c, var(--muted))' }}>{v.severity.toLowerCase()}</span></td>
                      <td className="right num">{v.cvss_score?.toFixed(1) ?? '–'}</td>
                      <td className="right num" title={v.epss_percentile != null ? `percentile ${pct(v.epss_percentile)}` : undefined}>{v.epss != null ? pct(v.epss, 1) : '–'}</td>
                      <td className="small muted nowrap">{v.published ? parseTs(v.published).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '–'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div></section>
      ) : (
        <section className="panel flush"><div className="panel-body table-wrap">
          {comps.error ? <div style={{ padding: 16 }}><ErrorNotice error={comps.error} /></div>
            : !comps.data ? <Loading />
            : compRows.length === 0 ? <Empty title="No dependencies found">Dependencies are read from requirements.txt, package.json, go.mod, pom.xml and CycloneDX SBOMs in git sources.</Empty>
            : (
              <table>
                <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Service</th><th>Manifest</th></tr></thead>
                <tbody>
                  {compRows.map(c => (
                    <tr key={c.id}>
                      <td className="mono">{c.name}{!c.direct && <span className="faint small"> (transitive)</span>}</td>
                      <td className="mono">{c.version}</td><td>{c.ecosystem}</td><td>{c.service_name}</td><td className="mono small muted">{c.manifest}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div></section>
      )}
    </div>
  )
}
