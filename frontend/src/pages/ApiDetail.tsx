import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api'
import { ActionCard } from '../components'
import type { ApiDetail, Control, OwaspItem, RemediationAction } from '../types'
import {
  ago, Empty, ErrorNotice, humanize, LIFECYCLE_TEXT, Loading, Method, n, pct, StateTag, Status, useAsync, useCan, useToast, when,
} from '../ui'
import { EvidenceFlags } from './Inventory'

const TABS = ['Summary', 'Risk', 'Controls', 'Evidence', 'Vulnerabilities', 'Gateway rules', 'Ownership'] as const
type Tab = typeof TABS[number]
const CONTROL_ORDER = ['authentication', 'authorization', 'input_validation', 'rate_limiting', 'inventory', 'gateway']
const CONTROL_TEXT: Record<string, string> = {
  authentication: 'Authentication', authorization: 'Object-level authorization', input_validation: 'Input validation',
  rate_limiting: 'Rate limiting', inventory: 'Inventory & documentation', gateway: 'ZombieShield gateway rule',
}

export default function ApiDetailPage({ id }: { id: string }) {
  const { data, error, loading, reload, setData } = useAsync(() => api.apiDetail(id), [id])
  const actions = useAsync(() => api.remediation({ api_id: id }), [id])
  const [tab, setTab] = useState<Tab>('Summary')
  useEffect(() => { if (data) document.title = `${data.http_method} ${data.display_path} · ZombieShield` }, [data])

  if (error) return <ErrorNotice error={error} onRetry={() => reload()} />
  if (loading || !data) return <Loading />
  const a = data
  const counts: Partial<Record<Tab, number>> = {
    Evidence: a.evidence.length, Vulnerabilities: a.vulnerabilities.length, 'Gateway rules': actions.data?.length ?? 0,
    Controls: (a.security_controls.owasp as OwaspItem[] | undefined)?.length,
  }

  return (
    <div className="stack loose">
      <div className="stack tight">
        <a href="#/inventory" className="small">Back to inventory</a>
        <div className="row top wrap" style={{ gap: 20 }}>
          <div className="grow stack tight" style={{ minWidth: 280 }}>
            <div className="row" style={{ gap: 10 }}><Method m={a.http_method} /><h1 className="path" style={{ fontSize: 22, fontWeight: 600 }}>{a.display_path}</h1></div>
            <div className="row wrap muted small">
              <StateTag state={a.lifecycle_state} /><span>{a.service_name}</span><span className="faint">{a.host}</span>
              {a.version !== 'unversioned' && <span className="faint">version {a.version}</span>}
              {a.display_path !== a.endpoint_path && <span className="faint mono">{a.endpoint_path}</span>}
            </div>
          </div>
          <div className={`stack tight c-${a.risk_level ?? 'LOW'}`} style={{ alignItems: 'flex-end' }}>
            <span className="risk-big">{a.risk_score == null ? '–' : Math.round(a.risk_score)}</span>
            <span className="small" style={{ color: 'var(--c)', fontWeight: 600 }}>{a.risk_level ? `${a.risk_level.toLowerCase()} risk` : 'not scored'}</span>
          </div>
        </div>
        {a.decision && (
          <div className={`notice ${a.decision.action === 'MONITOR' ? '' : 'error'}`} style={a.decision.action === 'REMEDIATE' ? { borderColor: 'color-mix(in srgb, var(--warn) 55%, transparent)', color: 'var(--text)' } : undefined}>
            <strong>{humanize(a.decision.action.toLowerCase())}.</strong> {a.decision.reason}
          </div>
        )}
      </div>

      <div>
        <div className="tabs" role="tablist">
          {TABS.map(t => (
            <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>
              {t}{counts[t] ? <span className="count">{counts[t]}</span> : null}
            </button>
          ))}
        </div>
        {tab === 'Summary' && <SummaryTab a={a} />}
        {tab === 'Risk' && <RiskTab a={a} />}
        {tab === 'Controls' && <ControlsTab a={a} />}
        {tab === 'Evidence' && <EvidenceTab a={a} />}
        {tab === 'Vulnerabilities' && <VulnTab a={a} />}
        {tab === 'Gateway rules' && <RulesTab actions={actions.data} error={actions.error} onChanged={(x: RemediationAction) => {
          actions.setData(list => (list ?? []).map(item => item.id === x.id ? { ...item, ...x } : item))
          void reload(true)
        }} />}
        {tab === 'Ownership' && <OwnershipTab a={a} onSaved={next => setData({ ...a, ...next })} />}
      </div>
    </div>
  )
}

function SummaryTab({ a }: { a: ApiDetail }) {
  return (
    <div className="grid two">
      <section className="panel"><div className="panel-body stack">
        <h2>Why it is {LIFECYCLE_TEXT[a.lifecycle_state].label.toLowerCase()}</h2>
        <p>{a.classification_reason ?? 'Not classified yet.'}</p>
        <EvidenceFlags api={a} />
        <dl className="kv">
          <dt>First seen</dt><dd>{when(a.first_seen)}</dd>
          <dt>Last seen in traffic</dt><dd>{a.last_runtime_seen ? `${when(a.last_runtime_seen)} (${ago(a.last_runtime_seen)})` : 'never'}</dd>
          {a.removed_in_commit && <><dt>Removed in commit</dt><dd className="mono">{a.removed_in_commit.slice(0, 12)}{a.removed_at ? `, ${when(a.removed_at)}` : ''}</dd></>}
          {a.removal_note && <><dt>Removal</dt><dd>{a.removal_note}</dd></>}
          {a.spec_deprecated && <><dt>Specification</dt><dd>marked deprecated{a.superseded_by ? <>; successor <span className="mono">{a.superseded_by}</span></> : ''}</dd></>}
          {a.code_location && <><dt>Code</dt><dd className="mono">{a.code_location}</dd></>}
          {a.spec_security.length > 0 && <><dt>Declared security</dt><dd>{a.spec_security.join(', ')}</dd></>}
          <dt>Sources</dt><dd>{a.sources.join(', ') || '–'}</dd>
        </dl>
      </div></section>
      <div className="stack">
        <section className="panel"><div className="panel-body stack">
          <h2>Traffic</h2>
          <div className="stats">
            <div className="stat"><span className="n">{n(a.request_count)}</span><span className="l">requests</span></div>
            <div className="stat"><span className="n">{n(a.unique_clients)}</span><span className="l">clients</span></div>
            <div className="stat"><span className="n">{n(a.error_count)}</span><span className="l">errors</span></div>
            <div className={`stat${a.unauth_success_count ? ' alert' : ''}`}><span className="n">{n(a.unauth_success_count)}</span><span className="l">anonymous successes</span></div>
            <div className={`stat${a.attack_request_count ? ' alert' : ''}`}><span className="n">{n(a.attack_request_count)}</span><span className="l">attack payloads</span></div>
            <div className="stat"><span className="n">{n(a.anomalous_client_count)}</span><span className="l">anomalous clients</span></div>
          </div>
        </div></section>
        <section className="panel"><div className="panel-body stack">
          <h2>Endpoint models</h2>
          {a.ml_explanation.length === 0 ? <p className="muted small">The endpoint model has not scored this API.</p> : a.ml_explanation.map(m => (
            <div key={m.model} className="stack tight">
              <div className="row">
                <strong className="grow">{m.model === 'legacy' ? 'Looks like a legacy endpoint' : 'Handles sensitive data'}</strong>
                <span className={m.flagged ? 'status FAILED' : 'muted small'}>{pct(m.score)} {m.flagged ? '(flagged)' : ''}</span>
              </div>
              <div className="risk-bar" style={{ width: '100%', height: 5 }}><span style={{ width: pct(m.score), background: m.flagged ? 'var(--risk-high)' : 'var(--risk-low)' }} /></div>
              <div className="faint small">Threshold {pct(m.threshold)}{m.signals.length ? ` · signals: ${m.signals.join(', ')}` : ''}</div>
            </div>
          ))}
        </div></section>
      </div>
    </div>
  )
}

function RiskTab({ a }: { a: ApiDetail }) {
  if (!a.risk_breakdown.length) return <Empty title="No risk factors">{a.risk_explanation ?? 'This endpoint has not been scored yet, or no risk factor applies.'}</Empty>
  const max = Math.max(...a.risk_breakdown.map(f => Math.abs(f.points)), 1)
  return (
    <section className="panel"><div className="panel-body stack">
      <p>{a.risk_explanation}</p>
      <div>
        {a.risk_breakdown.map((f, i) => (
          <div key={i} className="factor">
            <strong>{f.factor}</strong>
            <div className="stack tight">
              <div className="factor-bar"><span className={f.points < 0 ? 'neg' : ''} style={{ width: `${(Math.abs(f.points) / max) * 100}%` }} /></div>
              <span className="muted small">{f.evidence}</span>
            </div>
            <span className="factor-pts" style={{ color: f.points < 0 ? 'var(--ok)' : undefined }}>{f.points > 0 ? '+' : ''}{f.points}</span>
          </div>
        ))}
      </div>
      <p className="faint small">The score is the capped sum of these points (0–100). Every factor shows the evidence that earned it. Assessed {ago(a.classified_at)}.</p>
    </div></section>
  )
}

function ControlsTab({ a }: { a: ApiDetail }) {
  const controls = a.security_controls
  const owasp = (controls.owasp as OwaspItem[] | undefined) ?? []
  if (!controls || !Object.keys(controls).length) return <Empty title="Controls not assessed">Run the pipeline to assess security controls.</Empty>
  return (
    <div className="stack">
      <div className="controls">
        {CONTROL_ORDER.filter(k => controls[k]).map(key => {
          const c = controls[key] as Control
          return (
            <div key={key} className={`control ${c.status}`}>
              <div className="row"><strong className="grow">{CONTROL_TEXT[key]}</strong><Status s={c.status} /></div>
              <p className="muted small" style={{ marginTop: 4 }}>{c.summary}</p>
            </div>
          )
        })}
      </div>
      <section className="panel"><div className="panel-body stack">
        <h2>OWASP API Security Top 10 (2023)</h2>
        {owasp.length === 0 ? <p className="muted">No category applies based on the evidence collected.</p> : (
          <ul className="stack" style={{ margin: 0, paddingLeft: 18 }}>
            {owasp.map(o => <li key={o.id}><strong>{o.name}</strong><div className="muted small">{o.reason}</div></li>)}
          </ul>
        )}
      </div></section>
    </div>
  )
}

const EVIDENCE_COLOR = (kind: string) =>
  kind.includes('removed') ? 'var(--zombie)' : kind.includes('runtime') ? 'var(--link)' : kind.includes('deprecat') ? 'var(--deprecated)'
    : kind.includes('added') || kind.includes('spec') || kind.includes('code') ? 'var(--active)' : 'var(--muted)'

function EvidenceTab({ a }: { a: ApiDetail }) {
  const [all, setAll] = useState(false)
  const events = [...a.evidence].reverse()
  if (!events.length) return <Empty title="No evidence recorded" />
  const shown = all ? events : events.slice(0, 40)
  return (
    <section className="panel"><div className="panel-body">
      <ol className="timeline">
        {shown.map(e => (
          <li key={e.id} style={{ ['--k' as string]: EVIDENCE_COLOR(e.kind) }}>
            <div className="row wrap" style={{ gap: 8 }}><strong>{e.summary}</strong></div>
            <div className="faint small">{when(e.observed_at)} · {humanize(e.kind)} · {e.source}</div>
          </li>
        ))}
      </ol>
      {events.length > shown.length && <button className="btn small" onClick={() => setAll(true)}>Show all {events.length} events</button>}
    </div></section>
  )
}

function VulnTab({ a }: { a: ApiDetail }) {
  if (!a.vulnerabilities.length) return <Empty title="No known vulnerabilities">No vulnerable dependency was found for the {a.service_name} service.</Empty>
  return (
    <section className="panel flush"><div className="panel-body table-wrap">
      <table>
        <thead><tr><th>Advisory</th><th>Component</th><th>Severity</th><th className="right">CVSS</th><th className="right">EPSS</th><th>Fixed in</th></tr></thead>
        <tbody>
          {a.vulnerabilities.map(v => (
            <tr key={v.id + v.component}>
              <td><a href={v.url} target="_blank" rel="noreferrer" className="mono">{v.id}</a>{v.in_kev && <span className="chip bad" style={{ marginLeft: 6 }}>CISA KEV</span>}<div className="cell-sub" style={{ maxWidth: '60ch' }}>{v.summary}</div></td>
              <td><span className="mono">{v.component}</span> <span className="faint">{v.version}</span><div className="cell-sub">{v.ecosystem} · {v.manifest}</div></td>
              <td><span className={`status c-${v.severity}`} style={{ color: 'var(--c, var(--muted))' }}>{v.severity.toLowerCase()}</span></td>
              <td className="right num">{v.cvss_score?.toFixed(1) ?? '–'}</td>
              <td className="right num">{v.epss != null ? pct(v.epss, 1) : '–'}</td>
              <td className="mono small">{v.fixed_versions.join(', ') || <span className="faint">no fix published</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div></section>
  )
}

function RulesTab({ actions, error, onChanged }: { actions: RemediationAction[] | null; error: string | null; onChanged: (a: RemediationAction) => void }) {
  if (error) return <ErrorNotice error={error} />
  if (!actions) return <Loading />
  if (!actions.length) return <Empty title="No gateway change proposed">Remediation proposes gateway rules for endpoints whose decision is remediate or escalate.</Empty>
  return <div className="stack">{actions.map(x => <ActionCard key={x.id} action={x} onChanged={onChanged} showApi={false} />)}</div>
}

function OwnershipTab({ a, onSaved }: { a: ApiDetail; onSaved: (next: Partial<ApiDetail>) => void }) {
  const canEdit = useCan('analyst')
  const toast = useToast()
  const [owner, setOwner] = useState(a.owner ?? '')
  const [notes, setNotes] = useState(a.notes ?? '')
  const [registered, setRegistered] = useState(a.is_registered)
  const [deprecated, setDeprecated] = useState(a.manually_deprecated)
  const [removed, setRemoved] = useState(a.manually_removed)
  const [busy, setBusy] = useState(false)
  const save = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true)
    try {
      const changes = { owner: owner || null, notes: notes || null, is_registered: registered, manually_deprecated: deprecated, manually_removed: removed }
      await api.updateApi(a.id, changes)
      onSaved(changes); toast('Ownership saved. Lifecycle updates on the next pipeline run.')
    } catch (exc) { toast(exc instanceof Error ? exc.message : String(exc), 'error') } finally { setBusy(false) }
  }
  return (
    <form className="panel" onSubmit={save}><div className="panel-body stack" style={{ maxWidth: 640 }}>
      <label className="field">Owner (team or person)<input type="text" value={owner} onChange={e => setOwner(e.target.value)} disabled={!canEdit} maxLength={255} /></label>
      <label className="field">Notes<textarea rows={4} value={notes} onChange={e => setNotes(e.target.value)} disabled={!canEdit} style={{ fontFamily: 'var(--sans)', fontSize: 13 }} /></label>
      <label className="check"><input type="checkbox" checked={registered} onChange={e => setRegistered(e.target.checked)} disabled={!canEdit} /> Registered in the API catalogue</label>
      <label className="check"><input type="checkbox" checked={deprecated} onChange={e => setDeprecated(e.target.checked)} disabled={!canEdit} /> Mark as deprecated</label>
      <label className="check"><input type="checkbox" checked={removed} onChange={e => setRemoved(e.target.checked)} disabled={!canEdit} /> Mark as removed (retired)</label>
      {canEdit ? <div><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save ownership'}</button></div>
        : <p className="faint small">Editing needs the analyst role.</p>}
    </div></form>
  )
}

