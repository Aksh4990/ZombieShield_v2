import { useMemo, useState } from 'react'
import { api } from '../api'
import { ActionCard, KIND_TEXT } from '../components'
import type { RemediationAction } from '../types'
import { Empty, ErrorNotice, Loading, PageHead, useAsync } from '../ui'

const GROUPS: { key: string; label: string; statuses: string[]; empty: string }[] = [
  { key: 'review', label: 'To review', statuses: ['PROPOSED'], empty: 'No proposals waiting for review.' },
  { key: 'approved', label: 'Approved', statuses: ['APPROVED'], empty: 'Nothing approved and waiting to be applied.' },
  { key: 'live', label: 'On the gateway', statuses: ['APPLIED', 'VERIFIED'], empty: 'No ZombieShield rules are active on the gateway.' },
  { key: 'closed', label: 'Closed', statuses: ['REJECTED', 'ROLLED_BACK'], empty: 'Nothing rejected or rolled back.' },
]

export default function Remediation() {
  const { data, error, loading, reload, setData } = useAsync(() => api.remediation(), [])
  const [group, setGroup] = useState('review')
  const [kind, setKind] = useState('')
  const [showConfig, setShowConfig] = useState(false)
  const config = useAsync(() => showConfig ? api.gatewayConfig() : Promise.resolve(null), [showConfig, data])

  const counts = useMemo(() => Object.fromEntries(GROUPS.map(g => [g.key, (data ?? []).filter(a => g.statuses.includes(a.status)).length])), [data])
  const current = GROUPS.find(g => g.key === group)!
  const rows = (data ?? []).filter(a => current.statuses.includes(a.status) && (!kind || a.kind === kind))
  const onChanged = (next: RemediationAction) => {
    setData(list => (list ?? []).map(a => a.id === next.id ? { ...a, ...next } : a))
    void reload(true)
  }

  return (
    <div className="stack loose">
      <PageHead title="Remediation" lead="Gateway rules proposed from the evidence. An admin approves and applies each one, an analyst verifies it against traffic, and every step is audited.">
        <button className="btn" onClick={() => setShowConfig(v => !v)} aria-expanded={showConfig}>{showConfig ? 'Hide gateway config' : 'Show gateway config'}</button>
      </PageHead>

      {showConfig && (
        <section className="panel"><div className="panel-body stack">
          <h2>What the gateway is running</h2>
          {config.error ? <ErrorNotice error={config.error} /> : !config.data ? <p className="muted">Loading…</p> : config.data.rules === 0
            ? <p className="muted">No rules are applied. The gateway's rule files are empty.</p>
            : Object.entries(config.data.files).map(([file, text]) => (
              <div key={file} className="stack tight"><span className="mono small muted">{file}</span><pre className="code">{text}</pre></div>
            ))}
        </div></section>
      )}

      <div>
        <div className="row wrap" style={{ marginBottom: 14 }}>
          <div className="tabs" role="tablist" style={{ marginBottom: 0, flex: 1 }}>
            {GROUPS.map(g => (
              <button key={g.key} role="tab" aria-selected={group === g.key} onClick={() => setGroup(g.key)}>
                {g.label}<span className="count">{counts[g.key] ?? 0}</span>
              </button>
            ))}
          </div>
          <select value={kind} onChange={e => setKind(e.target.value)} aria-label="Filter by rule type">
            <option value="">All rule types</option>
            {Object.entries(KIND_TEXT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        {error ? <ErrorNotice error={error} onRetry={() => reload()} />
          : loading && !data ? <Loading />
          : rows.length === 0 ? <section className="panel"><Empty title={current.empty}>
              {group === 'review' && (data ?? []).length === 0 ? 'Proposals appear after a pipeline run finds zombie endpoints, missing authentication, unthrottled abuse or deprecated endpoints still in use.' : null}
            </Empty></section>
          : <div className="stack">{rows.map(a => <ActionCard key={a.id} action={a} onChanged={onChanged} />)}</div>}
      </div>
    </div>
  )
}
