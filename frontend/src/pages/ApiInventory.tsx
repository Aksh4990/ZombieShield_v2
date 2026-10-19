import { useEffect, useMemo, useState } from 'react'
import { getApiRecommendations, runClassification, runRiskAssessments } from '../api'
import type { ApiInventoryItem, RemediationResponse } from '../types'

interface ApiInventoryProps { apis: ApiInventoryItem[]; loading: boolean; error: string | null }

const sourceLabel = (api: ApiInventoryItem, source: string) => api.sources.includes(source) ? 'Evidence present' : 'No evidence'

export function ApiInventory({ apis, loading, error }: ApiInventoryProps) {
  const [selected, setSelected] = useState<ApiInventoryItem | null>(null)
  const [recommendations, setRecommendations] = useState<RemediationResponse | null>(null)
  const [recommendationError, setRecommendationError] = useState<string | null>(null)
  const [recommendationsLoading, setRecommendationsLoading] = useState(false)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('ALL')
  const [running, setRunning] = useState(false)
  const [assessing, setAssessing] = useState(false)

  const visible = useMemo(
    () => apis.filter((api) => (filter === 'ALL' || api.lifecycle_state === filter) && `${api.service_name} ${api.endpoint_path} ${api.http_method}`.toLowerCase().includes(query.toLowerCase())),
    [apis, filter, query],
  )

  useEffect(() => {
    if (!selected) {
      setRecommendations(null)
      setRecommendationError(null)
      return
    }
    let cancelled = false
    setRecommendations(null)
    setRecommendationError(null)
    setRecommendationsLoading(true)
    getApiRecommendations(selected.id)
      .then((response) => { if (!cancelled) setRecommendations(response) })
      .catch((requestError) => { if (!cancelled) setRecommendationError(requestError instanceof Error ? requestError.message : 'Unable to load recommendations') })
      .finally(() => { if (!cancelled) setRecommendationsLoading(false) })
    return () => { cancelled = true }
  }, [selected])

  const classify = async () => { setRunning(true); try { await runClassification(); window.location.reload() } finally { setRunning(false) } }
  const assess = async () => { setAssessing(true); try { await runRiskAssessments(); window.location.reload() } finally { setAssessing(false) } }

  return <section>
    <p className="eyebrow">Evidence-led inventory</p>
    <h1>API Inventory</h1>
    <p className="page-lead">Select any API to explain its evidence, lifecycle state, risk contributors, and recommended next actions.</p>
    <div className="actions">
      <button className="submit" onClick={classify} disabled={running}>{running ? 'Classifying...' : 'Run lifecycle classification'}</button>
      <button className="secondary-button" onClick={assess} disabled={assessing}>{assessing ? 'Assessing...' : 'Run risk assessment'}</button>
    </div>
    <div className="inventory-toolbar"><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search endpoint, service, or method" /><select value={filter} onChange={(e) => setFilter(e.target.value)}><option value="ALL">All lifecycle states</option><option value="ACTIVE">Active</option><option value="ZOMBIE">Zombie</option><option value="DEPRECATED">Deprecated</option><option value="DECOMMISSIONED">Decommissioned</option></select><span>{visible.length} APIs shown</span></div>
    {loading && <p>Loading inventory...</p>}
    {error && <p className="error">Unable to load API inventory: {error}</p>}
    {!loading && !error && <div className="inventory-grid">{visible.length === 0 ? <p className="empty">No matching API inventory records.</p> : visible.map((api) => <button className={`api-card ${api.lifecycle_state === 'ZOMBIE' ? 'zombie-card' : ''}`} key={api.id} onClick={() => setSelected(api)}><div className="api-card-top"><span className={`method method-${api.http_method.toLowerCase()}`}>{api.http_method}</span><span className={`state ${api.lifecycle_state.toLowerCase()}`}>{api.lifecycle_state}</span></div><code>{api.endpoint_path}</code><strong>{api.service_name}</strong><small>{api.host} · {api.version}</small><div className="api-card-footer"><span>{api.sources.length} evidence source{api.sources.length === 1 ? '' : 's'}</span>{api.risk_score === null ? <span>Not assessed</span> : <span className={`risk-text risk-${api.risk_level?.toLowerCase()}`}>{api.risk_level} {api.risk_score.toFixed(0)}/100</span>}</div></button>)}</div>}
    {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}><aside className="detail-drawer" onClick={(e) => e.stopPropagation()}><button className="close-button" onClick={() => setSelected(null)} aria-label="Close details">×</button><p className="eyebrow">API security profile</p><div className="detail-title"><span className={`method method-${selected.http_method.toLowerCase()}`}>{selected.http_method}</span><code>{selected.endpoint_path}</code></div><p className="detail-meta">{selected.service_name} · {selected.host} · {selected.version}</p><div className="detail-score"><span>Final risk score</span><strong className={`risk-${selected.risk_level?.toLowerCase()}`}>{selected.risk_score === null ? '—' : selected.risk_score.toFixed(0)}</strong><span className={`state risk-${selected.risk_level?.toLowerCase()}`}>{selected.risk_level ?? 'NOT ASSESSED'}</span></div><h2>Lifecycle</h2><span className={`state ${selected.lifecycle_state.toLowerCase()}`}>{selected.lifecycle_state}</span><p>{selected.classification_reason ?? 'Lifecycle classification has not run yet.'}</p><h2>Evidence</h2><div className="evidence-list">{[['openapi', 'OpenAPI'], ['git', 'Source code'], ['runtime_log', 'Runtime logs']].map(([key, label]) => <div key={key}><span className={selected.sources.includes(key) ? 'evidence-yes' : 'evidence-no'}>{selected.sources.includes(key) ? '✓' : '×'}</span><strong>{label}</strong><small>{sourceLabel(selected, key)}</small></div>)}</div><h2>Risk contributors</h2><div className="finding-list">{selected.risk_findings.length ? selected.risk_findings.map((finding) => <p key={finding}>{finding}</p>) : <p>No risk assessment findings stored yet.</p>}</div><h2>Operational evidence</h2><p>Threat findings: <strong>{selected.threat_finding_count}</strong> · Simulation findings: <strong>{selected.simulation_finding_count}</strong></p><h2>Recommended actions</h2>{recommendationsLoading && <p className="muted">Preparing evidence-based recommendations...</p>}{recommendationError && <p className="error">{recommendationError}</p>}{recommendations && <div className="recommendation-list">{recommendations.recommendations.map((recommendation) => <article className="recommendation-card" key={recommendation.key}><div className="recommendation-heading"><strong>{recommendation.title}</strong><span className={`state recommendation-${recommendation.priority.toLowerCase()}`}>{recommendation.priority}</span></div><p><b>Action:</b> {recommendation.action}</p><p><b>Why:</b> {recommendation.rationale}</p><ul>{recommendation.evidence.map((evidence) => <li key={evidence}>{evidence}</li>)}</ul><p className="recommendation-validation"><b>Validate:</b> {recommendation.validation}</p>{recommendation.reference_url && <a href={recommendation.reference_url} target="_blank" rel="noreferrer">Open source advisory</a>}</article>)}</div>}<p className="muted recommendation-note">Recommendations are advisory only and are based on stored evidence. No route, dependency, or security control is changed by this view.</p>{recommendations?.limitations.map((limitation) => <p className="muted recommendation-limit" key={limitation}>{limitation}</p>)}</aside></div>}
  </section>
}
