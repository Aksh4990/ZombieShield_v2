import { useState } from 'react'
import { getModelEvaluation } from '../api'
import type { ApiInventoryItem, LifecycleState, ModelEvaluationResponse } from '../types'

interface DashboardProps { health: string; apis: ApiInventoryItem[]; error: string | null }

const lifecycleMeta: Record<LifecycleState, { label: string; tone: string; description: string }> = {
  ACTIVE: { label: 'Active', tone: 'active', description: 'Supported and operating' },
  DEPRECATED: { label: 'Deprecated', tone: 'deprecated', description: 'Scheduled for retirement' },
  ZOMBIE: { label: 'Zombie', tone: 'zombie', description: 'Runtime activity without support evidence' },
  DECOMMISSIONED: { label: 'Decommissioned', tone: 'decommissioned', description: 'Removed from the supported surface' },
}

export function Dashboard({ health, apis, error }: DashboardProps) {
  const [evaluation, setEvaluation] = useState<ModelEvaluationResponse | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [evaluationError, setEvaluationError] = useState<string | null>(null)
  const count = (state: LifecycleState) => apis.filter((api) => api.lifecycle_state === state).length
  const highRisk = apis.filter((api) => api.risk_level === 'HIGH' || api.risk_level === 'CRITICAL').length
  const critical = apis.filter((api) => api.risk_level === 'CRITICAL').length
  const assessed = apis.filter((api) => api.risk_score !== null).length
  const threats = apis.reduce((total, api) => total + api.threat_finding_count, 0)
  const simulations = apis.reduce((total, api) => total + api.simulation_finding_count, 0)
  const attention = apis.filter((api) => api.lifecycle_state === 'ZOMBIE' || api.risk_level === 'HIGH' || api.risk_level === 'CRITICAL').slice(0, 4)
  const coverage = apis.length ? Math.round((assessed / apis.length) * 100) : 0
  const evaluate = async () => { setEvaluating(true); setEvaluationError(null); try { setEvaluation(await getModelEvaluation()) } catch (requestError) { setEvaluationError(requestError instanceof Error ? requestError.message : 'Model evaluation failed') } finally { setEvaluating(false) } }

  return <section className="dashboard">
    <div className="hero-panel"><div><p className="eyebrow">Security operations overview</p><h1>API attack surface, made explainable.</h1><p className="hero-copy">Discover what exists, identify what should not be exposed, and prioritise action using evidence you can inspect.</p></div><div className={`system-pulse ${health === 'healthy' ? 'online' : ''}`}><span></span><div><strong>{health === 'healthy' ? 'Platform healthy' : 'Checking platform'}</strong><small>Backend service status</small></div></div></div>
    {error && <p className="error" role="alert">Unable to reach the backend: {error}</p>}
    <div className="kpi-grid">
      <article className="kpi-card kpi-primary"><span className="kpi-icon">◎</span><div><small>Total APIs</small><strong>{apis.length}</strong><p>Unified inventory records</p></div></article>
      <article className="kpi-card kpi-zombie"><span className="kpi-icon">◌</span><div><small>Zombie APIs</small><strong>{count('ZOMBIE')}</strong><p>Runtime-only exposure signals</p></div></article>
      <article className="kpi-card kpi-risk"><span className="kpi-icon">!</span><div><small>High / critical risk</small><strong>{highRisk}</strong><p>{critical} critical item{critical === 1 ? '' : 's'} require attention</p></div></article>
      <article className="kpi-card"><span className="kpi-icon">✓</span><div><small>Risk coverage</small><strong>{coverage}%</strong><p>{assessed} of {apis.length} APIs assessed</p></div></article>
    </div>
    <div className="dashboard-columns"><section className="panel"><div className="panel-heading"><div><p className="eyebrow">Lifecycle intelligence</p><h2>Inventory distribution</h2></div><span className="panel-tag">{apis.length} tracked</span></div><div className="lifecycle-grid">{(Object.keys(lifecycleMeta) as LifecycleState[]).map((state) => { const meta = lifecycleMeta[state]; const value = count(state); const percentage = apis.length ? Math.round((value / apis.length) * 100) : 0; return <article className="lifecycle-card" key={state}><div><span className={`dot ${meta.tone}`}></span><strong>{meta.label}</strong><small>{meta.description}</small></div><b>{value}</b><div className="progress"><i className={meta.tone} style={{ width: `${percentage}%` }}></i></div><em>{percentage}% of inventory</em></article> })}</div></section><section className="panel posture-panel"><p className="eyebrow">Evidence posture</p><h2>Security signal summary</h2><div className="signal-row"><span>Threat intelligence findings</span><strong>{threats}</strong></div><div className="signal-row"><span>Observed simulation risks</span><strong>{simulations}</strong></div><div className="signal-row"><span>High-risk inventory</span><strong>{highRisk}</strong></div><p className="muted">Signals are derived from persisted inventory evidence. Unknown controls are not treated as missing controls.</p></section></div>
    <section className="panel model-panel">
      <div className="panel-heading">
        <div><p className="eyebrow">Controlled ML comparison</p><h2>Logistic Regression vs Random Forest vs Gradient Boosting</h2></div>
        <button className="secondary-button" onClick={evaluate} disabled={evaluating}>{evaluating ? 'Evaluating models...' : 'Run model comparison'}</button>
      </div>
      <p className="muted">Uses the same held-out synthetic risk scenarios for both models. This compares controlled model behavior, not real-world security accuracy.</p>
      {evaluationError && <p className="error">{evaluationError}</p>}
      {evaluation && <>
        <div className="model-meta"><span>{evaluation.total_scenarios} synthetic scenarios</span><span>{evaluation.train_scenarios} train / {evaluation.test_scenarios} test</span><span>Seed {evaluation.random_state}</span></div>
        <div className="model-grid">{evaluation.metrics.map((model) => <article className={`model-card ${model.selected_for_live_scoring ? 'live-model' : ''}`} key={model.name}><div><strong>{model.name}</strong>{model.selected_for_live_scoring && <span className="panel-tag">Live scorer</span>}</div><div className="model-score"><span>Macro F1</span><b>{(model.f1_macro * 100).toFixed(1)}%</b></div><div className="metric-bars"><label>Accuracy <i><em style={{ width: `${model.accuracy * 100}%` }}></em></i><b>{(model.accuracy * 100).toFixed(1)}%</b></label><label>Precision <i><em style={{ width: `${model.precision_macro * 100}%` }}></em></i><b>{(model.precision_macro * 100).toFixed(1)}%</b></label><label>Recall <i><em style={{ width: `${model.recall_macro * 100}%` }}></em></i><b>{(model.recall_macro * 100).toFixed(1)}%</b></label></div><small>Training time: {model.training_time_ms.toFixed(1)} ms</small></article>)}</div>
        <details className="dataset-samples">
          <summary>View representative synthetic training scenarios</summary>
          <p>One generated example from each label is shown below. These are feature combinations created for the demonstration, not observations of real APIs.</p>
          <div className="sample-grid">{evaluation.sample_scenarios.map((sample) => <article className="sample-card" key={sample.risk_label}><span className={`state risk-${sample.risk_label.toLowerCase()}`}>{sample.risk_label}</span><dl><div><dt>Registered</dt><dd>{sample.features.registration_confirmed ? 'Yes' : 'No'}</dd></div><div><dt>Documented</dt><dd>{sample.features.documentation_confirmed ? 'Yes' : 'No'}</dd></div><div><dt>Zombie state</dt><dd>{sample.features.zombie_lifecycle ? 'Yes' : 'No'}</dd></div><div><dt>Threat findings</dt><dd>{sample.features.known_threat_finding_count}</dd></div><div><dt>Simulation findings</dt><dd>{sample.features.simulation_finding_count}</dd></div></dl></article>)}</div>
        </details>
        <p className="model-notice">{evaluation.dataset_notice}</p>
      </>}
    </section>
    <section className="panel attention-panel"><div className="panel-heading"><div><p className="eyebrow">Prioritised review</p><h2>Requires attention</h2></div><span className="panel-tag">{attention.length} shown</span></div>{attention.length === 0 ? <p className="empty">No high-risk or zombie APIs currently require review.</p> : <div className="attention-list">{attention.map((api) => <article key={api.id}><div><span className={`method method-${api.http_method.toLowerCase()}`}>{api.http_method}</span><code>{api.endpoint_path}</code></div><span>{api.service_name}</span><span className={`state ${api.lifecycle_state.toLowerCase()}`}>{api.lifecycle_state}</span><span className={`risk-text risk-${api.risk_level?.toLowerCase()}`}>{api.risk_level ?? 'NOT ASSESSED'} {api.risk_score?.toFixed(0) ?? ''}</span></article>)}</div>}</section>
  </section>
}
