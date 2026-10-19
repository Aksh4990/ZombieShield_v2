import { useState } from 'react'
import { api } from './api'
import type { RemediationAction } from './types'
import { ago, Confirm, Endpoint, humanize, RiskPill, StateTag, Status, useCan, useToast } from './ui'

type Step = 'approve' | 'reject' | 'apply' | 'verify' | 'rollback' | 'reopen'
const STEP_TEXT: Record<Step, { label: string; done: string; title: string; body: string; danger?: boolean; role: 'analyst' | 'admin' }> = {
  approve: { label: 'Approve', done: 'Approved', role: 'admin', title: 'Approve this gateway change?', body: 'Approval records your decision. Nothing reaches the gateway until the change is applied.' },
  reject: { label: 'Reject', done: 'Rejected', role: 'analyst', danger: true, title: 'Reject this proposal?', body: 'The proposal is kept for the record. Re-running the pipeline will not propose it again until it is reopened.' },
  apply: { label: 'Apply to gateway', done: 'Applied', role: 'admin', title: 'Apply this rule to the gateway?', body: 'ZombieShield rewrites the gateway rule files. The Sock Shop gateway reloads within a few seconds after checking the configuration with nginx -t.' },
  verify: { label: 'Verify', done: 'Verified', role: 'analyst', title: 'Verify against traffic?', body: 'Checks the requests logged since the rule was applied. If there is no traffic yet, the rule stays applied and you can verify later.' },
  rollback: { label: 'Roll back', done: 'Rolled back', role: 'admin', danger: true, title: 'Roll back this rule?', body: 'The rule is removed from the gateway files and the gateway reloads without it.' },
  reopen: { label: 'Reopen', done: 'Reopened', role: 'analyst', title: 'Reopen as a proposal?', body: 'The action goes back to proposed so it can be approved again.' },
}
const NEXT: Record<string, Step[]> = {
  PROPOSED: ['approve', 'reject'],
  APPROVED: ['apply', 'reject'],
  APPLIED: ['verify', 'rollback'],
  VERIFIED: ['rollback'],
  REJECTED: ['reopen'],
  ROLLED_BACK: ['reopen'],
}
export const KIND_TEXT: Record<string, string> = {
  BLOCK_ROUTE: 'Block route (410 Gone)',
  REQUIRE_AUTH: 'Require credentials (401)',
  RATE_LIMIT: 'Rate limit (429)',
  DEPRECATION_HEADERS: 'Deprecation headers',
}

export function ActionCard({ action, onChanged, showApi = true }: { action: RemediationAction; onChanged: (a: RemediationAction) => void; showApi?: boolean }) {
  const toast = useToast()
  const isAdmin = useCan('admin')
  const isAnalyst = useCan('analyst')
  const [pending, setPending] = useState<Step | null>(null)
  const [busy, setBusy] = useState(false)
  const [showRule, setShowRule] = useState(false)

  const run = async (step: Step, note: string) => {
    setPending(null); setBusy(true)
    try {
      const result = await api.remediationStep(action.id, step, note || undefined)
      onChanged(result)
      if (step === 'verify' && result.verification && !result.verification.passed) toast(`Not verified yet: ${result.verification.note}`, 'error')
      else toast(`${STEP_TEXT[step].done}: ${action.title}`)
    } catch (exc) {
      toast(exc instanceof Error ? exc.message : String(exc), 'error')
    } finally { setBusy(false) }
  }

  const steps = (NEXT[action.status] ?? []).filter(s => (STEP_TEXT[s].role === 'admin' ? isAdmin : isAnalyst))
  const hidden = (NEXT[action.status] ?? []).length - steps.length
  const stepInfo = pending ? STEP_TEXT[pending] : null

  return (
    <article className="panel">
      <div className="panel-body stack">
        <div className="row top wrap">
          <div className="grow stack tight">
            <div className="row wrap" style={{ gap: 8 }}>
              <span className={`chip c-${action.priority}`} style={{ color: 'var(--c)', borderColor: 'var(--c)' }}>{action.priority.toLowerCase()} priority</span>
              <span className="chip">{KIND_TEXT[action.kind] ?? humanize(action.kind)}</span>
              <Status s={action.status} />
            </div>
            <h3 style={{ fontSize: 15 }}>{action.title}</h3>
          </div>
          {showApi && action.api && (
            <a href={`#/apis/${action.api_id}`} className="stack tight" style={{ color: 'inherit', alignItems: 'flex-end' }}>
              <span className="row"><StateTag state={action.api.lifecycle_state} /><RiskPill score={action.api.risk_score} level={riskLevel(action.api.risk_score)} /></span>
              <span className="faint small">{action.api.service} · {action.api.host}</span>
            </a>
          )}
        </div>
        {showApi && action.api && <Endpoint method={action.api.method} path={action.api.path} />}
        <p className="muted" style={{ maxWidth: '90ch' }}>{action.rationale}</p>
        <dl className="kv small">
          <dt>Proposed</dt><dd>{ago(action.proposed_at)}</dd>
          {action.approved_by && <><dt>Approved</dt><dd>by {action.approved_by}, {ago(action.approved_at)}</dd></>}
          {action.applied_at && <><dt>Applied</dt><dd>{ago(action.applied_at)}</dd></>}
          {action.verified_at && <><dt>Verified</dt><dd>{ago(action.verified_at)}</dd></>}
          {action.verification_note && <><dt>Note</dt><dd>{action.verification_note}</dd></>}
        </dl>
        <div className="row wrap">
          {steps.map(step => (
            <button key={step} className={`btn small ${step === 'apply' || step === 'approve' ? 'primary' : STEP_TEXT[step].danger ? 'danger' : ''}`}
              disabled={busy} onClick={() => setPending(step)}>{STEP_TEXT[step].label}</button>
          ))}
          <button className="btn small ghost" onClick={() => setShowRule(v => !v)} aria-expanded={showRule}>{showRule ? 'Hide nginx rule' : 'Show nginx rule'}</button>
          {hidden > 0 && <span className="faint small">Next step needs the admin role.</span>}
        </div>
        {showRule && <pre className="code">{action.config_snippet}</pre>}
      </div>
      {stepInfo && (
        <Confirm open title={stepInfo.title} body={<>{stepInfo.body}<div style={{ marginTop: 8 }}><strong>{action.title}</strong></div></>}
          confirmLabel={stepInfo.label} danger={stepInfo.danger} withNote={pending !== 'verify'}
          onConfirm={note => run(pending!, note)} onClose={() => setPending(null)} />
      )}
    </article>
  )
}

function riskLevel(score: number | null): string | null {
  if (score == null) return null
  return score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW'
}
