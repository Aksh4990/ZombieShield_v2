"""Recommendation-only decision engine (MONITOR / REMEDIATE / ESCALATE).

Uses the risk score when a risk stage has produced one; otherwise it decides from lifecycle
and threat-intelligence evidence alone. Nothing is ever blocked or changed automatically.
"""

from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import API, Decision, LifecycleState


def decide(api: API) -> tuple[str, str]:
    reasons: list[str] = []
    action = "MONITOR"

    def raise_to(level: str, reason: str) -> None:
        nonlocal action
        order = {"MONITOR": 0, "REMEDIATE": 1, "ESCALATE": 2}
        if order[level] > order[action]:
            action = level
        reasons.append(reason)

    if api.risk_score is not None:
        if api.risk_score >= 75:
            raise_to("ESCALATE", f"risk score {api.risk_score:.0f}/100 is critical")
        elif api.risk_score >= 50:
            raise_to("REMEDIATE", f"risk score {api.risk_score:.0f}/100 is elevated")
    if api.kev_count:
        raise_to("ESCALATE", f"{api.kev_count} dependency vulnerability(ies) are on the CISA Known Exploited list")
    if api.lifecycle_state == LifecycleState.ZOMBIE:
        raise_to("REMEDIATE", "retired endpoint still receiving traffic: confirm owner and clients, then retire it at the gateway")
    elif api.lifecycle_state == LifecycleState.SHADOW:
        raise_to("REMEDIATE", "undocumented endpoint in use: register an owner and document it, or remove it")
    elif api.lifecycle_state == LifecycleState.DEPRECATED and api.in_runtime and api.request_count:
        raise_to("REMEDIATE", "deprecated endpoint still in use: migrate clients and set a sunset date")
    if api.vulnerability_count and not api.kev_count:
        raise_to("REMEDIATE", f"{api.vulnerability_count} known vulnerability(ies) in the service's dependencies")
    if api.in_current_code and not api.in_current_spec and api.in_runtime:
        raise_to("REMEDIATE", "implemented and in use but missing from the published specification")
    if not reasons:
        reasons.append("no elevated evidence; keep monitoring")
    text = "; ".join(reasons)
    return action, text[0].upper() + text[1:] + ". Recommendation only; no automatic action was taken."


def run(db: Session) -> dict:
    db.execute(delete(Decision))
    counts = {"MONITOR": 0, "REMEDIATE": 0, "ESCALATE": 0}
    now = datetime.now(timezone.utc)
    for api in db.scalars(select(API)):
        action, reason = decide(api)
        db.add(Decision(api_id=api.id, action=action, status="RECOMMENDED", reason=reason, decided_at=now))
        counts[action] += 1
    return counts
