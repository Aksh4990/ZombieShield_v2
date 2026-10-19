"""Stage 9: remediation proposals and the human approval workflow for gateway rules.

The pipeline stage (`run`) only ever *proposes*. A proposal becomes a gateway rule only after an
administrator approves it and then applies it; applying regenerates the nginx rule files from every
APPLIED/VERIFIED action, and rolling back regenerates them without the rolled-back one.

    PROPOSED --approve--> APPROVED --apply--> APPLIED --verify--> VERIFIED
        |                    |                   |                    |
        +--reject--> REJECTED                    +------rollback------+--> ROLLED_BACK

Re-running the pipeline refreshes the wording of PROPOSED actions, removes PROPOSED actions whose
evidence has gone, and never touches actions a person has already acted on.

Proposals (one per API and kind)
  BLOCK_ROUTE          ZOMBIE endpoints: return 410 Gone
  REQUIRE_AUTH         authentication NOT_ENFORCED (and not already being blocked)
  RATE_LIMIT           unthrottled heavy use, anomalous clients or BOLA enumeration
  DEPRECATION_HEADERS  DEPRECATED endpoints still called: announce Deprecation / Sunset / successor
"""

import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import API, Decision, LifecycleState, RemediationAction, RequestLog
from app.services import gateway
from app.services.controls import BOLA_IDS_PER_CLIENT, RATE_LIMIT_EXPECTED_RPM, suspicious_clients

KINDS = ("BLOCK_ROUTE", "REQUIRE_AUTH", "RATE_LIMIT", "DEPRECATION_HEADERS")
HUMAN_STATES = {"APPROVED", "APPLIED", "VERIFIED", "REJECTED", "ROLLED_BACK"}
MIN_RATE_PER_MINUTE = 30  # pages fan out into several calls per view; lower limits break normal browsing
TRANSITIONS = {
    "approve": ({"PROPOSED"}, "APPROVED"),
    "reject": ({"PROPOSED", "APPROVED"}, "REJECTED"),
    "apply": ({"APPROVED"}, "APPLIED"),
    "verify": ({"APPLIED"}, "VERIFIED"),
    "rollback": ({"APPLIED", "VERIFIED"}, "ROLLED_BACK"),
    "reopen": ({"REJECTED", "ROLLED_BACK"}, "PROPOSED"),
}


class WorkflowError(ValueError):
    pass


def _utc(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _status(api: API, control: str) -> str:
    return ((api.security_controls or {}).get(control) or {}).get("status", "UNKNOWN")


def _summary(api: API, control: str) -> str:
    return ((api.security_controls or {}).get(control) or {}).get("summary", "")


def _priority(api: API) -> str:
    return api.risk_level or ("HIGH" if api.lifecycle_state == LifecycleState.ZOMBIE else "MEDIUM")


def _client_minute_counts(db: Session) -> dict:
    """api_id -> {(client, minute): requests} for the clients that define "normal" use of each endpoint.

    Excluded: clients with a named attack pattern (anomaly model) and, per endpoint, clients that
    enumerated object IDs or flooded it. Otherwise a lab with one attacker and few real users would
    derive the limit from the attack itself (seen on the first Docker run: 164 requests/minute).
    """
    flagged = set(suspicious_clients(db))
    counts: dict = defaultdict(lambda: defaultdict(int))
    ids: dict = defaultdict(lambda: defaultdict(set))
    query = select(RequestLog.api_id, RequestLog.client_hash, RequestLog.ts, RequestLog.raw_id, RequestLog.status).where(RequestLog.api_id.is_not(None))
    for api_id, client, ts, raw_id, status in db.execute(query).yield_per(5000):
        if not client or client in flagged:
            continue
        key = (client, int(_utc(ts).timestamp()) // 60)
        counts[api_id][key] += 1
        if raw_id and 200 <= status < 300:
            ids[api_id][key].add(raw_id)
    for api_id, per_minute in counts.items():
        abusive = {client for (client, minute), n in per_minute.items()
                   if n >= RATE_LIMIT_EXPECTED_RPM or len(ids[api_id].get((client, minute), ())) >= BOLA_IDS_PER_CLIENT}
        if abusive:
            counts[api_id] = defaultdict(int, {key: n for key, n in per_minute.items() if key[0] not in abusive})
    return counts


def suggested_rate(minute_counts: dict | None) -> tuple[int, int, str]:
    """Twice the 95th percentile of per-client requests per minute from normal clients (floor 30/min)."""
    values = sorted((minute_counts or {}).values())
    if not values:
        return 60, 30, "no normal-client baseline; default 60 requests/minute"
    p95 = values[min(len(values) - 1, math.ceil(0.95 * len(values)) - 1)]
    rate = max(MIN_RATE_PER_MINUTE, 2 * p95)
    return rate, max(10, rate // 2), f"normal clients peak at {p95} request(s)/minute (95th percentile of {len(values)} client-minutes); limit set to twice that, at least {MIN_RATE_PER_MINUTE}"


def _rule(api: API, kind: str, **params) -> dict:
    return {"kind": kind, "host": api.host, "method": api.http_method, "path": api.endpoint_path,
            "path_regex": gateway.path_regex(api.endpoint_path), "params": params}


def _snippet(action_id: str, api: API, rule: dict, title: str) -> str:
    renderable = gateway.RenderableRule(action_id, rule["kind"], api.host, api.http_method, api.endpoint_path, rule["params"], title)
    locations, maps = gateway.render([renderable])
    maps_body = maps.split("\n", 1)[1].strip()
    locations_body = locations.split("\n", 1)[1].strip()
    return (f"# Preview. Applied rules are written to {gateway.LOCATIONS_FILE} (server block) and {gateway.MAPS_FILE} (http block).\n"
            + (f"\n# http {{ ... }}\n{maps_body}\n" if maps_body else "") + f"\n# server {{ ... }}\n{locations_body}\n")


def proposals_for(api: API, decision: str | None, minute_counts: dict | None, now: datetime) -> list[dict]:
    if decision not in ("REMEDIATE", "ESCALATE"):
        return []
    out: list[dict] = []
    target = f"{api.http_method} {api.display_path}"
    blocking = api.lifecycle_state == LifecycleState.ZOMBIE
    if blocking:
        removed = f" (removed in {api.removed_in_commit[:10]})" if api.removed_in_commit else ""
        out.append({"kind": "BLOCK_ROUTE", "title": f"Retire {target} at the gateway (410 Gone)",
                    "rationale": f"Zombie endpoint{removed}: {api.classification_reason or 'retired but still receiving traffic'}. "
                                 f"{api.request_count} request(s) from {api.unique_clients} client(s) still reach it; notify them before applying.",
                    "rule": _rule(api, "BLOCK_ROUTE", status=410)})
    if not blocking and _status(api, "authentication") == "NOT_ENFORCED":
        out.append({"kind": "REQUIRE_AUTH", "title": f"Require credentials for {target}",
                    "rationale": f"{_summary(api, 'authentication')}. The gateway will answer 401 to requests without credentials.",
                    "rule": _rule(api, "REQUIRE_AUTH", status=401)})
    throttle_reasons = []
    if _status(api, "rate_limiting") in ("NOT_ENFORCED", "NOT_OBSERVED"):
        throttle_reasons.append(_summary(api, "rate_limiting"))
    if _status(api, "authorization") == "NOT_ENFORCED":
        throttle_reasons.append(_summary(api, "authorization") + " (a rate limit slows enumeration while ownership checks are fixed)")
    if not blocking and throttle_reasons:
        rate, burst, basis = suggested_rate(minute_counts)
        out.append({"kind": "RATE_LIMIT", "title": f"Rate-limit {target} to {rate} requests/minute per client",
                    "rationale": "; ".join(throttle_reasons) + f". {basis}.",
                    "rule": _rule(api, "RATE_LIMIT", rate_per_minute=rate, burst=burst, status=429)})
    if api.lifecycle_state == LifecycleState.DEPRECATED and api.in_runtime and api.request_count:
        sunset = (now + timedelta(days=get_settings().deprecation_sunset_days)).strftime("%a, %d %b %Y 00:00:00 GMT")
        params = {"deprecation": "true", "sunset": sunset}
        successor = (api.superseded_by or "").replace("{", "").replace("}", "")
        try:
            if successor:
                gateway._value(successor)
                params["successor"] = successor
        except gateway.UnsafeRule:
            pass
        out.append({"kind": "DEPRECATION_HEADERS", "title": f"Announce deprecation of {target} (Sunset {sunset[5:16]})",
                    "rationale": f"Deprecated in the specification but still called {api.request_count} time(s) by {api.unique_clients} client(s). "
                                 "Deprecation and Sunset headers tell clients to migrate before the endpoint is retired.",
                    "rule": _rule(api, "DEPRECATION_HEADERS", **params)})
    return out


def run(db: Session) -> dict:
    db.flush()  # sessions run with autoflush off; make earlier stages' writes visible
    now = datetime.now(timezone.utc)
    decisions = dict(db.execute(select(Decision.api_id, Decision.action)).all())
    existing = {(a.api_id, a.kind): a for a in db.scalars(select(RemediationAction))}
    minute_counts = _client_minute_counts(db)
    stats = {"proposed": 0, "refreshed": 0, "withdrawn": 0, "kept_human_decisions": 0, "unsafe_skipped": 0, "by_kind": defaultdict(int)}
    wanted: set = set()
    for api in db.scalars(select(API)):
        try:
            proposals = proposals_for(api, decisions.get(api.id), minute_counts.get(api.id), now)
        except gateway.UnsafeRule:
            stats["unsafe_skipped"] += 1
            continue
        for proposal in proposals:
            key = (api.id, proposal["kind"])
            wanted.add(key)
            action = existing.get(key)
            if action is not None and action.status in HUMAN_STATES:
                stats["kept_human_decisions"] += 1
                continue
            if action is None:
                action = RemediationAction(id=uuid.uuid4(), api_id=api.id, kind=proposal["kind"], status="PROPOSED", proposed_at=now)
                db.add(action)
                stats["proposed"] += 1
            else:
                stats["refreshed"] += 1
            action.title, action.rationale = proposal["title"][:500], proposal["rationale"][:2000]
            action.priority, action.rule = _priority(api), proposal["rule"]
            action.config_snippet = _snippet(str(action.id), api, proposal["rule"], action.title)
            stats["by_kind"][proposal["kind"]] += 1
    stale = [a.id for key, a in existing.items() if a.status == "PROPOSED" and key not in wanted]
    if stale:
        db.execute(delete(RemediationAction).where(RemediationAction.id.in_(stale)))
    stats["withdrawn"] = len(stale)
    stats["by_kind"] = dict(stats["by_kind"])
    return stats


# ---------------------------------------------------------------------------------------------
# Workflow


def _renderable(action: RemediationAction, api: API) -> gateway.RenderableRule:
    return gateway.RenderableRule(str(action.id), action.kind, api.host, api.http_method, api.endpoint_path, (action.rule or {}).get("params", {}), action.title)


def sync_gateway(db: Session) -> dict:
    """Rewrite the nginx rule files from every APPLIED or VERIFIED action."""
    rows = db.execute(select(RemediationAction, API).join(API, RemediationAction.api_id == API.id)
                      .where(RemediationAction.status.in_(gateway.RENDERED_STATES))).all()
    return gateway.write([_renderable(action, api) for action, api in rows])


def transition(db: Session, action: RemediationAction, step: str, user: str, note: str | None = None) -> dict:
    allowed, target = TRANSITIONS[step]
    if action.status not in allowed:
        raise WorkflowError(f"Cannot {step} an action in status {action.status} (allowed from {', '.join(sorted(allowed))})")
    now = datetime.now(timezone.utc)
    result: dict = {}
    if step == "verify":
        check = verify(db, action)
        result["verification"] = check
        action.verification_note = (note or check["note"])[:2000]
        if not check["passed"]:
            return result  # stays APPLIED; the note explains what is missing
        action.verified_at = now
    action.status = target
    if step == "approve":
        action.approved_by, action.approved_at = user, now
    elif step == "apply":
        action.applied_at = now
    elif step == "reopen":
        action.approved_by = action.approved_at = action.applied_at = action.verified_at = None
    if note and step != "verify":
        action.verification_note = note[:2000]
    if step in ("apply", "rollback"):
        db.flush()
        result["gateway"] = sync_gateway(db)
    return result


def verify(db: Session, action: RemediationAction) -> dict:
    """Check traffic observed since the rule was applied."""
    api = db.get(API, action.api_id)
    if action.applied_at is None or api is None:
        return {"passed": False, "note": "Action has not been applied"}
    since = _utc(action.applied_at)
    rows = [r for r in db.execute(select(RequestLog.ts, RequestLog.status, RequestLog.authenticated, RequestLog.client_hash)
                                  .where(RequestLog.api_id == api.id, RequestLog.method == api.http_method)).all() if _utc(r.ts) >= since]
    if action.kind == "DEPRECATION_HEADERS":
        return {"passed": True, "note": "Response headers are not in the access log; confirmed by the approver"}
    if not rows:
        return {"passed": False, "note": f"No {api.http_method} traffic to this endpoint since the rule was applied; try again after traffic arrives"}
    if action.kind == "BLOCK_ROUTE":
        leaked = sum(1 for r in rows if r.status < 400)
        if leaked:
            return {"passed": False, "note": f"{leaked} of {len(rows)} request(s) since applying still succeeded; is the gateway reloaded?"}
        return {"passed": True, "note": f"All {len(rows)} request(s) since applying were refused ({', '.join(sorted({str(r.status) for r in rows}))})"}
    if action.kind == "REQUIRE_AUTH":
        unauth = [r for r in rows if r.authenticated is False]
        if not unauth:
            return {"passed": False, "note": "No unauthenticated requests since applying; nothing to verify yet"}
        leaked = sum(1 for r in unauth if 200 <= r.status < 300)
        if leaked:
            return {"passed": False, "note": f"{leaked} unauthenticated request(s) still succeeded"}
        return {"passed": True, "note": f"All {len(unauth)} unauthenticated request(s) were refused"}
    if action.kind == "RATE_LIMIT":
        params = (action.rule or {}).get("params", {})
        ceiling = int(params.get("rate_per_minute", 60)) + int(params.get("burst", 0))
        per_minute: dict = defaultdict(int)
        throttled = 0
        for r in rows:
            if r.status == 429:
                throttled += 1
            else:
                per_minute[(r.client_hash, int(_utc(r.ts).timestamp()) // 60)] += 1
        worst = max(per_minute.values(), default=0)
        if worst > ceiling:
            return {"passed": False, "note": f"A client got {worst} unthrottled requests in one minute (limit {ceiling} with burst)"}
        return {"passed": True, "note": f"No client exceeded {ceiling} requests/minute; {throttled} request(s) throttled with 429"}
    return {"passed": False, "note": f"Unknown action kind {action.kind}"}
