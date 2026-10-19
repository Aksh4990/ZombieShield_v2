"""Stage 6: security-control evidence per API, mapped to the OWASP API Security Top 10 (2023).

Every control is reported with a status taken only from observed evidence (the published
specification, the request log, the payload classifier, anomaly detection and approved gateway
rules). Nothing is guessed: when there is no evidence either way the status is UNKNOWN.

Statuses
  ENFORCED       evidence that the control works (e.g. unauthenticated calls were refused)
  DECLARED       the specification asks for it but no runtime evidence confirms it
  NOT_ENFORCED   evidence that the control is missing (e.g. unauthenticated calls succeeded)
  NOT_OBSERVED   traffic was seen but the control never showed up (e.g. no 429 under load)
  NOT_REQUIRED   public by design: anonymous calls succeed and nothing indicates credentials are expected
  UNKNOWN        no evidence either way

`API.security_controls` layout (read by the risk and remediation stages and the dashboard)::

    {
      "authentication":   {"status", "summary", "evidence": {...}},
      "authorization":    {...},   # object-level (BOLA) exposure on /{id} endpoints
      "input_validation": {...},   # how the endpoint answered requests the payload model flagged
      "rate_limiting":    {...},
      "inventory":        {...},   # documented / owned / lifecycle governance
      "gateway":          {...},   # ZombieShield gateway rules approved or applied for this API
      "owasp":            [{"id", "name", "reason"}],
      "assessed_at":      ISO timestamp,
    }
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import API, AnomalyEvent, LifecycleState, RemediationAction, RequestLog

OWASP = {
    "API1": "API1:2023 Broken Object Level Authorization",
    "API2": "API2:2023 Broken Authentication",
    "API3": "API3:2023 Broken Object Property Level Authorization",
    "API4": "API4:2023 Unrestricted Resource Consumption",
    "API5": "API5:2023 Broken Function Level Authorization",
    "API8": "API8:2023 Security Misconfiguration",
    "API9": "API9:2023 Improper Inventory Management",
}

# A single client reading this many distinct object IDs on one {id} endpoint with 2xx answers within
# one minute is the same threshold and window the anomaly model uses for "OBJECT_ID_ENUMERATION (BOLA probing)".
BOLA_IDS_PER_CLIENT = 8
# Requests per client per minute above which we expect a rate limiter to have answered 429 at least once.
RATE_LIMIT_EXPECTED_RPM = 60
_PRIVILEGED_WORDS = ("admin", "internal", "manage", "debug", "actuator", "config", "export", "import")
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ACTIVE_RULE_STATES = {"APPROVED", "APPLIED", "VERIFIED"}
# Credentials are "expected" on an endpoint when at least this share of the calls that report an
# auth state carry credentials (public endpoints such as a product catalogue stay near 0%).
AUTH_EXPECTED_SHARE = 0.5
# Anomaly windows are attack evidence only with a named attack pattern: the anomaly model flags every
# rare-looking window, so the generic label does not make a client "suspicious".
# RETIRED_ENDPOINT_ACCESS is a lifecycle signal already scored as ZOMBIE/SHADOW exposure, not an attack.
NON_ATTACK_PATTERNS = {"UNUSUAL_BEHAVIOUR", "RETIRED_ENDPOINT_ACCESS"}


@dataclass
class RuntimeStats:
    requests: int = 0
    authenticated_known: int = 0
    unauth_requests: int = 0
    unauth_success: int = 0
    unauth_refused: int = 0
    auth_success: int = 0
    status_429: int = 0
    attacks: int = 0
    attacks_accepted: int = 0
    attacks_rejected: int = 0
    max_rpm_per_client: int = 0
    clients: set[str] = field(default_factory=set)
    ids_per_client_minute: dict[tuple[str, int], set[str]] = field(default_factory=lambda: defaultdict(set))
    per_client_minute: dict[tuple[str, int], int] = field(default_factory=lambda: defaultdict(int))

    def add(self, row) -> None:
        self.requests += 1
        status = row.status
        ok = 200 <= status < 300
        if row.authenticated is not None:
            self.authenticated_known += 1
            if row.authenticated is False:
                self.unauth_requests += 1
                if ok:
                    self.unauth_success += 1
                elif status in (401, 403):
                    self.unauth_refused += 1
            elif ok:
                self.auth_success += 1
        if status == 429:
            self.status_429 += 1
        if row.payload_label not in (None, "normal"):
            self.attacks += 1
            if ok:
                self.attacks_accepted += 1
            elif 400 <= status < 500:
                self.attacks_rejected += 1
        client = row.client_hash or "unknown"
        self.clients.add(client)
        ts = row.ts if row.ts.tzinfo else row.ts.replace(tzinfo=timezone.utc)
        minute = int(ts.timestamp()) // 60
        if ok and row.raw_id:
            self.ids_per_client_minute[(client, minute)].add(row.raw_id)
        self.per_client_minute[(client, minute)] += 1

    def finish(self) -> None:
        self.max_rpm_per_client = max(self.per_client_minute.values(), default=0)

    @property
    def authenticated_share(self) -> float | None:
        return None if not self.authenticated_known else (self.authenticated_known - self.unauth_requests) / self.authenticated_known

    @property
    def max_ids_per_client(self) -> int:
        return max((len(ids) for ids in self.ids_per_client_minute.values()), default=0)


def _runtime_stats(db: Session) -> dict:
    stats: dict = defaultdict(RuntimeStats)
    query = select(RequestLog.api_id, RequestLog.ts, RequestLog.status, RequestLog.authenticated, RequestLog.client_hash,
                   RequestLog.raw_id, RequestLog.payload_label).where(RequestLog.api_id.is_not(None))
    for row in db.execute(query).yield_per(5000):
        stats[row.api_id].add(row)
    for item in stats.values():
        item.finish()
    return stats


def suspicious_clients(db: Session) -> dict[str, set[str]]:
    """client hash -> named attack patterns the anomaly model attributed to it."""
    out: dict[str, set[str]] = defaultdict(set)
    for client, pattern in db.execute(select(AnomalyEvent.client_hash, AnomalyEvent.pattern).where(AnomalyEvent.is_anomaly.is_(True))):
        if pattern and pattern not in NON_ATTACK_PATTERNS:
            out[client].add(pattern)
    return out


def auth_expected(api: API, rt: RuntimeStats) -> tuple[bool, str]:
    if api.spec_security:
        return True, "the specification requires " + ", ".join(api.spec_security)
    share = rt.authenticated_share
    if share is not None and share >= AUTH_EXPECTED_SHARE:
        return True, f"{share:.0%} of calls normally carry credentials"
    if any(word in api.endpoint_path.lower() for word in _PRIVILEGED_WORDS):
        return True, "the path names a privileged function"
    return False, ""


def _control(status: str, summary: str, **evidence) -> dict:
    return {"status": status, "summary": summary, "evidence": evidence}


def _ml_flag(api: API, model: str) -> bool:
    return any(item.get("model") == model and item.get("flagged") for item in api.ml_explanation or [])


def authentication(api: API, rt: RuntimeStats) -> dict:
    declared = list(api.spec_security or [])
    evidence = {"declared_schemes": declared, "unauthenticated_requests": rt.unauth_requests,
                "unauthenticated_successes": rt.unauth_success, "unauthenticated_refused": rt.unauth_refused}
    expected, why = auth_expected(api, rt)
    evidence.update(credentials_expected=expected, authenticated_share=None if rt.authenticated_share is None else round(rt.authenticated_share, 3))
    if rt.unauth_success and expected:
        return _control("NOT_ENFORCED", f"{rt.unauth_success} request(s) without credentials succeeded, although {why}", **evidence)
    if rt.unauth_success:
        return _control("NOT_REQUIRED", f"Public endpoint: anonymous calls succeed and nothing indicates credentials are expected "
                                        f"(no security in the specification, {1 - (rt.authenticated_share or 0):.0%} of calls anonymous)", **evidence)
    if rt.unauth_refused:
        return _control("ENFORCED", f"{rt.unauth_refused} request(s) without credentials were refused with 401/403", **evidence)
    if declared:
        return _control("DECLARED", "Specification requires " + ", ".join(declared) + "; no unauthenticated traffic observed to confirm it", **evidence)
    if rt.authenticated_known and rt.unauth_requests == 0:
        return _control("UNKNOWN", "All observed requests carried credentials; enforcement not tested by traffic", **evidence)
    return _control("UNKNOWN", "No authentication declared and no runtime evidence", **evidence)


def object_authorization(api: API, rt: RuntimeStats) -> dict:
    if "{id}" not in api.endpoint_path:
        return _control("UNKNOWN", "Endpoint takes no object identifier", applicable=False)
    worst = rt.max_ids_per_client
    evidence = {"applicable": True, "max_distinct_ids_per_client_minute": worst, "threshold": BOLA_IDS_PER_CLIENT,
                "unauthenticated_successes": rt.unauth_success}
    if worst >= BOLA_IDS_PER_CLIENT:
        return _control("NOT_ENFORCED", f"One client successfully read {worst} different object IDs within a minute (BOLA enumeration pattern)", **evidence)
    if rt.unauth_success and auth_expected(api, rt)[0]:
        return _control("NOT_ENFORCED", "Objects were returned to callers without credentials", **evidence)
    if rt.requests:
        return _control("UNKNOWN", f"No enumeration seen (max {worst} IDs per client per minute); ownership checks cannot be confirmed from logs", **evidence)
    return _control("UNKNOWN", "No runtime traffic", **evidence)


def input_validation(api: API, rt: RuntimeStats) -> dict:
    evidence = {"flagged_requests": rt.attacks, "accepted": rt.attacks_accepted, "rejected": rt.attacks_rejected}
    if not rt.attacks:
        return _control("UNKNOWN", "No requests flagged by the payload classifier", **evidence)
    if rt.attacks_accepted:
        return _control("NOT_ENFORCED", f"{rt.attacks_accepted} of {rt.attacks} flagged attack payload(s) got a 2xx answer", **evidence)
    if rt.attacks_rejected:
        return _control("ENFORCED", f"All {rt.attacks} flagged attack payload(s) were rejected with 4xx", **evidence)
    return _control("UNKNOWN", f"{rt.attacks} flagged payload(s) answered with other statuses", **evidence)


def rate_limiting(api: API, rt: RuntimeStats, suspicious: dict[str, set[str]]) -> dict:
    patterns = sorted({p for client in rt.clients & suspicious.keys() for p in suspicious[client]})
    count = len(rt.clients & suspicious.keys())
    evidence = {"responses_429": rt.status_429, "max_requests_per_client_minute": rt.max_rpm_per_client,
                "expected_limit_rpm": RATE_LIMIT_EXPECTED_RPM, "anomalous_clients": api.anomalous_client_count,
                "suspicious_clients": count, "suspicious_patterns": patterns}
    if rt.status_429:
        return _control("ENFORCED", f"{rt.status_429} request(s) were throttled with 429", **evidence)
    if rt.max_rpm_per_client >= RATE_LIMIT_EXPECTED_RPM:
        return _control("NOT_ENFORCED", f"A client sent {rt.max_rpm_per_client} requests in one minute and was never throttled", **evidence)
    if count:
        return _control("NOT_OBSERVED", f"{count} client(s) showing {', '.join(patterns)} were never throttled", **evidence)
    if rt.requests:
        return _control("UNKNOWN", f"Traffic stayed below {RATE_LIMIT_EXPECTED_RPM} requests per client minute; no 429 seen", **evidence)
    return _control("UNKNOWN", "No runtime traffic", **evidence)


def inventory(api: API) -> dict:
    documented = api.in_current_spec
    evidence = {"documented": documented, "in_code": api.in_current_code, "owner": api.owner, "registered": api.is_registered,
                "lifecycle_state": api.lifecycle_state.value, "spec_deprecated": api.spec_deprecated, "superseded_by": api.superseded_by}
    state = api.lifecycle_state
    if state == LifecycleState.ZOMBIE:
        return _control("NOT_ENFORCED", "Retired endpoint is still reachable and used", **evidence)
    if state == LifecycleState.SHADOW:
        return _control("NOT_ENFORCED", "Endpoint in use but absent from every current specification and codebase", **evidence)
    if state == LifecycleState.DEPRECATED and api.in_runtime:
        target = f"; successor {api.superseded_by}" if api.superseded_by else ""
        return _control("DECLARED", f"Deprecated in the specification but still called{target}", **evidence)
    if api.in_current_code and not documented:
        return _control("NOT_ENFORCED", "Implemented in code but missing from the published specification", **evidence)
    if documented and (api.owner or api.is_registered):
        return _control("ENFORCED", "Documented and owned", **evidence)
    if documented:
        return _control("DECLARED", "Documented; no owner recorded", **evidence)
    return _control("UNKNOWN", "No inventory evidence", **evidence)


def gateway(api: API, rules: list[RemediationAction]) -> dict:
    active = [{"kind": r.kind, "status": r.status} for r in rules if r.status in _ACTIVE_RULE_STATES]
    if any(r["status"] == "VERIFIED" for r in active):
        return _control("ENFORCED", "Gateway rule verified against traffic", rules=active)
    if any(r["status"] == "APPLIED" for r in active):
        return _control("DECLARED", "Gateway rule applied, not yet verified", rules=active)
    if active:
        return _control("DECLARED", "Gateway rule approved, not yet applied", rules=active)
    return _control("UNKNOWN", "No ZombieShield gateway rule", rules=[])


def owasp_mapping(api: API, controls: dict, rt: RuntimeStats) -> list[dict]:
    found: list[dict] = []

    def add(key: str, reason: str) -> None:
        if all(item["id"] != key for item in found):
            found.append({"id": key, "name": OWASP[key], "reason": reason})

    authz, authn, validation, limits, inv = (controls[k] for k in ("authorization", "authentication", "input_validation", "rate_limiting", "inventory"))
    sensitive = _ml_flag(api, "sensitive")
    path = api.endpoint_path.lower()
    if authz["status"] == "NOT_ENFORCED":
        add("API1", authz["summary"])
    if authn["status"] == "NOT_ENFORCED":
        add("API2", authn["summary"])
    if sensitive and (authn["status"] == "NOT_ENFORCED" or authz["status"] == "NOT_ENFORCED"):
        add("API3", "Endpoint likely returns sensitive fields (endpoint ML) and access control is not enforced")
    if limits["status"] in ("NOT_ENFORCED", "NOT_OBSERVED"):
        add("API4", limits["summary"])
    privileged = any(word in path for word in _PRIVILEGED_WORDS)
    if rt.unauth_success and (privileged or api.http_method in _WRITE_METHODS):
        what = "privileged path" if privileged else f"{api.http_method} operation"
        add("API5", f"Unauthenticated callers succeeded on a {what}")
    if validation["status"] == "NOT_ENFORCED":
        add("API8", validation["summary"])
    if api.vulnerability_count:
        add("API8", f"{api.vulnerability_count} known vulnerability(ies) in the service's dependencies (unpatched components)")
    if authn["status"] == "NOT_ENFORCED" and api.spec_security:
        add("API8", "Specification declares authentication that the deployment does not enforce")
    if inv["status"] == "NOT_ENFORCED" or (api.lifecycle_state == LifecycleState.DEPRECATED and api.in_runtime):
        add("API9", inv["summary"])
    return found


def assess(api: API, rt: RuntimeStats, rules: list[RemediationAction], now: datetime, suspicious: dict[str, set[str]] | None = None) -> dict:
    controls = {
        "authentication": authentication(api, rt),
        "authorization": object_authorization(api, rt),
        "input_validation": input_validation(api, rt),
        "rate_limiting": rate_limiting(api, rt, suspicious or {}),
        "inventory": inventory(api),
        "gateway": gateway(api, rules),
    }
    controls["owasp"] = owasp_mapping(api, controls, rt)
    controls["assessed_at"] = now.isoformat()
    return controls


def run(db: Session) -> dict:
    db.flush()  # sessions run with autoflush off; make earlier stages' writes visible
    now = datetime.now(timezone.utc)
    stats = _runtime_stats(db)
    suspicious = suspicious_clients(db)
    rules_by_api: dict = defaultdict(list)
    for rule in db.scalars(select(RemediationAction)):
        rules_by_api[rule.api_id].append(rule)
    summary = {"assessed": 0, "auth_not_enforced": 0, "bola_exposed": 0, "attacks_accepted": 0, "unthrottled": 0, "owasp": defaultdict(int)}
    empty = RuntimeStats()
    for api in db.scalars(select(API)):
        controls = assess(api, stats.get(api.id, empty), rules_by_api.get(api.id, []), now, suspicious)
        api.security_controls = controls
        api.owasp_categories = [item["name"] for item in controls["owasp"]]
        summary["assessed"] += 1
        summary["auth_not_enforced"] += controls["authentication"]["status"] == "NOT_ENFORCED"
        summary["bola_exposed"] += controls["authorization"]["status"] == "NOT_ENFORCED"
        summary["attacks_accepted"] += controls["input_validation"]["status"] == "NOT_ENFORCED"
        summary["unthrottled"] += controls["rate_limiting"]["status"] in ("NOT_ENFORCED", "NOT_OBSERVED")
        for item in controls["owasp"]:
            summary["owasp"][item["id"]] += 1
    summary["owasp"] = dict(sorted(summary["owasp"].items()))
    return summary
