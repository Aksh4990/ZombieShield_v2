"""Stage 7: explainable risk score (0-100) per API.

The score is a capped sum of points, one entry per factor, each with the evidence that earned it,
so every number on the dashboard can be traced back to a fact. There are no hidden weights:
the whole policy is the `POINTS` table and the functions below.

Factors (max points)
  exposure      lifecycle: ZOMBIE 30, SHADOW 25, deprecated-but-called 12, undocumented-in-code 8
  access        authentication not enforced 20 (+5 privileged/write), BOLA pattern 15
  data          endpoint ML flags sensitive data 10 (x1.5 when access control is missing)
  supply chain  KEV 25, else worst CVSS (>=9: 15, >=7: 10, other: 5), +5 when EPSS >= 0.1
  attack        accepted attack payloads 15 / rejected attack payloads 5
  behaviour     clients with a named anomaly pattern 5 + 2 each (max 12), unthrottled heavy use 5
  reach         log-scaled distinct clients, max 5
  mitigation    decommissioned -80%, verified gateway block -60%, applied block -40%, verified auth/rate rule -20%

Levels: >=75 CRITICAL, >=50 HIGH, >=25 MEDIUM, else LOW (aligned with the decision engine's
ESCALATE >=75 and REMEDIATE >=50 thresholds).
"""

import math
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import API, Component, LifecycleState, RiskLevel, ThreatFinding, Vulnerability

POINTS = {
    "zombie": 30, "shadow": 25, "deprecated_in_use": 12, "undocumented": 8,
    "auth_not_enforced": 20, "privileged_unauth": 5, "bola": 15,
    "sensitive": 10,
    "kev": 25, "cvss_critical": 15, "cvss_high": 10, "cvss_other": 5, "epss": 5,
    "attack_accepted": 15, "attack_seen": 5,
    "anomaly_base": 5, "anomaly_per_client": 2, "anomaly_max": 12, "unthrottled": 5,
    "reach_max": 5,
}
EPSS_THRESHOLD = 0.1
LEVELS = [(75, RiskLevel.CRITICAL), (50, RiskLevel.HIGH), (25, RiskLevel.MEDIUM), (0, RiskLevel.LOW)]


def level_for(score: float) -> RiskLevel:
    return next(level for floor, level in LEVELS if score >= floor)


def service_vulnerabilities(db: Session) -> dict[str, dict]:
    """Worst vulnerability evidence per service, from the threat-intel stage's findings."""
    out: dict[str, dict] = defaultdict(lambda: {"count": 0, "kev": [], "max_cvss": None, "max_epss": None, "worst": None})
    rows = db.execute(select(ThreatFinding.service_name, Vulnerability, Component.name, Component.version)
                      .join(Vulnerability, ThreatFinding.vulnerability_id == Vulnerability.id)
                      .join(Component, ThreatFinding.component_id == Component.id)).all()
    seen: set[tuple[str, str]] = set()
    for service, vuln, component, version in rows:
        if (service, vuln.id) in seen:
            continue
        seen.add((service, vuln.id))
        entry = out[service]
        entry["count"] += 1
        label = f"{vuln.id} in {component} {version}"
        if vuln.in_kev:
            entry["kev"].append(label)
        if vuln.cvss_score is not None and (entry["max_cvss"] is None or vuln.cvss_score > entry["max_cvss"]):
            entry["max_cvss"], entry["worst"] = vuln.cvss_score, label
        if vuln.epss is not None and (entry["max_epss"] is None or vuln.epss > entry["max_epss"]):
            entry["max_epss"] = vuln.epss
    return out


def _status(api: API, control: str) -> str:
    return ((api.security_controls or {}).get(control) or {}).get("status", "UNKNOWN")


def _summary(api: API, control: str) -> str:
    return ((api.security_controls or {}).get(control) or {}).get("summary", "")


def _sensitive(api: API) -> dict | None:
    return next((item for item in api.ml_explanation or [] if item.get("model") == "sensitive" and item.get("flagged")), None)


def assess(api: API, vulns: dict | None) -> tuple[float, list[dict]]:
    factors: list[dict] = []

    def add(factor: str, points: float, evidence: str) -> None:
        if points:
            factors.append({"factor": factor, "points": round(points, 1), "evidence": evidence})

    # Exposure: lifecycle
    state = api.lifecycle_state
    if state == LifecycleState.ZOMBIE:
        add("Zombie endpoint", POINTS["zombie"], api.classification_reason or "retired endpoint still receiving traffic")
    elif state == LifecycleState.SHADOW:
        add("Shadow endpoint", POINTS["shadow"], api.classification_reason or "undocumented endpoint in use")
    elif state == LifecycleState.DEPRECATED and api.in_runtime and api.request_count:
        add("Deprecated but still called", POINTS["deprecated_in_use"], f"{api.request_count} request(s) to a deprecated endpoint")
    elif state == LifecycleState.ACTIVE and api.in_current_code and not api.in_current_spec and api.in_runtime:
        add("Undocumented in specification", POINTS["undocumented"], "implemented and called but absent from the published specification")

    # Access control
    auth_missing = _status(api, "authentication") == "NOT_ENFORCED"
    bola = _status(api, "authorization") == "NOT_ENFORCED"
    if auth_missing:
        add("Authentication not enforced", POINTS["auth_not_enforced"], _summary(api, "authentication"))
        owasp_ids = {item.get("id") for item in (api.security_controls or {}).get("owasp", [])}
        if "API5" in owasp_ids:
            add("Privileged or write operation open", POINTS["privileged_unauth"], f"unauthenticated {api.http_method} succeeded")
    if bola:
        add("Object-level authorization gap", POINTS["bola"], _summary(api, "authorization"))

    # Data sensitivity (endpoint ML)
    sensitive = _sensitive(api)
    if sensitive:
        multiplier = 1.5 if (auth_missing or bola) else 1.0
        terms = ", ".join(sensitive.get("signals") or []) or "field names"
        add("Handles sensitive data", POINTS["sensitive"] * multiplier,
            f"endpoint model score {sensitive['score']:.2f} (signals: {terms})" + ("; exposed without access control" if multiplier > 1 else ""))

    # Supply chain
    if vulns and vulns["count"]:
        if vulns["kev"]:
            add("Known exploited vulnerability", POINTS["kev"], "CISA KEV: " + ", ".join(vulns["kev"][:3]))
        else:
            cvss = vulns["max_cvss"]
            points = POINTS["cvss_other"] if cvss is None else POINTS["cvss_critical"] if cvss >= 9 else POINTS["cvss_high"] if cvss >= 7 else POINTS["cvss_other"]
            cvss_text = f"worst CVSS {cvss:.1f} ({vulns['worst']})" if cvss is not None else "no CVSS score published"
            add("Vulnerable dependencies", points, f"{vulns['count']} known vulnerability(ies); {cvss_text}")
        if vulns["max_epss"] is not None and vulns["max_epss"] >= EPSS_THRESHOLD:
            add("Likely to be exploited (EPSS)", POINTS["epss"], f"highest EPSS probability {vulns['max_epss']:.2f}")

    # Observed attacks
    validation = (api.security_controls or {}).get("input_validation") or {}
    accepted = (validation.get("evidence") or {}).get("accepted", 0)
    if accepted:
        add("Attack payloads accepted", POINTS["attack_accepted"], validation.get("summary", ""))
    elif api.attack_request_count:
        add("Targeted by attack payloads", POINTS["attack_seen"], f"{api.attack_request_count} request(s) flagged by the payload classifier")

    # Behaviour
    limits = ((api.security_controls or {}).get("rate_limiting") or {}).get("evidence") or {}
    suspicious = limits.get("suspicious_clients", 0)
    if suspicious:
        points = min(POINTS["anomaly_max"], POINTS["anomaly_base"] + POINTS["anomaly_per_client"] * suspicious)
        add("Suspicious clients", points, f"{suspicious} client(s) showing {', '.join(limits.get('suspicious_patterns', []))} (traffic anomaly model)")
    if _status(api, "rate_limiting") == "NOT_ENFORCED":
        add("No rate limiting", POINTS["unthrottled"], _summary(api, "rate_limiting"))

    # Reach
    if api.unique_clients:
        points = min(POINTS["reach_max"], math.log10(api.unique_clients + 1) * 2.5)
        add("Client reach", points, f"{api.unique_clients} distinct client(s)")

    raw = min(100.0, sum(f["points"] for f in factors))

    # Mitigation already in place at the gateway
    rules = ((api.security_controls or {}).get("gateway") or {}).get("evidence", {}).get("rules", [])
    statuses = {(r["kind"], r["status"]) for r in rules}
    reduction, why = 0.0, ""
    if state == LifecycleState.DECOMMISSIONED:
        reduction, why = 0.8, "endpoint decommissioned: absent from current code, specification and recent traffic"
    elif ("BLOCK_ROUTE", "VERIFIED") in statuses:
        reduction, why = 0.6, "route blocked at the gateway (verified)"
    elif ("BLOCK_ROUTE", "APPLIED") in statuses:
        reduction, why = 0.4, "route blocked at the gateway (not yet verified)"
    elif any(status == "VERIFIED" for _, status in statuses):
        reduction, why = 0.2, "compensating gateway rule verified"
    if reduction and raw:
        factors.append({"factor": "Decommissioned" if state == LifecycleState.DECOMMISSIONED else "Gateway mitigation", "points": round(-raw * reduction, 1), "evidence": why})
    score = round(max(0.0, raw * (1 - reduction)), 1)
    return score, factors


def explain(score: float, level: RiskLevel, factors: list[dict]) -> str:
    if not factors:
        return f"{level.value} ({score:.0f}/100): no risk factors observed."
    top = sorted((f for f in factors if f["points"] > 0), key=lambda f: -f["points"])[:3]
    text = "; ".join(f"{f['factor'].lower()} (+{f['points']:.0f})" for f in top)
    mitigation = next((f for f in factors if f["points"] < 0), None)
    tail = f"; reduced by {mitigation['evidence']} ({mitigation['points']:.0f})" if mitigation else ""
    return f"{level.value} ({score:.0f}/100) driven by {text}{tail}."


def run(db: Session) -> dict:
    db.flush()  # sessions run with autoflush off; make earlier stages' writes visible
    now = datetime.now(timezone.utc)
    vulns = service_vulnerabilities(db)
    counts = {level.value: 0 for level in RiskLevel}
    total = 0.0
    apis = list(db.scalars(select(API)))
    for api in apis:
        score, factors = assess(api, vulns.get(api.service_name))
        level = level_for(score)
        api.risk_score, api.risk_level, api.risk_breakdown = score, level.value, factors
        api.risk_explanation = explain(score, level, factors)[:2000]
        api.risk_assessed_at = now
        counts[level.value] += 1
        total += score
    return {"assessed": len(apis), "levels": counts, "mean_score": round(total / len(apis), 1) if apis else 0.0,
            "max_score": max((a.risk_score or 0 for a in apis), default=0.0)}
