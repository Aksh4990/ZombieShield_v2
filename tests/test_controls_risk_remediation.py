"""Stages 6 (controls), 7 (risk) and 9 (remediation + gateway rules)."""

import shutil
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import API, Component, Decision, LifecycleState, RemediationAction, RequestLog, ThreatFinding, Vulnerability
from app.services import controls, decision, gateway, remediation, risk
from conftest import login

NOW = datetime.now(timezone.utc)


def make_api(db, path="/v1/customers/{id}", method="GET", state=LifecycleState.ACTIVE, **extra) -> API:
    api = API(id=uuid.uuid4(), canonical_key=uuid.uuid4().hex, organization="lab", service_name=extra.pop("service_name", "shop"), host="front-end",
              http_method=method, endpoint_path=path, display_path=path, lifecycle_state=state, sources=[], current_sources=[],
              spec_security=extra.pop("spec_security", []), ml_explanation=extra.pop("ml_explanation", []), risk_breakdown=[],
              owasp_categories=[], security_controls={}, **extra)
    db.add(api)
    db.flush()
    return api


def add_requests(db, api, n, *, status=200, authenticated=True, client="c1", ids=None, label=None, start=None, spacing=timedelta(seconds=2)):
    start = start or (NOW - timedelta(hours=1)).replace(second=0, microsecond=0)  # minute-aligned: per-minute counts are deterministic
    for i in range(n):
        db.add(RequestLog(ts=start + i * spacing, api_id=api.id, method=api.http_method, path=api.endpoint_path, status=status,
                          client_hash=client, authenticated=authenticated, raw_id=(ids[i % len(ids)] if ids else None), payload_label=label))
    api.request_count = (api.request_count or 0) + n
    api.in_runtime = True


# ---------------------------------------------------------------- stage 6

def test_controls_detect_missing_auth_bola_and_accepted_attacks():
    with SessionLocal() as db:
        api = make_api(db, method="GET", spec_security=["bearerAuth"])
        add_requests(db, api, 12, authenticated=False, client="enum", ids=[str(i) for i in range(12)])
        add_requests(db, api, 3, authenticated=True, client="c2", label="sqli", status=200)
        protected = make_api(db, path="/v2/orders/{id}")
        add_requests(db, protected, 4, authenticated=False, status=401)
        db.commit()
        summary = controls.run(db)
        db.commit()
        assert summary["auth_not_enforced"] == 1 and summary["bola_exposed"] == 1
        c = api.security_controls
        assert c["authentication"]["status"] == "NOT_ENFORCED" and "bearerAuth" in c["authentication"]["summary"]
        assert c["authorization"]["status"] == "NOT_ENFORCED"
        assert c["input_validation"]["status"] == "NOT_ENFORCED"
        ids = {item["id"] for item in c["owasp"]}
        assert {"API1", "API2", "API8"} <= ids
        assert protected.security_controls["authentication"]["status"] == "ENFORCED"
        assert protected.owasp_categories == []


def test_public_endpoint_is_not_flagged_for_missing_auth():
    with SessionLocal() as db:
        catalogue = make_api(db, path="/catalogue", state=LifecycleState.SHADOW)  # undocumented, so the decision is REMEDIATE
        add_requests(db, catalogue, 40, authenticated=False)
        admin = make_api(db, path="/admin/users")
        add_requests(db, admin, 3, authenticated=False)
        db.commit()
        controls.run(db)
        risk.run(db)
        decision.run(db)
        remediation.run(db)
        db.commit()
        assert catalogue.security_controls["authentication"]["status"] == "NOT_REQUIRED"
        assert "API2" not in {i["id"] for i in catalogue.security_controls["owasp"]}
        assert not any(f["factor"] == "Authentication not enforced" for f in catalogue.risk_breakdown)
        assert db.query(RemediationAction).filter_by(api_id=catalogue.id, kind="REQUIRE_AUTH").count() == 0
        assert admin.security_controls["authentication"]["status"] == "NOT_ENFORCED"  # privileged path: credentials expected
        assert {"API2", "API5"} <= {i["id"] for i in admin.security_controls["owasp"]}


def test_only_named_anomaly_patterns_count_as_suspicious():
    from app.models import AnomalyEvent
    with SessionLocal() as db:
        api = make_api(db, path="/cart")
        add_requests(db, api, 5, client="shopper")
        add_requests(db, api, 5, client="prober")
        start = NOW - timedelta(hours=1)
        db.add_all([AnomalyEvent(client_hash="shopper", window_start=start, window_end=start, score=0.6, is_anomaly=True, pattern="UNUSUAL_BEHAVIOUR"),
                    AnomalyEvent(client_hash="prober", window_start=start, window_end=start, score=0.9, is_anomaly=True, pattern="INJECTION_ATTEMPTS")])
        api.anomalous_client_count = 2
        db.commit()
        controls.run(db)
        risk.run(db)
        evidence = api.security_controls["rate_limiting"]["evidence"]
        assert evidence["suspicious_clients"] == 1 and evidence["suspicious_patterns"] == ["INJECTION_ATTEMPTS"]
        assert next(f for f in api.risk_breakdown if f["factor"] == "Suspicious clients")["points"] == 7
        counts = remediation._client_minute_counts(db)[api.id]
        assert {client for client, _ in counts} == {"shopper"}


def test_decommissioned_endpoint_risk_is_discounted():
    with SessionLocal() as db:
        api = make_api(db, path="/accounts/{id}", state=LifecycleState.DECOMMISSIONED,
                       ml_explanation=[{"model": "sensitive", "score": 0.8, "flagged": True, "signals": []}])
        db.commit()
        controls.run(db)
        risk.run(db)
        assert api.risk_score == 2.0 and api.risk_breakdown[-1]["factor"] == "Decommissioned"


def test_controls_rate_limit_evidence():
    with SessionLocal() as db:
        burst = make_api(db, path="/catalogue")
        add_requests(db, burst, 80, spacing=timedelta(milliseconds=200))
        throttled = make_api(db, path="/login", method="POST")
        add_requests(db, throttled, 5, status=429)
        db.commit()
        controls.run(db)
        assert burst.security_controls["rate_limiting"]["status"] == "NOT_ENFORCED"
        assert "API4" in {i["id"] for i in burst.security_controls["owasp"]}
        assert throttled.security_controls["rate_limiting"]["status"] == "ENFORCED"


# ---------------------------------------------------------------- stage 7

def test_risk_is_explainable_and_ordered():
    with SessionLocal() as db:
        sensitive = [{"model": "sensitive", "score": 0.91, "flagged": True, "signals": ["email", "card"]}]
        zombie = make_api(db, path="/v1/customers/{id}", state=LifecycleState.ZOMBIE, classification_reason="removed in git, still called",
                          ml_explanation=sensitive, unique_clients=3)
        add_requests(db, zombie, 20, authenticated=True, client="owner", ids=["1"])  # normal callers send credentials
        add_requests(db, zombie, 12, authenticated=False, client="enum", ids=[str(i) for i in range(12)])
        healthy = make_api(db, path="/v2/customers/{id}", unique_clients=3)
        add_requests(db, healthy, 5)
        db.commit()
        controls.run(db)
        summary = risk.run(db)
        db.commit()
        assert zombie.risk_score > 75 and zombie.risk_level == "CRITICAL"
        assert healthy.risk_score < 25 and healthy.risk_level == "LOW"
        assert summary["levels"]["CRITICAL"] == 1
        factors = {f["factor"]: f for f in zombie.risk_breakdown}
        assert {"Zombie endpoint", "Authentication not enforced", "Object-level authorization gap", "Handles sensitive data"} <= set(factors)
        assert factors["Handles sensitive data"]["points"] == 15  # amplified because access control is missing
        assert zombie.risk_score == min(100, sum(f["points"] for f in zombie.risk_breakdown))
        assert zombie.risk_explanation.startswith("CRITICAL")
        action, _ = decision.decide(zombie)
        assert action == "ESCALATE"


def test_risk_uses_service_vulnerabilities_and_gateway_mitigation():
    with SessionLocal() as db:
        api = make_api(db, path="/cart/{id}", method="PUT", state=LifecycleState.ZOMBIE, service_name="front-end")
        add_requests(db, api, 3)
        component = Component(service_name="front-end", ecosystem="npm", name="morgan", version="1.7.0", purl="pkg:npm/morgan@1.7.0", manifest="package.json")
        db.add_all([component, Vulnerability(id="GHSA-test", summary="x", severity="CRITICAL", cvss_score=9.8, epss=0.4)])
        db.flush()
        db.add(ThreatFinding(component_id=component.id, vulnerability_id="GHSA-test", service_name="front-end", match_reason="range"))
        db.commit()
        controls.run(db)
        risk.run(db)
        before = api.risk_score
        factors = {f["factor"] for f in api.risk_breakdown}
        assert {"Vulnerable dependencies", "Likely to be exploited (EPSS)"} <= factors
        db.add(RemediationAction(api_id=api.id, kind="BLOCK_ROUTE", title="t", rationale="r", config_snippet="", status="VERIFIED"))
        db.commit()
        controls.run(db)
        risk.run(db)
        assert api.risk_score == pytest.approx(before * 0.4, abs=0.2)
        assert api.risk_breakdown[-1]["factor"] == "Gateway mitigation"


# ---------------------------------------------------------------- gateway rendering

def test_path_regex():
    assert gateway.path_regex("/cart/{id}") == "^/cart/[^/]+/?$"
    assert gateway.path_regex("/v1/a.b/{id}/items") == r"^/v1/a\.b/[^/]+/items/?$"
    assert gateway.path_regex("/static*") == "^/static.*$"
    for bad in ("/x;return 200", '/a"b', "/a b", "relative"):
        with pytest.raises(gateway.UnsafeRule):
            gateway.path_regex(bad)


def _rules():
    R = gateway.RenderableRule
    return [R("1", "BLOCK_ROUTE", "front-end", "PUT", "/cart/{id}", {}, "t"),
            R("2", "RATE_LIMIT", "front-end", "GET", "/cart/{id}", {"rate_per_minute": 30, "burst": 15}, "t"),
            R("3", "REQUIRE_AUTH", "front-end", "GET", "/orders/search/customerId", {}, "t"),
            R("4", "DEPRECATION_HEADERS", "front-end", "GET", "/v2/legacy-report", {"deprecation": "true", "sunset": "Sun, 17 Jan 2027 00:00:00 GMT", "successor": "/v3/report"}, "t")]


def test_render_groups_methods_per_location():
    locations, maps = gateway.render(_rules(), upstream="http://sockshop_front_end", auth_variable="$zs_has_auth")
    assert locations.count('location ~ "^/cart/[^/]+/?$"') == 1  # one block per path; methods split via maps
    assert "return 410" in locations and "limit_req zone=" in locations and "return 401" in locations
    assert "limit_req_zone $zs_rl_key_1_1 zone=zs_rl_1_1:10m rate=30r/m;" in maps
    assert '"GET:0" 1;' in maps and "rel=successor-version" in maps


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_rendered_config_passes_nginx_syntax_check(tmp_path):
    rules_dir = tmp_path / "zombieshield"
    result = gateway.write(_rules(), str(rules_dir))
    assert result["rules"] == 4
    nginx_conf = Path(__file__).resolve().parents[1] / "sockshop" / "gateway" / "nginx.conf"
    conf = nginx_conf.read_text().replace("/etc/nginx/zombieshield", str(rules_dir)).replace("/var/log/gateway/access.log", str(tmp_path / "access.log"))
    conf = conf.replace("server front-end:8079;", "server 127.0.0.1:8079;")
    (tmp_path / "nginx.conf").write_text(f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\n" + conf)
    check = subprocess.run(["nginx", "-t", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf")], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


# ---------------------------------------------------------------- stage 9 + workflow

def _seed_zombie_and_shadow(db):
    zombie = make_api(db, path="/cart/{id}", method="PUT", state=LifecycleState.ZOMBIE, classification_reason="removed in 2017",
                      removed_in_commit="abc1234def", unique_clients=2)
    add_requests(db, zombie, 6)
    shadow = make_api(db, path="/orders/search/customerId", state=LifecycleState.SHADOW, unique_clients=1)
    add_requests(db, shadow, 200, authenticated=True, client="svc", spacing=timedelta(seconds=10))
    add_requests(db, shadow, 130, authenticated=False, spacing=timedelta(milliseconds=250))  # >= 65 in some clock minute
    deprecated = make_api(db, path="/v2/legacy-report", state=LifecycleState.DEPRECATED, superseded_by="/v3/report/{id}")
    add_requests(db, deprecated, 2)
    healthy = make_api(db, path="/catalogue")
    add_requests(db, healthy, 3)
    db.commit()
    return zombie, shadow, deprecated, healthy


def _run_stages(db):
    controls.run(db)
    risk.run(db)
    decision.run(db)
    summary = remediation.run(db)
    db.commit()
    return summary


def test_remediation_proposals_are_idempotent_and_respect_humans():
    with SessionLocal() as db:
        zombie, shadow, deprecated, healthy = _seed_zombie_and_shadow(db)
        summary = _run_stages(db)
        kinds = {(a.api_id, a.kind) for a in db.query(RemediationAction)}
        assert (zombie.id, "BLOCK_ROUTE") in kinds and (zombie.id, "REQUIRE_AUTH") not in kinds
        assert {(shadow.id, "REQUIRE_AUTH"), (shadow.id, "RATE_LIMIT")} <= kinds
        assert (deprecated.id, "DEPRECATION_HEADERS") in kinds
        assert not any(api_id == healthy.id for api_id, _ in kinds)
        assert summary["proposed"] == len(kinds)
        dep = db.query(RemediationAction).filter_by(api_id=deprecated.id).one()
        assert dep.rule["params"]["successor"] == "/v3/report/id"

        block = db.query(RemediationAction).filter_by(api_id=zombie.id, kind="BLOCK_ROUTE").one()
        assert "return 410" in block.config_snippet and block.priority in ("MEDIUM", "HIGH", "CRITICAL")
        block.status = "REJECTED"
        db.commit()
        again = _run_stages(db)
        assert again["proposed"] == 0 and again["kept_human_decisions"] == 1
        assert db.get(RemediationAction, block.id).status == "REJECTED"

        # evidence disappears -> the untouched proposal is withdrawn
        deprecated.lifecycle_state = LifecycleState.ACTIVE
        db.commit()
        third = _run_stages(db)
        assert third["withdrawn"] == 1
        assert db.query(RemediationAction).filter_by(api_id=deprecated.id).count() == 0


def test_rate_limit_is_derived_from_normal_clients():
    rate, burst, basis = remediation.suggested_rate({("a", 1): 14, ("a", 2): 25, ("b", 1): 20})
    assert rate == 50 and burst == 25 and "95th percentile" in basis
    assert remediation.suggested_rate({("a", 1): 1})[0] == remediation.MIN_RATE_PER_MINUTE


def test_approval_workflow_writes_and_verifies_gateway_rules(client, analyst, admin_headers):
    with SessionLocal() as db:
        zombie, *_ = _seed_zombie_and_shadow(db)
        _run_stages(db)
        zombie_id = zombie.id
    listing = client.get("/remediation", headers=analyst).json()
    block = next(a for a in listing if a["kind"] == "BLOCK_ROUTE")
    assert block["api"]["path"] == "/cart/{id}" and block["status"] == "PROPOSED"

    assert client.post(f"/remediation/{block['id']}/approve", headers=analyst).status_code == 403  # analysts cannot approve
    assert client.post(f"/remediation/{block['id']}/apply", headers=admin_headers).status_code == 409  # must approve first
    approved = client.post(f"/remediation/{block['id']}/approve", headers=admin_headers, json={"note": "owner agreed"}).json()
    assert approved["status"] == "APPROVED" and approved["approved_by"] == "admin"
    applied = client.post(f"/remediation/{block['id']}/apply", headers=admin_headers)
    assert applied.status_code == 200, applied.text
    assert applied.json()["gateway"]["rules"] == 1

    rules_dir = Path(get_settings().gateway_rules_dir)
    conf = (rules_dir / gateway.LOCATIONS_FILE).read_text()
    assert 'location ~ "^/cart/[^/]+/?$"' in conf and "return 410" in conf
    assert (rules_dir / gateway.MAPS_FILE).is_file()
    preview = client.get("/remediation/gateway-config", headers=analyst).json()
    assert preview["rules"] == 1

    # No traffic yet: verification stays pending
    pending = client.post(f"/remediation/{block['id']}/verify", headers=analyst).json()
    assert pending["status"] == "APPLIED" and not pending["verification"]["passed"]
    with SessionLocal() as db:
        api = db.get(API, zombie_id)
        add_requests(db, api, 3, status=410, start=datetime.now(timezone.utc) + timedelta(seconds=1))
        db.commit()
    verified = client.post(f"/remediation/{block['id']}/verify", headers=analyst).json()
    assert verified["status"] == "VERIFIED", verified
    assert "410" in verified["verification_note"]

    rolled = client.post(f"/remediation/{block['id']}/rollback", headers=admin_headers).json()
    assert rolled["status"] == "ROLLED_BACK" and rolled["gateway"]["rules"] == 0
    assert "location" not in (rules_dir / gateway.LOCATIONS_FILE).read_text()
    audit = client.get("/audit", headers=admin_headers).json()
    assert {"remediation.approve", "remediation.apply", "remediation.verify", "remediation.rollback"} <= {e["action"] for e in audit}
