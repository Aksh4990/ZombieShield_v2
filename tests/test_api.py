import json
import time
from datetime import datetime, timedelta, timezone

from app.services import decision
from app.models import LifecycleState
from conftest import _TMP, login


def write_log(lines: list[tuple[str, str, int]]) -> str:
    now = datetime.now(timezone.utc)
    path = _TMP / "gateway.log"
    with path.open("w") as handle:
        for index, (method, uri, status) in enumerate(lines):
            ts = (now - timedelta(minutes=len(lines) - index)).isoformat()
            handle.write(json.dumps({"ts": ts, "client": f"10.0.0.{index % 7}", "method": method, "uri": uri, "status": status, "auth": "1", "service": "shop"}) + "\n")
    return str(path)


def run_pipeline(client, headers) -> dict:
    run = client.post("/pipeline/run", headers=headers, json={"logs_from_start": True})
    assert run.status_code == 202, run.text
    for _ in range(200):
        state = client.get(f"/pipeline/runs/{run.json()['id']}", headers=headers).json()
        if state["status"] in {"SUCCEEDED", "FAILED"}:
            return state
        time.sleep(0.1)
    raise AssertionError("pipeline did not finish")


def test_health_and_authentication(client):
    assert client.get("/health").json() == {"status": "healthy"}
    assert client.get("/apis").status_code == 401
    assert client.post("/auth/login", json={"username": "analyst", "password": "wrong"}).status_code == 401
    viewer_free = login(client)
    assert client.get("/auth/me", headers=viewer_free).json()["role"] == "analyst"


def test_roles_are_enforced(client, analyst, admin_headers):
    assert client.get("/audit", headers=analyst).status_code == 403
    created = client.post("/users", headers=admin_headers, json={"username": "viewer1", "password": "viewer-password-1", "role": "viewer"})
    assert created.status_code == 201
    viewer = login(client, "viewer1", "viewer-password-1")
    assert client.get("/apis", headers=viewer).status_code == 200
    assert client.post("/sources", headers=viewer, json={"name": "x", "kind": "git", "location": "shop"}).status_code == 403
    assert any(row["action"] == "user.create" for row in client.get("/audit", headers=admin_headers).json())


def test_git_source_must_stay_inside_discovery_root(client, analyst):
    for location in ("../outside", "/etc"):
        assert client.post("/sources", headers=analyst, json={"name": location, "kind": "git", "location": location}).status_code == 400


def test_full_pipeline_finds_zombie_shadow_and_deprecated(client, analyst, shop_repo):
    log = write_log([("GET", "/v2/customers/7", 200)] * 5 + [("GET", "/v1/customers/7", 200)] * 4 + [("GET", "/internal/export", 200)] * 3
                    + [("GET", "/admin.php", 404)] * 6 + [("GET", "/v2/legacy-report", 200)] * 2)
    assert client.post("/sources", headers=analyst, json={"name": "shop", "kind": "git", "location": "shop", "service_name": "shop", "host": "shop.test"}).status_code == 201
    assert client.post("/sources", headers=analyst, json={"name": "gw", "kind": "runtime_log", "location": log, "service_name": "shop", "host": "shop.test"}).status_code == 201
    state = run_pipeline(client, analyst)
    assert state["status"] == "SUCCEEDED", state["error"]
    statuses = {stage["key"]: stage["status"] for stage in state["stages"]}
    assert statuses["controls"] == statuses["risk"] == statuses["remediation"] == "SKIPPED"
    assert statuses["decisions"] == "SUCCEEDED"

    apis = {(a["http_method"], a["endpoint_path"]): a for a in client.get("/apis", headers=analyst).json()}
    assert apis[("GET", "/v1/customers/{id}")]["lifecycle_state"] == "ZOMBIE"
    assert apis[("GET", "/internal/export")]["lifecycle_state"] == "SHADOW"
    assert apis[("GET", "/v2/legacy-report")]["lifecycle_state"] == "DEPRECATED"
    assert apis[("GET", "/v2/customers/{id}")]["lifecycle_state"] == "ACTIVE"
    assert ("GET", "/admin.php") not in apis  # 404 probes never enter the inventory

    zombie = client.get(f"/apis/{apis[('GET', '/v1/customers/{id}')]['id']}", headers=analyst).json()
    kinds = [event["kind"] for event in zombie["evidence"]]
    assert "removed_in_git" in kinds and "runtime_seen" in kinds
    assert "Replace v1 customers API with v2" in zombie["classification_reason"]
    assert zombie["decision"]["action"] == "REMEDIATE"
    summary = client.get("/dashboard/summary", headers=analyst).json()
    assert summary["lifecycle"]["ZOMBIE"] == 1 and summary["lifecycle"]["SHADOW"] == 1
    graph = client.get("/graph", headers=analyst).json()
    assert any(node["id"] == "svc:shop" for node in graph["nodes"])


def test_second_concurrent_run_is_rejected(client, analyst):
    from app.db.session import SessionLocal
    from app.models import PipelineRun
    with SessionLocal() as db:
        db.add(PipelineRun(status="RUNNING", triggered_by="someone", stages=[]))
        db.commit()
    assert client.post("/pipeline/run", headers=analyst, json={}).status_code == 409


def test_decision_policy_without_risk_score():
    class Stub:
        risk_score = None
        kev_count = 1
        vulnerability_count = 1
        lifecycle_state = LifecycleState.ACTIVE
        in_runtime = True
        request_count = 3
        in_current_code = True
        in_current_spec = True
    action, reason = decision.decide(Stub())
    assert action == "ESCALATE" and "Known Exploited" in reason


def test_validation_scores_against_ground_truth(client, analyst, shop_repo):
    log = write_log([("GET", "/v1/customers/7", 200)] * 3 + [("GET", "/internal/export", 200)] * 2 + [("GET", "/v2/customers/1", 200)])
    client.post("/sources", headers=analyst, json={"name": "shop", "kind": "git", "location": "shop", "service_name": "shop", "host": "shop.test"})
    client.post("/sources", headers=analyst, json={"name": "gw", "kind": "runtime_log", "location": log, "service_name": "shop", "host": "shop.test"})
    assert run_pipeline(client, analyst)["status"] == "SUCCEEDED"
    truth = {"name": "test", "endpoints": [
        {"service": "shop", "method": "GET", "path": "/v1/customers/{customerId}", "expected": "ZOMBIE"},
        {"service": "shop", "method": "GET", "path": "/internal/export", "expected": "SHADOW"},
        {"service": "shop", "method": "GET", "path": "/v2/customers/{id}", "expected": "ACTIVE"},
        {"service": "shop", "method": "GET", "path": "/health", "expected": "DEPRECATED"},
        {"service": "shop", "method": "GET", "path": "/never-seen", "expected": "ACTIVE"},
    ]}
    result = client.post("/validation/run", headers=analyst, json=truth)
    assert result.status_code == 200, result.text
    metrics = result.json()["metrics"]
    assert metrics["endpoints"] == 5 and metrics["not_found"] == 1
    assert metrics["unmanaged_zombie_or_shadow"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 2, "fp": 0, "fn": 0}
    assert metrics["accuracy"] == 0.6
    assert client.post("/validation/run", headers=analyst, json={"endpoints": [{"service": "x", "method": "GET", "path": "/", "expected": "MAYBE"}]}).status_code == 422
    assert len(client.get("/validation/runs", headers=analyst).json()) == 1
