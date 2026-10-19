from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.models import LifecycleState
from app.services.discovery.git_history import mine_history
from app.services.lifecycle import LifecycleClassifier

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def api(**overrides):
    base = dict(in_current_spec=False, in_current_code=False, in_runtime=False, previously_in_code=False, previously_in_spec=False,
                spec_deprecated=False, manually_deprecated=False, manually_removed=False, removal_note=None, request_count=0,
                last_runtime_seen=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def classify(item, superseded=None):
    return LifecycleClassifier(30).classify(item, NOW, superseded).state


def test_lifecycle_rules():
    recent = NOW - timedelta(days=1)
    assert classify(api(previously_in_code=True, in_runtime=True, request_count=5, last_runtime_seen=recent)) == LifecycleState.ZOMBIE
    assert classify(api(previously_in_code=True)) == LifecycleState.DECOMMISSIONED
    assert classify(api(in_runtime=True, request_count=3, last_runtime_seen=recent)) == LifecycleState.SHADOW
    assert classify(api(in_current_spec=True, spec_deprecated=True)) == LifecycleState.DEPRECATED
    assert classify(api(in_current_spec=True, spec_deprecated=True, in_runtime=True, request_count=9, last_runtime_seen=recent), "/v2/x") == LifecycleState.ZOMBIE
    assert classify(api(in_current_code=True)) == LifecycleState.ACTIVE
    stale = NOW - timedelta(days=90)
    assert classify(api(in_runtime=True, request_count=1, last_runtime_seen=stale)) == LifecycleState.ACTIVE  # weak evidence -> unchanged


def test_git_history_finds_retired_route(shop_repo):
    history = mine_history(shop_repo)
    assert len(history.commits) == 2
    removed = {(item.method, item.path): item for item in history.removed_routes}
    assert ("GET", "/v1/customers/{id}") in removed
    assert removed[("GET", "/v1/customers/{id}")].removed_commit.subject == "Replace v1 customers API with v2"
    assert ("GET", "/v1/customers/{id}") in {(i.method, i.path) for i in history.removed_spec_operations}
    assert history.routes[("GET", "/health")].present_at_head
