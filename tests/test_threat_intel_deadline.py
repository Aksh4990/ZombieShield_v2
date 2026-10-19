"""Feed calls must respect a wall-clock budget, and a restart must not leave a pipeline run stuck."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from app.core.config import get_settings
from app.services.threat_intel import feeds


class _Trickle(BaseHTTPRequestHandler):
    """Answers 200 and then sends one byte every 0.2 s for a minute: never idle long enough for httpx's read timeout."""

    def _trickle(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            for _ in range(300):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = _trickle

    def log_message(self, *args):
        pass


@pytest.fixture
def trickle_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Trickle)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_fetch_gives_up_at_the_deadline_even_when_bytes_keep_arriving(trickle_url):
    started = time.monotonic()
    with httpx.Client() as client, pytest.raises(httpx.TimeoutException):
        feeds.fetch(client, "GET", trickle_url + "/feed.json", feeds.deadline(1.0))
    assert time.monotonic() - started < 3


def test_fetch_gives_up_when_dns_never_answers(monkeypatch):
    import socket

    real = socket.getaddrinfo

    def hanging(host, *args, **kwargs):
        if host == "feeds.example.test":
            time.sleep(30)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", hanging)
    started = time.monotonic()
    with httpx.Client(trust_env=False) as client, pytest.raises(httpx.TimeoutException, match="DNS or network stall"):  # no proxy: resolve locally
        feeds.fetch(client, "GET", "https://feeds.example.test/kev.json", feeds.deadline(1.0))
    assert time.monotonic() - started < 3


def test_slow_feeds_fall_back_to_offline_cache_quickly(trickle_url, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "threat_intel_mode", "auto")
    monkeypatch.setattr(settings, "threat_intel_timeout_seconds", 1.5)
    monkeypatch.setattr(settings, "osv_api_url", trickle_url + "/v1")
    monkeypatch.setattr(settings, "kev_feed_url", trickle_url + "/kev.json")
    monkeypatch.setattr(settings, "epss_api_url", trickle_url + "/epss")
    from app.db.session import SessionLocal
    from app.models import Source
    from app.services.threat_intel import service

    with SessionLocal() as db:
        db.add(Source(name="none", kind="sbom", location="/nonexistent", enabled=True))  # no packages needed for the KEV path
        db.commit()
        monkeypatch.setattr(service, "collect_components", lambda _db: [])
        started = time.monotonic()
        with httpx.Client() as client, pytest.raises(httpx.TimeoutException):
            feeds.fetch(client, "POST", settings.osv_api_url + "/querybatch", feeds.deadline(), json={"queries": []})
        result = service.correlate(db)
        assert time.monotonic() - started < 8
        assert result["components"] == 0


def test_interrupted_runs_are_failed_on_startup(client, analyst):
    from app.db.session import SessionLocal
    from app.models import PipelineRun
    from app.services import bootstrap

    with SessionLocal() as db:
        db.add(PipelineRun(status="RUNNING", triggered_by="someone",
                           stages=[{"key": "discovery", "status": "SUCCEEDED"}, {"key": "threat_intel", "status": "RUNNING"}]))
        db.commit()
    assert client.post("/pipeline/run", headers=analyst, json={}).status_code == 409
    assert bootstrap.recover_interrupted_runs() == 1
    with SessionLocal() as db:
        run = db.query(PipelineRun).filter_by(triggered_by="someone").one()
        assert run.status == "FAILED" and "restarted" in run.error
        assert run.stages[1]["status"] == "FAILED" and run.stages[0]["status"] == "SUCCEEDED"
    assert client.post("/pipeline/run", headers=analyst, json={}).status_code == 202


def test_correlate_stores_new_vulnerabilities_before_their_findings(monkeypatch, tmp_path):
    """Regression: on PostgreSQL the findings were inserted before the vulnerabilities they reference."""
    import json
    import shutil
    from pathlib import Path

    from app.db.session import SessionLocal
    from app.models import Component, ThreatFinding, Vulnerability
    from app.services.threat_intel import service

    settings = get_settings()
    cache = tmp_path / "cache"
    shutil.copytree(Path(__file__).resolve().parents[1] / "backend" / "data" / "threat_cache", cache)
    monkeypatch.setattr(settings, "threat_cache_dir", str(cache))
    monkeypatch.setattr(settings, "threat_intel_mode", "offline")
    feeds._offline_index.cache_clear()
    index = json.loads((cache / "osv_index.json").read_text())
    assert index["npm:morgan"]  # the bundled Sock Shop cache knows morgan advisories

    with SessionLocal() as db:
        components = [Component(service_name="front-end", ecosystem="npm", name=name, version=version, purl=f"pkg:npm/{name}@{version}", manifest="package.json")
                      for name, version in (("morgan", "1.7.0"), ("express", "4.13.4"), ("async", "2.0.1"))]
        db.add_all(components)
        db.commit()
        monkeypatch.setattr(service, "collect_components", lambda _db: components)
        result = service.correlate(db)
        db.commit()
        assert result["findings"] >= 2 and result["feed"].startswith("offline")
        assert db.query(ThreatFinding).count() == result["findings"]
        assert {f.vulnerability_id for f in db.query(ThreatFinding)} <= {v.id for v in db.query(Vulnerability)}
        again = service.correlate(db)  # re-running with existing vulnerabilities must also work
        db.commit()
        assert again["findings"] == result["findings"]
    feeds._offline_index.cache_clear()


def test_failed_stage_with_huge_error_is_recorded(monkeypatch):
    from app.db.session import SessionLocal
    from app.models import PipelineRun
    from app.services import pipeline

    def explode(db, options):
        raise RuntimeError("x" * 20000)  # e.g. a database error that embeds a whole INSERT statement

    assert pipeline._lock.acquire(timeout=120)  # let any run started by an earlier test finish first
    pipeline._lock.release()
    monkeypatch.setattr(pipeline, "STAGES", [("boom", "Boom", explode)])
    with SessionLocal() as db:
        run = pipeline.create_run(db, "tester")
    pipeline.execute(run.id)
    with SessionLocal() as db:
        stored = db.get(PipelineRun, run.id)
        assert stored.status == "FAILED"
        assert len(stored.error) <= pipeline.RUN_ERROR_LIMIT and "truncated" in stored.error
        assert len(stored.stages[0]["error"]) <= pipeline.STAGE_ERROR_LIMIT
