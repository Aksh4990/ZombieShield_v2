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
