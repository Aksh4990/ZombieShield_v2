"""One-click pipeline: runs every stage in order in a background thread and records progress.

Extension slots
---------------
Three stages are left for the project team to implement. Create the module and expose
`run(db: Session) -> dict` (a JSON-serialisable summary); the pipeline picks it up
automatically and otherwise marks the stage SKIPPED:

  app/services/controls.py     security-control evidence per API   (runs before risk)
  app/services/risk.py         risk score + breakdown per API      (runs before decisions)
  app/services/remediation.py  remediation proposals               (runs after decisions)

Each module receives an open SQLAlchemy session; the pipeline commits after each stage.
"""

import importlib
import logging
import threading
import traceback
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import PipelineRun, Source
from app.services import decision, lifecycle, traffic
from app.services.discovery.runner import run_source
from app.services.inventory import InventoryWriter
from app.services.ml import anomaly, endpoint_model
from app.services.threat_intel import service as threat_intel

log = logging.getLogger(__name__)
_lock = threading.Lock()

EXTENSION_SLOTS = {"controls": "app.services.controls", "risk": "app.services.risk", "remediation": "app.services.remediation"}


def extension(name: str) -> Callable[[Session], dict] | None:
    try:
        module = importlib.import_module(EXTENSION_SLOTS[name])
    except ModuleNotFoundError as exc:
        if exc.name == EXTENSION_SLOTS[name]:
            return None
        raise
    runner = getattr(module, "run", None)
    return runner if callable(runner) else None


def _discover(db: Session, options: dict) -> dict:
    writer = InventoryWriter(db)
    results = []
    sources = list(db.scalars(select(Source).where(Source.enabled.is_(True))))
    # specs and code first so runtime paths can be matched to known templates
    order = {"openapi": 0, "git": 1, "sbom": 2, "runtime_log": 3}
    for source in sorted(sources, key=lambda s: order.get(s.kind, 9)):
        kwargs = {"from_start": bool(options.get("logs_from_start"))} if source.kind == "runtime_log" else {}
        results.extend(r.as_dict() for r in run_source(db, source, writer, **kwargs))
    writer.commit()
    traffic.refresh_aggregates(db)
    return {"sources": len(sources), "apis_added": writer.added, "results": results}


def _lifecycle(db: Session, options: dict) -> dict:
    return lifecycle.classify_inventory(db, get_settings().lifecycle_activity_window_days)


def _endpoint_ml(db: Session, options: dict) -> dict:
    if not endpoint_model.available():
        return {"status": "SKIPPED", "note": "endpoint model artifact not available"}
    return {"scored": endpoint_model.score_inventory(db)}


def _threat_intel(db: Session, options: dict) -> dict:
    return threat_intel.correlate(db)


def _anomaly(db: Session, options: dict) -> dict:
    return anomaly.detect(db, window_seconds=get_settings().anomaly_window_seconds)


def _slot(name: str):
    def stage(db: Session, options: dict) -> dict:
        runner = extension(name)
        if runner is None:
            return {"status": "SKIPPED", "note": f"{EXTENSION_SLOTS[name]} not implemented yet (see app/services/pipeline.py)"}
        return runner(db) or {}
    return stage


def _decisions(db: Session, options: dict) -> dict:
    return decision.run(db)


STAGES: list[tuple[str, str, Callable]] = [
    ("discovery", "Discovery & inventory", _discover),
    ("endpoint_ml", "Endpoint intelligence (ML)", _endpoint_ml),
    ("lifecycle", "Lifecycle classification", _lifecycle),
    ("threat_intel", "Threat intelligence", _threat_intel),
    ("anomaly", "Traffic anomaly detection (ML)", _anomaly),
    ("controls", "Security-control evidence", _slot("controls")),
    ("risk", "Risk assessment", _slot("risk")),
    ("decisions", "Decisions", _decisions),
    ("remediation", "Remediation", _slot("remediation")),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_run(db: Session, user: str, options: dict | None = None) -> PipelineRun:
    run = PipelineRun(triggered_by=user, options=options or {}, status="QUEUED",
                      stages=[{"key": key, "name": name, "status": "PENDING"} for key, name, _ in STAGES])
    db.add(run)
    db.commit()
    return run


def execute(run_id: uuid.UUID) -> None:
    """Run all stages for an existing PipelineRun. Safe to call in a background thread."""
    if not _lock.acquire(blocking=False):
        with SessionLocal() as db:
            run = db.get(PipelineRun, run_id)
            run.status, run.error, run.finished_at = "FAILED", "Another pipeline run is already in progress", datetime.now(timezone.utc)
            db.commit()
        return
    try:
        with SessionLocal() as db:
            run = db.get(PipelineRun, run_id)
            run.status = "RUNNING"
            db.commit()
            summary = {}
            for index, (key, _name, function) in enumerate(STAGES):
                stages = [dict(stage) for stage in run.stages]
                stages[index].update(status="RUNNING", started_at=_now())
                run.stages = stages
                db.commit()
                try:
                    result = function(db, run.options or {})
                    db.commit()
                    status = result.pop("status", "SUCCEEDED") if isinstance(result, dict) else "SUCCEEDED"
                except Exception as exc:  # stage failure stops the run but is recorded
                    db.rollback()
                    log.exception("Pipeline stage %s failed", key)
                    stages = [dict(stage) for stage in run.stages]
                    stages[index].update(status="FAILED", finished_at=_now(), error=str(exc))
                    run.stages, run.status, run.error = stages, "FAILED", f"{key}: {exc}\n{traceback.format_exc(limit=3)}"
                    run.finished_at = datetime.now(timezone.utc)
                    db.commit()
                    return
                stages = [dict(stage) for stage in run.stages]
                stages[index].update(status=status, finished_at=_now(), result=result)
                run.stages = stages
                summary[key] = result
                db.commit()
            run.status, run.summary, run.finished_at = "SUCCEEDED", {k: v for k, v in summary.items() if k != "discovery"}, datetime.now(timezone.utc)
            db.commit()
    finally:
        _lock.release()


def start_in_background(run_id: uuid.UUID) -> threading.Thread:
    thread = threading.Thread(target=execute, args=(run_id,), name=f"pipeline-{run_id}", daemon=True)
    thread.start()
    return thread
