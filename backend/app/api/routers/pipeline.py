import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, analyst, audit, viewer
from app.db.session import SessionLocal
from app.models import PipelineRun
from app.schemas import PipelineRunRead, PipelineRunRequest
from app.services import pipeline

router = APIRouter(tags=["pipeline"])


@router.post("/pipeline/run", response_model=PipelineRunRead, status_code=202)
def start(payload: PipelineRunRequest | None = None, db: Session = DB, user: CurrentUser = Depends(analyst)) -> PipelineRun:
    running = db.scalar(select(PipelineRun).where(PipelineRun.status.in_(["QUEUED", "RUNNING"])).limit(1))
    if running is not None:
        raise HTTPException(409, f"Pipeline run {running.id} is already in progress")
    run = pipeline.create_run(db, user.username, (payload or PipelineRunRequest()).model_dump())
    audit(db, user, "pipeline.run", "pipeline_run", str(run.id))
    db.commit()
    pipeline.start_in_background(run.id)
    return run


@router.get("/pipeline/runs", response_model=list[PipelineRunRead])
def runs(limit: int = 20, db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[PipelineRun]:
    return list(db.scalars(select(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(min(limit, 100))))


@router.get("/pipeline/runs/{run_id}", response_model=PipelineRunRead)
def get_run(run_id: uuid.UUID, db: Session = DB, _: CurrentUser = Depends(viewer)) -> PipelineRun:
    run = db.get(PipelineRun, run_id)
    if run is None:
        raise HTTPException(404, "Pipeline run not found")
    return run


@router.get("/pipeline/runs/{run_id}/stream")
async def stream(run_id: uuid.UUID, _: CurrentUser = Depends(viewer)) -> StreamingResponse:
    """Server-sent events with the run's stage list whenever it changes."""

    async def events():
        last = None
        for _ in range(3600):
            with SessionLocal() as db:
                run = db.get(PipelineRun, run_id)
                if run is None:
                    yield "event: error\ndata: {}\n\n"
                    return
                payload = PipelineRunRead.model_validate(run).model_dump_json()
            if payload != last:
                last = payload
                yield f"data: {payload}\n\n"
            if json.loads(payload)["status"] in {"SUCCEEDED", "FAILED"}:
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/pipeline/extensions")
def extensions(_: CurrentUser = Depends(viewer)) -> dict:
    return {name: {"module": module, "implemented": pipeline.extension(name) is not None} for name, module in pipeline.EXTENSION_SLOTS.items()}
