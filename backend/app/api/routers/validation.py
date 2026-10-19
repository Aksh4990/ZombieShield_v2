from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, analyst, audit, viewer
from app.models import ValidationRun
from app.services.validation import GroundTruthError, validate

router = APIRouter(tags=["validation"])


def _read(run: ValidationRun) -> dict:
    return {"id": str(run.id), "at": run.at.isoformat(), "ground_truth": run.ground_truth, "metrics": run.metrics, "details": run.details}


@router.post("/validation/run")
def run_validation(truth: dict, db: Session = DB, user: CurrentUser = Depends(analyst)) -> dict:
    """Body: the ground-truth JSON (see sockshop/ground_truth.template.json)."""
    try:
        run = validate(db, truth)
    except GroundTruthError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, user, "validation.run", "validation_run", str(run.id), endpoints=run.metrics["endpoints"])
    db.commit()
    return _read(run)


@router.get("/validation/runs")
def list_runs(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[dict]:
    return [_read(run) for run in db.scalars(select(ValidationRun).order_by(ValidationRun.at.desc()).limit(20))]
