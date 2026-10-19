"""Remediation proposals and the approval workflow for gateway rules.

Analysts can review, reject, verify and reopen; only administrators can approve, apply and roll back,
because those steps change what the gateway enforces.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, admin, analyst, audit, viewer
from app.models import API, RemediationAction
from app.schemas import RemediationRead, RemediationStep
from app.services import gateway, remediation

router = APIRouter(prefix="/remediation", tags=["remediation"])
_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _with_api(action: RemediationAction, api: API | None) -> dict:
    item = RemediationRead.model_validate(action).model_dump(mode="json")
    item["api"] = None if api is None else {"method": api.http_method, "path": api.display_path, "service": api.service_name,
                                            "host": api.host, "lifecycle_state": api.lifecycle_state.value, "risk_score": api.risk_score}
    return item


@router.get("")
def list_actions(status: str | None = Query(default=None, pattern=r"^[A-Z_]+$"), kind: str | None = Query(default=None, pattern=r"^[A-Z_]+$"),
                 api_id: uuid.UUID | None = None, db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[dict]:
    query = select(RemediationAction, API).join(API, RemediationAction.api_id == API.id)
    if status:
        query = query.where(RemediationAction.status == status)
    if kind:
        query = query.where(RemediationAction.kind == kind)
    if api_id:
        query = query.where(RemediationAction.api_id == api_id)
    rows = db.execute(query).all()
    rows.sort(key=lambda row: (_PRIORITY.get(row[0].priority, 9), -(row[1].risk_score or 0), row[0].kind))
    return [_with_api(action, api) for action, api in rows]


@router.get("/gateway-config")
def gateway_config(db: Session = DB, _: CurrentUser = Depends(viewer)) -> dict:
    """The nginx configuration that the currently applied rules produce (what `apply` writes)."""
    rows = db.execute(select(RemediationAction, API).join(API, RemediationAction.api_id == API.id)
                      .where(RemediationAction.status.in_(gateway.RENDERED_STATES))).all()
    rules = [remediation._renderable(action, api) for action, api in rows if gateway.host_allowed(api.host)]
    locations, maps = gateway.render(rules)
    return {"rules": len(rules), "files": {gateway.LOCATIONS_FILE: locations, gateway.MAPS_FILE: maps}}


@router.get("/{action_id}")
def get_action(action_id: uuid.UUID, db: Session = DB, _: CurrentUser = Depends(viewer)) -> dict:
    action = db.get(RemediationAction, action_id)
    if action is None:
        raise HTTPException(404, "Remediation action not found")
    return _with_api(action, db.get(API, action.api_id))


def _step(step: str, role):
    def handler(action_id: uuid.UUID, payload: RemediationStep | None = None, db: Session = DB, user: CurrentUser = Depends(role)) -> dict:
        action = db.get(RemediationAction, action_id)
        if action is None:
            raise HTTPException(404, "Remediation action not found")
        before = action.status
        try:
            result = remediation.transition(db, action, step, user.username, (payload or RemediationStep()).note)
        except remediation.WorkflowError as exc:
            raise HTTPException(409, str(exc)) from exc
        except gateway.UnsafeRule as exc:
            db.rollback()
            raise HTTPException(422, f"Rule cannot be rendered safely: {exc}") from exc
        except OSError as exc:
            db.rollback()
            raise HTTPException(500, f"Gateway rule files could not be written: {exc}") from exc
        audit(db, user, f"remediation.{step}", "remediation_action", str(action.id), kind=action.kind, before=before, after=action.status)
        db.commit()
        return {**_with_api(action, db.get(API, action.api_id)), **result}
    handler.__name__ = f"{step}_action"
    return handler


for _name, _role in (("approve", admin), ("reject", analyst), ("apply", admin), ("verify", analyst), ("rollback", admin), ("reopen", analyst)):
    router.add_api_route(f"/{{action_id}}/{_name}", _step(_name, _role), methods=["POST"], name=f"remediation_{_name}")
