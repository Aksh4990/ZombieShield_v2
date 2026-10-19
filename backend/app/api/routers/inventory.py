import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import DB, CurrentUser, analyst, audit, viewer
from app.models import API, Decision, LifecycleState
from app.schemas import APIDetail, APISummary, APIUpdate
from app.services.threat_intel.service import service_vulnerabilities

router = APIRouter(tags=["inventory"])
_SORTS = {
    "risk": (API.risk_score.desc().nulls_last(),), "last_seen": (API.last_seen.desc(),), "traffic": (API.request_count.desc(),),
    "path": (API.endpoint_path.asc(), API.http_method.asc()), "service": (API.service_name.asc(), API.endpoint_path.asc()),
}


@router.get("/apis", response_model=list[APISummary])
def list_apis(
    q: str | None = Query(default=None, max_length=200),
    lifecycle_state: LifecycleState | None = None,
    service: str | None = None,
    source_kind: str | None = Query(default=None, pattern=r"^(openapi|git|runtime_log)$"),
    method: str | None = None,
    sort: str = Query(default="risk", pattern=r"^(risk|last_seen|traffic|path|service)$"),
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = DB, _: CurrentUser = Depends(viewer),
) -> list[API]:
    statement = select(API)
    if q:
        like = f"%{q.lower()}%"
        statement = statement.where(or_(API.endpoint_path.ilike(like), API.display_path.ilike(like), API.service_name.ilike(like)))
    if lifecycle_state:
        statement = statement.where(API.lifecycle_state == lifecycle_state)
    if service:
        statement = statement.where(API.service_name == service)
    if method:
        statement = statement.where(API.http_method == method.upper())
    records = list(db.scalars(statement.order_by(*_SORTS[sort], API.endpoint_path).limit(limit)))
    if source_kind:
        records = [api for api in records if any(item.startswith(source_kind + ":") for item in api.sources or [])]
    return records


@router.get("/apis/{api_id}", response_model=APIDetail)
def get_api(api_id: uuid.UUID, db: Session = DB, _: CurrentUser = Depends(viewer)) -> dict:
    api = db.scalar(select(API).options(selectinload(API.evidence)).where(API.id == api_id))
    if api is None:
        raise HTTPException(404, "API not found")
    detail = APIDetail.model_validate(api).model_dump()
    detail["evidence"] = sorted(detail["evidence"], key=lambda item: item["observed_at"])
    detail["vulnerabilities"] = service_vulnerabilities(db, api.service_name)
    latest = db.scalar(select(Decision).where(Decision.api_id == api.id).order_by(Decision.decided_at.desc()).limit(1))
    detail["decision"] = latest
    return detail


@router.patch("/apis/{api_id}", response_model=APISummary)
def update_api(api_id: uuid.UUID, payload: APIUpdate, db: Session = DB, user: CurrentUser = Depends(analyst)) -> API:
    api = db.get(API, api_id)
    if api is None:
        raise HTTPException(404, "API not found")
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(api, field, value)
    audit(db, user, "api.update", "api", str(api_id), changes=changes)
    db.commit()
    return api


@router.get("/services")
def services(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[str]:
    return sorted(set(db.scalars(select(API.service_name))))
