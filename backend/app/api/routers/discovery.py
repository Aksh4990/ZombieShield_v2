import uuid
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, analyst, audit, viewer
from app.models import Source
from app.schemas import DiscoveryResponse, GitScan, LogUpload, OpenAPIUpload, SourceCreate, SourceRead
from app.services import traffic
from app.services.discovery.runner import DiscoveryError, ingest_spec_text, resolve_repository, run_git_source, run_source
from app.services.inventory import InventoryWriter

router = APIRouter(tags=["discovery"])


# ---- configured sources
@router.get("/sources", response_model=list[SourceRead])
def list_sources(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[Source]:
    return list(db.scalars(select(Source).order_by(Source.kind, Source.name)))


@router.post("/sources", response_model=SourceRead, status_code=201)
def create_source(payload: SourceCreate, db: Session = DB, user: CurrentUser = Depends(analyst)) -> Source:
    if db.scalar(select(Source).where(Source.name == payload.name)):
        raise HTTPException(409, "A source with this name already exists")
    if payload.kind == "git":
        try:
            resolve_repository(payload.location)
        except DiscoveryError as exc:
            raise HTTPException(400, str(exc)) from exc
    source = Source(**payload.model_dump())
    db.add(source)
    audit(db, user, "source.create", "source", payload.name, kind=payload.kind, location=payload.location)
    db.commit()
    return source


@router.put("/sources/{source_id}", response_model=SourceRead)
def update_source(source_id: uuid.UUID, payload: SourceCreate, db: Session = DB, user: CurrentUser = Depends(analyst)) -> Source:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    for field, value in payload.model_dump().items():
        setattr(source, field, value)
    audit(db, user, "source.update", "source", str(source_id))
    db.commit()
    return source


@router.delete("/sources/{source_id}", status_code=204)
def delete_source(source_id: uuid.UUID, db: Session = DB, user: CurrentUser = Depends(analyst)) -> None:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    db.delete(source)
    audit(db, user, "source.delete", "source", str(source_id), name=source.name)
    db.commit()


@router.post("/sources/{source_id}/run", response_model=DiscoveryResponse)
def run_one_source(source_id: uuid.UUID, db: Session = DB, user: CurrentUser = Depends(analyst)) -> DiscoveryResponse:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    writer = InventoryWriter(db)
    results = run_source(db, source, writer)
    writer.commit()
    audit(db, user, "source.run", "source", str(source_id))
    db.commit()
    return DiscoveryResponse(results=[r.as_dict() for r in results], apis_added=writer.added)


# ---- ad-hoc uploads (useful for demos and tests)
@router.post("/discovery/openapi", response_model=DiscoveryResponse)
def upload_openapi(payload: OpenAPIUpload, db: Session = DB, user: CurrentUser = Depends(analyst)) -> DiscoveryResponse:
    writer = InventoryWriter(db)
    try:
        result = ingest_spec_text(db, writer, payload.document, name=payload.name, organization=payload.organization,
                                  host=payload.host, service_name=payload.service_name)
    except DiscoveryError as exc:
        raise HTTPException(422, str(exc)) from exc
    writer.commit()
    audit(db, user, "discovery.openapi", "source", payload.name)
    db.commit()
    return DiscoveryResponse(results=[result.as_dict()], apis_added=writer.added)


@router.post("/discovery/git", response_model=DiscoveryResponse)
def scan_git(payload: GitScan, db: Session = DB, user: CurrentUser = Depends(analyst)) -> DiscoveryResponse:
    try:
        resolve_repository(payload.repository_path)
    except DiscoveryError as exc:
        raise HTTPException(400, str(exc)) from exc
    source = SimpleNamespace(name=payload.name, location=payload.repository_path, organization=payload.organization, host=payload.host,
                             service_name=payload.service_name, options={"mine_history": payload.mine_history})
    writer = InventoryWriter(db)
    results = run_git_source(db, writer, source)
    writer.commit()
    audit(db, user, "discovery.git", "source", payload.repository_path)
    db.commit()
    return DiscoveryResponse(results=[r.as_dict() for r in results], apis_added=writer.added)


@router.post("/discovery/runtime-log", response_model=DiscoveryResponse)
def upload_log(payload: LogUpload, db: Session = DB, user: CurrentUser = Depends(analyst)) -> DiscoveryResponse:
    writer = InventoryWriter(db)
    stats = traffic.ingest_log_content(db, writer, payload.log_content, source_name=payload.name, organization=payload.organization,
                                       host=payload.host, default_service=payload.service_name or "runtime-service")
    writer.commit()
    traffic.refresh_aggregates(db)
    audit(db, user, "discovery.runtime_log", "source", payload.name, records=stats["records"])
    db.commit()
    return DiscoveryResponse(results=[{"source": payload.name, "kind": "runtime_log", **stats}], apis_added=writer.added)
