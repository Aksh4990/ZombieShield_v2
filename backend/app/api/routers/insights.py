"""Read-only views: threat intel, traffic, anomalies, ML model cards, decisions, dashboard, graph, audit."""

from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, admin, viewer
from app.models import API, AnomalyEvent, AuditLog, Component, Decision, LifecycleState, PipelineRun, RemediationAction, RequestLog, ThreatFinding, Vulnerability
from app.schemas import AnomalyRead, AuditRead, ComponentRead, DecisionRead, RequestRead, VulnerabilityRead
from app.services import traffic
from app.services.ml import endpoint_model, payload_model

router = APIRouter(tags=["insights"])


@router.get("/threat-intel/components", response_model=list[ComponentRead])
def components(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[Component]:
    return list(db.scalars(select(Component).order_by(Component.service_name, Component.name)))


@router.get("/threat-intel/vulnerabilities")
def vulnerabilities(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[dict]:
    rows = db.execute(select(Vulnerability, Component).join(ThreatFinding, ThreatFinding.vulnerability_id == Vulnerability.id)
                      .join(Component, ThreatFinding.component_id == Component.id)).all()
    grouped: dict[str, dict] = {}
    for vuln, component in rows:
        item = grouped.setdefault(vuln.id, {**VulnerabilityRead.model_validate(vuln).model_dump(), "affected": []})
        item["affected"].append({"service": component.service_name, "component": component.name, "version": component.version, "ecosystem": component.ecosystem})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(grouped.values(), key=lambda v: (not v["in_kev"], order.get(v["severity"], 9), -(v["cvss_score"] or 0)))


@router.get("/traffic/recent", response_model=list[RequestRead])
def recent(limit: int = Query(default=100, le=500), after_id: int | None = None, db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[RequestLog]:
    return traffic.recent_requests(db, limit, after_id)


@router.get("/traffic/timeseries")
def timeseries(minutes: int = Query(default=60, le=1440), bucket_seconds: int = Query(default=60, ge=10, le=3600), db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[dict]:
    return traffic.timeseries(db, minutes, bucket_seconds)


@router.get("/traffic/anomalies", response_model=list[AnomalyRead])
def anomalies(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[AnomalyEvent]:
    return list(db.scalars(select(AnomalyEvent).order_by(AnomalyEvent.score.desc()).limit(200)))


@router.get("/ml/models")
def model_cards(_: CurrentUser = Depends(viewer)) -> dict:
    return {
        "payload": {"loaded": payload_model.get_classifier() is not None, "metrics": payload_model.metrics()},
        "endpoint": {"loaded": endpoint_model.available(), "metrics": endpoint_model.metrics()},
        "anomaly": {"loaded": True, "metrics": {"model": "IsolationForest (scikit-learn)", "training": "fitted on each pipeline run on a baseline period of the observed traffic",
                                                "features": ["requests", "distinct endpoints", "distinct object IDs", "404/401/403/5xx shares", "payload-classifier hits",
                                                             "unauthenticated share", "retired-endpoint share", "failed logins", "write share", "inter-arrival time"]}},
    }


@router.get("/decisions", response_model=list[DecisionRead])
def decisions(db: Session = DB, _: CurrentUser = Depends(viewer)) -> list[Decision]:
    return list(db.scalars(select(Decision).order_by(Decision.decided_at.desc())))


@router.get("/dashboard/summary")
def summary(db: Session = DB, _: CurrentUser = Depends(viewer)) -> dict:
    apis = list(db.scalars(select(API)))
    lifecycle = Counter(api.lifecycle_state.value for api in apis)
    sources = Counter(kind.split(":", 1)[0] for api in apis for kind in set(s.split(":", 1)[0] + ":" for s in api.sources or []))
    decisions_by_action = Counter(db.scalars(select(Decision.action)))
    services = defaultdict(lambda: Counter())
    for api in apis:
        services[api.service_name][api.lifecycle_state.value] += 1
    kev = db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True))) or 0
    vuln_count = db.scalar(select(func.count(func.distinct(ThreatFinding.vulnerability_id)))) or 0
    attention = sorted([api for api in apis if api.lifecycle_state in (LifecycleState.ZOMBIE, LifecycleState.SHADOW) or api.kev_count or (api.risk_score or 0) >= 50],
                       key=lambda a: (a.lifecycle_state != LifecycleState.ZOMBIE, -(a.risk_score or 0), -a.request_count))[:8]
    last_run = db.scalar(select(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(1))
    return {
        "total_apis": len(apis),
        "lifecycle": {state.value: lifecycle.get(state.value, 0) for state in LifecycleState},
        "by_source": {kind.rstrip(":"): count for kind, count in sources.items()},
        "undocumented_in_use": sum(1 for a in apis if a.in_runtime and not a.in_current_spec and a.lifecycle_state == LifecycleState.ACTIVE),
        "vulnerabilities": vuln_count, "kev_vulnerabilities": kev,
        "requests_observed": db.scalar(select(func.count()).select_from(RequestLog)) or 0,
        "payload_attacks": db.scalar(select(func.count()).select_from(RequestLog).where(RequestLog.payload_label.is_not(None), RequestLog.payload_label != "normal")) or 0,
        "anomalous_windows": db.scalar(select(func.count()).select_from(AnomalyEvent)) or 0,
        "decisions": dict(decisions_by_action),
        "risk_levels": dict(Counter(a.risk_level for a in apis if a.risk_level)),
        "remediation": dict(Counter(db.scalars(select(RemediationAction.status)))),
        "services": {name: dict(counts) for name, counts in sorted(services.items())},
        "attention": [{"id": str(a.id), "method": a.http_method, "path": a.display_path, "service": a.service_name, "state": a.lifecycle_state.value,
                       "reason": a.classification_reason, "requests": a.request_count, "kev": a.kev_count,
                       "risk_score": a.risk_score, "risk_level": a.risk_level} for a in attention],
        "last_run": {"id": str(last_run.id), "status": last_run.status, "started_at": last_run.started_at.isoformat(),
                     "finished_at": last_run.finished_at.isoformat() if last_run.finished_at else None} if last_run else None,
    }


@router.get("/graph")
def graph(db: Session = DB, _: CurrentUser = Depends(viewer)) -> dict:
    """Services -> endpoints, for the attack-surface view."""
    nodes, edges = [], []
    services: dict[str, int] = Counter()
    vulns_by_service = Counter(db.scalars(select(ThreatFinding.service_name)))
    for api in db.scalars(select(API)):
        services[api.service_name] += 1
        nodes.append({"id": str(api.id), "type": "endpoint", "label": f"{api.http_method} {api.display_path}", "service": api.service_name,
                      "state": api.lifecycle_state.value, "requests": api.request_count, "risk": api.risk_score})
        edges.append({"source": f"svc:{api.service_name}", "target": str(api.id)})
    nodes.extend({"id": f"svc:{name}", "type": "service", "label": name, "endpoints": count, "vulnerabilities": vulns_by_service.get(name, 0)}
                 for name, count in services.items())
    return {"nodes": nodes, "edges": edges}


@router.get("/audit", response_model=list[AuditRead])
def audit_log(limit: int = Query(default=200, le=1000), db: Session = DB, _: CurrentUser = Depends(admin)) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.at.desc()).limit(limit)))
