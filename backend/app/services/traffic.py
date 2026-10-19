"""Runtime traffic ingestion with data minimisation, plus traffic aggregates."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import hash_client
from app.models import API, RequestLog
from app.services.discovery.logs import parse_lines
from app.services.inventory import InventoryWriter, as_utc
from app.services.ml import payload_model
from app.services.normalization import template_runtime_path

# Responses that prove a route exists (or existed and is now blocked). 404 probes are kept out of the
# inventory so a directory-bruteforce scan cannot fill it with fake "shadow APIs".
_EXISTENCE_STATUSES = set(range(200, 400)) | {400, 401, 403, 405, 409, 410, 415, 422, 429} | set(range(500, 600))


def _known_templates(writer: InventoryWriter) -> dict[tuple[str, str], list[str]]:
    by_host: dict[tuple[str, str], list[str]] = defaultdict(list)
    for api in writer.cache.values():
        if api.in_current_spec or api.in_current_code or api.previously_in_code or api.previously_in_spec:
            by_host[(api.host, api.http_method)].append(api.endpoint_path)
    for templates in by_host.values():
        templates.sort(key=lambda t: (t.count("{id}"), -len(t)))
    return by_host


def ingest_log_content(db: Session, writer: InventoryWriter, content: str, *, source_name: str, organization: str, host: str, default_service: str) -> dict:
    records, skipped = parse_lines(content)
    templates = _known_templates(writer)
    classifier = payload_model.get_classifier()
    stats = {"records": len(records), "skipped": skipped, "new_apis": 0, "attacks": 0, "ignored_404": 0}
    before = writer.added
    tag = f"runtime_log:{source_name}"
    now = datetime.now(timezone.utc)
    rows = []
    for record in records:
        ts = as_utc(record.ts) or now
        record_host = host or record.host or "api.local"
        template, raw_id = template_runtime_path(record.path, templates.get((record_host.lower(), record.method)))
        label, score = (None, None)
        if classifier is not None:
            label, score = classifier.classify(record.path, record.query)
            if label != "normal":
                stats["attacks"] += 1
        api = None
        if record.status in _EXISTENCE_STATUSES:
            api, created = writer.get_or_create(organization, record_host, record.service or default_service, record.method, template, ts)
            if tag not in (api.sources or []):
                api.sources = [*(api.sources or []), tag]
                writer.refresh_flags(api)
            if api.service_name in {"runtime-service", "unknown-service"} and record.service:
                api.service_name = record.service
            if ts > as_utc(api.last_seen):
                api.last_seen = ts
            if api.last_runtime_seen is None or ts > as_utc(api.last_runtime_seen):
                api.last_runtime_seen = ts
            if ts < as_utc(api.first_seen):
                api.first_seen = ts
            api.request_count = (api.request_count or 0) + 1
            if record.status >= 400:
                api.error_count = (api.error_count or 0) + 1
            if record.authenticated is False and 200 <= record.status < 300:
                api.unauth_success_count = (api.unauth_success_count or 0) + 1
            if label not in (None, "normal"):
                api.attack_request_count = (api.attack_request_count or 0) + 1
            writer.add_evidence(api, "runtime_seen", source_name, f"Observed in runtime traffic ({source_name})",
                                {"status": record.status}, ts, dedupe_key=f"runtime:{source_name}:{ts.date().isoformat()}")
        else:
            stats["ignored_404"] += 1
        rows.append(RequestLog(
            ts=ts, api_id=api.id if api is not None else None, method=record.method, path=template, status=record.status,
            latency_ms=record.latency_ms, bytes_sent=record.bytes_sent, client_hash=hash_client(record.client),
            authenticated=record.authenticated, service_name=(api.service_name if api else record.service or default_service),
            raw_id=raw_id[:100] if raw_id else None, payload_score=score, payload_label=label, source_name=source_name,
        ))
    db.add_all(rows)
    stats["new_apis"] = writer.added - before
    return stats


def refresh_aggregates(db: Session) -> None:
    counts = dict(db.execute(
        select(RequestLog.api_id, func.count(func.distinct(RequestLog.client_hash))).where(RequestLog.api_id.is_not(None)).group_by(RequestLog.api_id)
    ).all())
    for api in db.scalars(select(API)):
        api.unique_clients = int(counts.get(api.id, 0))


def recent_requests(db: Session, limit: int = 100, after_id: int | None = None) -> list[RequestLog]:
    statement = select(RequestLog).order_by(RequestLog.id.desc()).limit(limit)
    if after_id is not None:
        statement = select(RequestLog).where(RequestLog.id > after_id).order_by(RequestLog.id.asc()).limit(limit)
    return list(db.scalars(statement))


def timeseries(db: Session, minutes: int = 60, bucket_seconds: int = 60) -> list[dict]:
    latest = db.scalar(select(func.max(RequestLog.ts)))
    if latest is None:
        return []
    latest = as_utc(latest)
    since = latest - timedelta(minutes=minutes)
    rows = db.execute(select(RequestLog.ts, RequestLog.status, RequestLog.payload_label, RequestLog.api_id).where(RequestLog.ts >= since)).all()
    lifecycle = dict(db.execute(select(API.id, API.lifecycle_state)).all())
    buckets: dict[int, dict] = {}
    for ts, status, label, api_id in rows:
        key = int(as_utc(ts).timestamp()) // bucket_seconds * bucket_seconds
        bucket = buckets.setdefault(key, {"t": datetime.fromtimestamp(key, tz=timezone.utc).isoformat(), "total": 0, "errors": 0, "attacks": 0, "zombie": 0, "shadow": 0, "probes": 0})
        bucket["total"] += 1
        if status >= 400:
            bucket["errors"] += 1
        if status == 404:
            bucket["probes"] += 1
        if label not in (None, "normal"):
            bucket["attacks"] += 1
        state = lifecycle.get(api_id)
        if state is not None and state.value == "ZOMBIE":
            bucket["zombie"] += 1
        if state is not None and state.value == "SHADOW":
            bucket["shadow"] += 1
    return [buckets[key] for key in sorted(buckets)]
