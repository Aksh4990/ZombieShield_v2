"""Batched inventory upserts with provenance (sources, current sources, evidence timeline)."""

import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import API, EvidenceEvent, LifecycleState
from app.services.discovery.code_routes import CodeRoute
from app.services.discovery.openapi import SpecOperation
from app.services.normalization import canonical_key, display_path, normalize_path, version_from_path


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass
class Observation:
    organization: str
    host: str
    service_name: str
    method: str
    path: str
    source_kind: str  # openapi | git | runtime_log | manual
    source_name: str
    observed_at: datetime | None = None
    spec: SpecOperation | None = None
    spec_version: str | None = None
    code: CodeRoute | None = None


class InventoryWriter:
    """Accumulates observations in one session and commits once (no per-row commits)."""

    def __init__(self, db: Session):
        self.db = db
        self.cache: dict[str, API] = {api.canonical_key: api for api in db.scalars(select(API))}
        self.added = 0
        self.updated = 0
        self._evidence_keys: set[tuple[uuid.UUID, str]] = set()
        for api_id, key in db.execute(select(EvidenceEvent.api_id, EvidenceEvent.dedupe_key).where(EvidenceEvent.dedupe_key.is_not(None))):
            self._evidence_keys.add((api_id, key))

    # -- helpers ---------------------------------------------------------
    def get_or_create(self, organization: str, host: str, service_name: str, method: str, path: str, when: datetime | None) -> tuple[API, bool]:
        key = canonical_key(organization, host, method, path)
        api = self.cache.get(key)
        if api is not None:
            return api, False
        when = as_utc(when) or datetime.now(timezone.utc)
        api = API(
            id=uuid.uuid4(), canonical_key=key, organization=organization, host=host.lower(), service_name=service_name,
            http_method=method.upper(), endpoint_path=normalize_path(path), display_path=display_path(path),
            version=version_from_path(path), sources=[], current_sources=[], spec_security=[], first_seen=when, last_seen=when,
            lifecycle_state=LifecycleState.ACTIVE, risk_breakdown=[], ml_explanation=[], owasp_categories=[], security_controls={},
            request_count=0, error_count=0, unauth_success_count=0, unique_clients=0, attack_request_count=0,
            anomalous_client_count=0, vulnerability_count=0, kev_count=0,
            in_current_spec=False, in_current_code=False, in_runtime=False, previously_in_spec=False, previously_in_code=False,
            spec_deprecated=False, is_registered=False, manually_deprecated=False, manually_removed=False,
        )
        self.db.add(api)
        self.cache[key] = api
        self.added += 1
        return api, True

    def add_evidence(self, api: API, kind: str, source: str, summary: str, details: dict | None = None, when: datetime | None = None, dedupe_key: str | None = None) -> None:
        if dedupe_key and (api.id, dedupe_key) in self._evidence_keys:
            return
        self.db.add(EvidenceEvent(api_id=api.id, kind=kind, source=source, summary=summary, details=details or {}, observed_at=as_utc(when) or datetime.now(timezone.utc), dedupe_key=dedupe_key))
        if dedupe_key:
            self._evidence_keys.add((api.id, dedupe_key))

    @staticmethod
    def _touch(api: API, when: datetime | None) -> None:
        when = as_utc(when)
        if when is None:
            return
        if when > as_utc(api.last_seen):
            api.last_seen = when
        if when < as_utc(api.first_seen):
            api.first_seen = when

    @staticmethod
    def refresh_flags(api: API) -> None:
        current = set(api.current_sources or [])
        api.in_current_spec = any(item.startswith("openapi:") for item in current)
        api.in_current_code = any(item.startswith("git:") for item in current)
        api.in_runtime = any(item.startswith("runtime_log:") for item in api.sources or [])

    # -- observations ----------------------------------------------------
    def observe(self, obs: Observation) -> API:
        api, created = self.get_or_create(obs.organization, obs.host, obs.service_name, obs.method, obs.path, obs.observed_at)
        if not created:
            self.updated += 1
        tag = f"{obs.source_kind}:{obs.source_name}"
        if tag not in (api.sources or []):
            api.sources = [*(api.sources or []), tag]
        if obs.source_kind in {"openapi", "git"} and tag not in (api.current_sources or []):
            api.current_sources = [*(api.current_sources or []), tag]
        if api.service_name in {"runtime-service", "unknown-service"} and obs.service_name not in {"runtime-service", "unknown-service"}:
            api.service_name = obs.service_name
        if obs.spec is not None:
            api.display_path = display_path(obs.spec.path)
            api.spec_deprecated = obs.spec.deprecated
            api.spec_security = obs.spec.security if obs.spec.security_declared else ["(not declared)"]
            api.spec_version = obs.spec_version
            api.is_registered = True
            self.add_evidence(api, "spec_seen", obs.source_name,
                              f"Documented in specification '{obs.source_name}'" + (f" (version {obs.spec_version})" if obs.spec_version not in (None, "unversioned") else "") + (" and marked deprecated" if obs.spec.deprecated else ""),
                              {"deprecated": obs.spec.deprecated, "security": obs.spec.security, "summary": obs.spec.summary}, obs.observed_at,
                              dedupe_key=f"spec:{obs.source_name}:{obs.spec.deprecated}")
        if obs.code is not None:
            api.code_location = f"{obs.code.file}:{obs.code.line}"
            self.add_evidence(api, "code_seen", obs.source_name, f"Route defined in source code at {obs.code.file}:{obs.code.line} ({obs.code.framework})",
                              {"file": obs.code.file, "line": obs.code.line, "framework": obs.code.framework, "note": obs.code.note}, obs.observed_at,
                              dedupe_key=f"code:{obs.source_name}:{obs.code.file}")
        self._touch(api, obs.observed_at)
        self.refresh_flags(api)
        return api

    def finish_source(self, kind: str, source_name: str, seen_ids: set[uuid.UUID]) -> int:
        """APIs this source no longer reports lose their 'current' status for that source."""
        tag = f"{kind}:{source_name}"
        dropped = 0
        for api in self.cache.values():
            if tag in (api.current_sources or []) and api.id not in seen_ids:
                api.current_sources = [item for item in api.current_sources if item != tag]
                if kind == "openapi":
                    api.previously_in_spec = True
                else:
                    api.previously_in_code = True
                self.add_evidence(api, "removed_from_source", source_name,
                                  f"No longer present in {'specification' if kind == 'openapi' else 'source code'} '{source_name}'",
                                  dedupe_key=f"dropped:{tag}:{date.today().isoformat()}")
                self.refresh_flags(api)
                dropped += 1
        return dropped

    def commit(self) -> None:
        self.db.commit()
