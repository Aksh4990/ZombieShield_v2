"""Threat intelligence, traffic analytics, decisions and remediation records."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.api import utc_now


class Component(Base):
    """A third-party dependency of a service, from an SBOM or manifest file."""

    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("service_name", "ecosystem", "name", "version", name="uq_component"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)  # PyPI npm Go Maven
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    purl: Mapped[str] = mapped_column(String(512), nullable=False)
    manifest: Mapped[str] = mapped_column(String(1024), nullable=False)
    direct: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)  # OSV / GHSA identifier
    aliases: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    in_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(20))
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="OSV.dev")
    url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    __table_args__ = (UniqueConstraint("component_id", "vulnerability_id", name="uq_threat_finding"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    component_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("components.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id: Mapped[str] = mapped_column(String(100), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    match_reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    correlated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class RequestLog(Base):
    """Data-minimised request record: no raw IP, no query string, no headers."""

    __tablename__ = "request_log"
    __table_args__ = (Index("ix_request_log_ts", "ts"), Index("ix_request_log_client", "client_hash", "ts"), Index("ix_request_log_api", "api_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    api_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("apis.id", ondelete="SET NULL"))
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)  # normalised template
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    bytes_sent: Mapped[int | None] = mapped_column(Integer)
    client_hash: Mapped[str | None] = mapped_column(String(32))
    authenticated: Mapped[bool | None] = mapped_column(Boolean)
    service_name: Mapped[str | None] = mapped_column(String(255))
    raw_id: Mapped[str | None] = mapped_column(String(100))  # object identifier segment (for BOLA-pattern analytics)
    payload_score: Mapped[float | None] = mapped_column(Float)
    payload_label: Mapped[str | None] = mapped_column(String(30))
    source_name: Mapped[str | None] = mapped_column(String(255))


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"
    __table_args__ = (UniqueConstraint("client_hash", "window_start", name="uq_anomaly_window"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    client_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False)
    pattern: Mapped[str] = mapped_column(String(60), nullable=False, default="UNUSUAL_BEHAVIOUR")
    features: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    top_endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Decision(Base):
    __tablename__ = "decisions"
    __table_args__ = (Index("ix_decisions_api_id", "api_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    api_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="RECOMMENDED")
    reason: Mapped[str] = mapped_column(String(2000), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class RemediationAction(Base):
    """A concrete, human-approved gateway change (block / rate-limit / require auth)."""

    __tablename__ = "remediation_actions"
    __table_args__ = (UniqueConstraint("api_id", "kind", name="uq_remediation_kind"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    api_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # BLOCK_ROUTE RATE_LIMIT REQUIRE_AUTH
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    rationale: Mapped[str] = mapped_column(String(2000), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    rule: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    config_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PROPOSED")  # PROPOSED APPROVED APPLIED VERIFIED REJECTED ROLLED_BACK
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    approved_by: Mapped[str | None] = mapped_column(String(100))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_note: Mapped[str | None] = mapped_column(String(2000))
