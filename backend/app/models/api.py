import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LifecycleState(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    SHADOW = "SHADOW"
    ZOMBIE = "ZOMBIE"
    DECOMMISSIONED = "DECOMMISSIONED"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class API(Base):
    """One canonical API operation: (organization, host, METHOD, normalised path)."""

    __tablename__ = "apis"
    __table_args__ = (
        Index("ix_apis_canonical_key", "canonical_key", unique=True),
        Index("ix_apis_lifecycle_state", "lifecycle_state"),
        Index("ix_apis_service", "service_name"),
        Index("ix_apis_last_seen", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    canonical_key: Mapped[str] = mapped_column(String(64), nullable=False)
    organization: Mapped[str] = mapped_column(String(255), nullable=False)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    endpoint_path: Mapped[str] = mapped_column(String(2048), nullable=False)  # canonical template, params -> {id}
    display_path: Mapped[str] = mapped_column(String(2048), nullable=False)  # first template seen with real names
    version: Mapped[str] = mapped_column(String(100), nullable=False, default="unversioned")
    spec_version: Mapped[str | None] = mapped_column(String(100))

    # Evidence flags (derived from sources; never user-guessed)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)  # every "kind:source" ever seen
    current_sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)  # spec/code sources at HEAD
    in_current_spec: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    in_current_code: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    in_runtime: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    previously_in_spec: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    previously_in_code: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    removed_in_commit: Mapped[str | None] = mapped_column(String(64))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removal_note: Mapped[str | None] = mapped_column(String(1000))
    spec_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    superseded_by: Mapped[str | None] = mapped_column(String(2048))
    spec_security: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    code_location: Mapped[str | None] = mapped_column(String(1024))

    # Ownership / manual metadata
    owner: Mapped[str | None] = mapped_column(String(255))
    is_registered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    manually_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    manually_removed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_runtime_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Runtime aggregates
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unauth_success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_clients: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attack_request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    anomalous_client_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Lifecycle
    lifecycle_state: Mapped[LifecycleState] = mapped_column(
        Enum(LifecycleState, name="lifecycle_state", native_enum=False, length=20), nullable=False, default=LifecycleState.ACTIVE
    )
    classification_reason: Mapped[str | None] = mapped_column(String(2000))
    classified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # ML context
    ml_legacy_score: Mapped[float | None] = mapped_column(Float)
    ml_sensitivity_score: Mapped[float | None] = mapped_column(Float)
    ml_explanation: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=list)

    # Risk
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_level: Mapped[str | None] = mapped_column(String(20))
    risk_breakdown: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=list)
    risk_explanation: Mapped[str | None] = mapped_column(String(2000))
    risk_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owasp_categories: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Summaries maintained by stages
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kev_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    security_controls: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    evidence: Mapped[list["EvidenceEvent"]] = relationship(back_populates="api", cascade="all, delete-orphan", order_by="EvidenceEvent.observed_at")

    @property
    def is_documented(self) -> bool:
        return self.in_current_spec

    @property
    def runtime_only(self) -> bool:
        return self.in_runtime and not (self.in_current_spec or self.in_current_code)


class EvidenceEvent(Base):
    """Timeline of everything ZombieShield learned about an API, with its source."""

    __tablename__ = "evidence_events"
    __table_args__ = (Index("ix_evidence_api", "api_id", "kind"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    api_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    dedupe_key: Mapped[str | None] = mapped_column(String(255))

    api: Mapped[API] = relationship(back_populates="evidence")
