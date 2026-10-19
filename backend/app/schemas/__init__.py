import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import LifecycleState


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- auth / users
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserRead(ORM):
    id: uuid.UUID
    username: str
    role: str
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=200)
    role: str = Field(pattern=r"^(viewer|analyst|admin)$")


# ---- inventory
class APISummary(ORM):
    id: uuid.UUID
    organization: str
    service_name: str
    host: str
    http_method: str
    endpoint_path: str
    display_path: str
    version: str
    sources: list[str]
    in_current_spec: bool
    in_current_code: bool
    in_runtime: bool
    previously_in_spec: bool
    previously_in_code: bool
    spec_deprecated: bool
    superseded_by: str | None
    owner: str | None
    lifecycle_state: LifecycleState
    classification_reason: str | None
    risk_score: float | None
    risk_level: str | None
    request_count: int
    unique_clients: int
    vulnerability_count: int
    kev_count: int
    attack_request_count: int
    anomalous_client_count: int
    ml_legacy_score: float | None
    ml_sensitivity_score: float | None
    first_seen: datetime
    last_seen: datetime
    last_runtime_seen: datetime | None


class EvidenceRead(ORM):
    id: uuid.UUID
    kind: str
    source: str
    summary: str
    details: dict
    observed_at: datetime


class DecisionRead(ORM):
    id: uuid.UUID
    api_id: uuid.UUID
    action: str
    status: str
    reason: str
    decided_at: datetime


class APIDetail(APISummary):
    current_sources: list[str]
    spec_security: list[str]
    spec_version: str | None
    code_location: str | None
    removed_in_commit: str | None
    removed_at: datetime | None
    removal_note: str | None
    is_registered: bool
    manually_deprecated: bool
    manually_removed: bool
    notes: str | None
    error_count: int
    unauth_success_count: int
    ml_explanation: list[dict]
    risk_breakdown: list[dict]
    risk_explanation: str | None
    owasp_categories: list[str]
    security_controls: dict
    classified_at: datetime | None
    evidence: list[EvidenceRead] = []
    vulnerabilities: list[dict] = []
    decision: DecisionRead | None = None


class APIUpdate(BaseModel):
    owner: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=5000)
    is_registered: bool | None = None
    manually_deprecated: bool | None = None
    manually_removed: bool | None = None


# ---- sources / discovery
class SourceBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: str = Field(pattern=r"^(openapi|git|runtime_log|sbom)$")
    location: str = Field(min_length=1, max_length=2048)
    organization: str = Field(default="zombieshield-lab", min_length=1, max_length=255)
    service_name: str | None = Field(default=None, max_length=255)
    host: str = Field(default="api.local", min_length=1, max_length=255)
    options: dict = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("host")
    @classmethod
    def lower_host(cls, value: str) -> str:
        return value.lower()


class SourceCreate(SourceBase):
    pass


class SourceRead(SourceBase, ORM):
    id: uuid.UUID
    last_run_at: datetime | None
    last_status: str | None
    created_at: datetime


class DiscoveryContext(BaseModel):
    organization: str = Field(default="zombieshield-lab", min_length=1, max_length=255)
    host: str = Field(default="api.local", min_length=1, max_length=255)
    service_name: str | None = Field(default=None, max_length=255)
    name: str = Field(default="manual-upload", min_length=1, max_length=255)


class OpenAPIUpload(DiscoveryContext):
    document: str = Field(min_length=2, max_length=10_000_000)


class GitScan(DiscoveryContext):
    repository_path: str = Field(min_length=1, max_length=1024)
    mine_history: bool = True


class LogUpload(DiscoveryContext):
    log_content: str = Field(min_length=1, max_length=50_000_000)


class DiscoveryResponse(BaseModel):
    results: list[dict]
    apis_added: int


# ---- pipeline
class PipelineRunRequest(BaseModel):
    logs_from_start: bool = False


class PipelineRunRead(ORM):
    id: uuid.UUID
    status: str
    triggered_by: str
    options: dict
    stages: list[dict]
    summary: dict
    error: str | None
    started_at: datetime
    finished_at: datetime | None


# ---- threat intel / traffic
class ComponentRead(ORM):
    id: uuid.UUID
    service_name: str
    ecosystem: str
    name: str
    version: str
    purl: str
    manifest: str
    direct: bool


class VulnerabilityRead(ORM):
    id: str
    aliases: list[str]
    summary: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    published: datetime | None
    in_kev: bool
    kev_date_added: str | None
    epss: float | None
    epss_percentile: float | None
    url: str


class RequestRead(ORM):
    id: int
    ts: datetime
    api_id: uuid.UUID | None
    method: str
    path: str
    status: int
    latency_ms: float | None
    client_hash: str | None
    authenticated: bool | None
    service_name: str | None
    payload_label: str | None
    payload_score: float | None


class AnomalyRead(ORM):
    id: uuid.UUID
    client_hash: str
    window_start: datetime
    window_end: datetime
    score: float
    pattern: str
    features: dict
    reasons: list[str]
    top_endpoints: list[str]


class AuditRead(ORM):
    id: uuid.UUID
    at: datetime
    username: str
    action: str
    target_type: str | None
    target_id: str | None
    details: dict
