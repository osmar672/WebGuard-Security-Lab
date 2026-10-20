"""Pydantic schemas and response envelopes (see docs/API_CONTRACT.md)."""
from datetime import datetime
import re
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import AuthorizationStatus, FindingStatus, JobState, Severity

T = TypeVar("T")


class Meta(BaseModel):
    page: int
    page_size: int
    total: int


class Envelope(BaseModel, Generic[T]):
    data: T
    meta: Meta | None = None


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[dict] | None = None
    request_id: str | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("email is invalid")
        return value


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: Literal["admin", "operator", "viewer"]
    is_active: bool
    created_at: datetime


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserOut


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=8, max_length=2048)
    authorization_confirmed: bool = Field(
        description="Caller attests they own or are explicitly authorized to test this target."
    )
    authorization_note: str | None = Field(default=None, max_length=2000)
    scope_rules: dict = Field(default_factory=dict, max_length=100)

    @field_validator("scope_rules")
    @classmethod
    def validate_scope_rules(cls, value: dict) -> dict:
        if any(not isinstance(key, str) or len(key) > 100 for key in value):
            raise ValueError("scope rule keys must be strings of at most 100 characters")
        return value

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("authorization_confirmed")
    @classmethod
    def must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("you must confirm you are authorized to test this target")
        return v


class TargetOut(ORM):
    id: str
    name: str
    base_url: str
    hostname: str
    scope_rules: dict
    authorization_status: AuthorizationStatus
    is_lab_target: bool
    created_at: datetime
    updated_at: datetime


class AuditOut(ORM):
    id: str
    target_id: str
    name: str
    state: JobState
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FindingOut(ORM):
    id: str
    audit_id: str | None
    workspace_scan_id: str | None = None
    scan_job_id: str | None
    title: str
    severity: Severity
    status: FindingStatus
    url: str | None
    description: str | None
    created_at: datetime


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    api: Literal["ok"]
    database: Literal["ok", "unavailable"]
    version: str
    time: datetime


class DashboardSummary(BaseModel):
    targets: int
    audits_by_state: dict[str, int]
    findings_by_severity: dict[str, int]
    open_findings: int
    recent_audits: list[AuditOut]


EngineState = Literal["available", "disabled", "not_configured", "not_implemented", "unavailable"]


class ToolCatalogItem(BaseModel):
    id: str
    name: str
    category: Literal["web_security", "api_testing", "browser", "performance", "code_security", "configuration"]
    description: str
    kind: Literal["builtin", "external"]
    state: EngineState
    detail: str
    profiles: list[Literal["quick", "standard", "exhaustive"]]
    requires_target: bool = True
    active_testing: bool = True


class TargetAuthorizationRequest(BaseModel):
    confirmed: bool
    note: str = Field(min_length=8, max_length=2000)

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 8:
            raise ValueError("provide an authorization reference or reason of at least 8 characters")
        return value


class WorkspaceRunCreate(BaseModel):
    engine: Literal["trivy", "semgrep", "gitleaks", "sbom"]
    profile: Literal["quick", "standard", "exhaustive"] = "quick"
    authorization_confirmed: bool

    @field_validator("authorization_confirmed")
    @classmethod
    def confirm_workspace_authorization(cls, value: bool) -> bool:
        if not value:
            raise ValueError("confirm you are authorized to scan the configured source workspace")
        return value


class WorkspaceRunOut(BaseModel):
    id: str
    engine: str
    profile: str
    state: JobState
    progress: int
    results: dict = Field(default_factory=dict)
    error_message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class ToolRunCreate(BaseModel):
    engine: str = Field(min_length=2, max_length=40)
    target_id: str = Field(min_length=36, max_length=36)
    profile: Literal["quick", "standard", "exhaustive"] = "quick"
    authorization_confirmed: bool

    @field_validator("engine")
    @classmethod
    def normalize_engine(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,39}", value):
            raise ValueError("engine identifier is invalid")
        return value

    @field_validator("authorization_confirmed")
    @classmethod
    def confirm_authorization(cls, value: bool) -> bool:
        if not value:
            raise ValueError("confirm authorization before creating a tool run")
        return value


class ToolRunOut(BaseModel):
    id: str
    audit_id: str
    target_id: str
    target_name: str
    engine: str
    state: JobState
    progress: int
    profile: str
    results: dict = Field(default_factory=dict)
    error_message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class RegressionOut(BaseModel):
    baseline_audit_id: str
    current_audit_id: str
    new_findings: list[dict]
    resolved_findings: list[dict]
    unchanged_findings: int



class EngineStatus(BaseModel):
    name: str
    kind: Literal["scanner", "browser", "load_test", "report"]
    state: EngineState
    detail: str


class AIAssistRequest(BaseModel):
    task: Literal["process_review", "audit_summary", "finding_triage", "remediation_plan", "general"] = "process_review"
    question: str = Field(default="", max_length=3000)
    audit_id: str | None = Field(default=None, max_length=36)

    @field_validator("question")
    @classmethod
    def trim_question(cls, value: str) -> str:
        return value.strip()


class AIStatusOut(BaseModel):
    configured: bool
    mode: Literal["remote_model", "local_rules"]
    provider: str
    model: str | None
    capabilities: list[str]
    privacy_note: str


class AIAssistOut(BaseModel):
    task: Literal["process_review", "audit_summary", "finding_triage", "remediation_plan", "general"]
    answer: str
    mode: Literal["remote_model", "local_rules"]
    provider: str
    model: str | None
    generated_at: datetime
    disclaimer: str
