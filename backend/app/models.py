"""Shared data model (see docs/DATA_MODEL.md). IDs are UUID4 strings; timestamps are UTC."""
from __future__ import annotations
import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class JobState(str, enum.Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    resolved = "resolved"


class AuthorizationStatus(str, enum.Enum):
    unverified = "unverified"
    authorized = "authorized"
    revoked = "revoked"


class UserRole(str, enum.Enum):
    admin = "admin"
    operator = "operator"
    viewer = "viewer"


def _enum(e: type[enum.Enum], name: str) -> Enum:
    return Enum(e, name=name, native_enum=False, validate_strings=True, length=32)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default=UserRole.viewer.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    targets: Mapped[list["Target"]] = relationship(back_populates="owner")


class Target(TimestampMixin, Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    scope_rules: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    authorization_status: Mapped[AuthorizationStatus] = mapped_column(
        _enum(AuthorizationStatus, "authorization_status"), default=AuthorizationStatus.unverified, nullable=False
    )
    authorization_note: Mapped[str | None] = mapped_column(Text)
    is_lab_target: Mapped[bool] = mapped_column(default=False, nullable=False)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    owner: Mapped[User | None] = relationship(back_populates="targets")
    audits: Mapped[list["Audit"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Audit(TimestampMixin, Base):
    __tablename__ = "audits"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    state: Mapped[JobState] = mapped_column(_enum(JobState, "audit_state"), default=JobState.pending, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    target: Mapped[Target] = relationship(back_populates="audits")
    findings: Mapped[list["Finding"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    load_tests: Mapped[list["LoadTest"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_audits_state_created", "state", "created_at"),)


class ScanJob(TimestampMixin, Base):
    __tablename__ = "scan_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)  # zap | nuclei | playwright | builtin
    state: Mapped[JobState] = mapped_column(_enum(JobState, "scan_job_state"), default=JobState.pending, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    audit: Mapped[Audit] = relationship(back_populates="scan_jobs")
    __table_args__ = (CheckConstraint("progress >= 0 AND progress <= 100", name="ck_scan_jobs_progress"),)


class LoadTest(TimestampMixin, Base):
    __tablename__ = "load_tests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    state: Mapped[JobState] = mapped_column(_enum(JobState, "load_test_state"), default=JobState.pending, nullable=False)
    virtual_users: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    audit: Mapped[Audit] = relationship(back_populates="load_tests")
    __table_args__ = (
        CheckConstraint("virtual_users BETWEEN 1 AND 500", name="ck_load_tests_vus"),
        CheckConstraint("duration_seconds BETWEEN 1 AND 3600", name="ck_load_tests_duration"),
    )


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str | None] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=True, index=True)
    workspace_scan_id: Mapped[str | None] = mapped_column(ForeignKey("workspace_scans.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False, index=True)
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.open, nullable=False
    )
    url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    audit: Mapped[Audit | None] = relationship(back_populates="findings")
    workspace_scan: Mapped[WorkspaceScan | None] = relationship(back_populates="findings")


class Report(TimestampMixin, Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False)  # json | html | pdf
    state: Mapped[JobState] = mapped_column(_enum(JobState, "report_state"), default=JobState.pending, nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    audit: Mapped[Audit] = relationship(back_populates="reports")


class WorkspaceScan(TimestampMixin, Base):
    __tablename__ = "workspace_scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[JobState] = mapped_column(_enum(JobState, "workspace_scan_state"), default=JobState.pending, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    findings: Mapped[list["Finding"]] = relationship(back_populates="workspace_scan", cascade="all, delete-orphan")
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_workspace_scans_progress"),
        Index("ix_workspace_scans_state_created", "state", "created_at"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (Index("ix_audit_events_entity", "entity_type", "entity_id", "created_at"),)


class WorkerHeartbeat(Base):
    """Last known capability catalog for the single configured queue worker."""
    __tablename__ = "worker_heartbeats"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="offline")
    capabilities: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
