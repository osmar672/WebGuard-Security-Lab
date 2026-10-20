"""Typed contracts for WebGuard's authorization and SSRF boundary."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

JobState = Literal["pending", "queued", "running", "completed", "failed", "cancelled"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class TargetAuthorization:
    """Explicit authorization grant for one target and its allowed scope.

    Hosts are exact hostnames/IP literals. Wildcards such as ``*.example.test``
    match subdomains only, not the apex domain. Never infer authorization from a URL.
    """

    target_id: str
    owner_id: str
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...] = (80, 443)
    allowed_path_prefixes: tuple[str, ...] = ("/",)
    authorization_reference: str = ""
    issued_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    isolated_lab: bool = False
    grant_id: str = ""

    def __post_init__(self) -> None:
        if not self.target_id.strip() or not self.owner_id.strip():
            raise ValueError("target_id and owner_id are required")
        if not self.allowed_hosts:
            raise ValueError("at least one allowed host is required")
        if not self.allowed_ports or any(p < 1 or p > 65535 for p in self.allowed_ports):
            raise ValueError("allowed_ports must contain valid TCP ports")
        if not self.allowed_path_prefixes:
            raise ValueError("at least one allowed path prefix is required")
        _require_aware(self.issued_at, "issued_at")
        if self.expires_at is not None:
            _require_aware(self.expires_at, "expires_at")
            if self.expires_at <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")
        from .urls import normalize_host_entry, normalize_path_prefix
        object.__setattr__(self, "allowed_hosts", tuple(normalize_host_entry(h) for h in self.allowed_hosts))
        object.__setattr__(self, "allowed_ports", tuple(sorted(set(self.allowed_ports))))
        object.__setattr__(self, "allowed_path_prefixes", tuple(normalize_path_prefix(p) for p in self.allowed_path_prefixes))

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or utc_now()
        return (now >= self.issued_at) and (self.expires_at is None or now < self.expires_at)


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Deployment-level security settings. Isolated lab behavior is off by default."""

    isolated_lab_enabled: bool = False
    resolver_timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if self.resolver_timeout_seconds <= 0:
            raise ValueError("resolver_timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class JobLimits:
    max_requests: int = 40
    max_concurrency: int = 4
    request_timeout_seconds: float = 8.0
    max_response_bytes: int = 1_000_000
    max_job_duration_seconds: float = 60.0
    max_redirects: int = 5

    def __post_init__(self) -> None:
        if self.max_requests < 1 or self.max_concurrency < 1:
            raise ValueError("max_requests and max_concurrency must be >= 1")
        if self.request_timeout_seconds <= 0 or self.max_job_duration_seconds <= 0:
            raise ValueError("timeouts must be positive")
        if self.max_response_bytes < 1 or self.max_redirects < 0:
            raise ValueError("max_response_bytes must be >= 1 and max_redirects >= 0")


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    original: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    is_ip_literal: bool


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    outcome: Literal["allowed", "denied", "changed", "cancelled", "completed"]
    target_id: str
    actor_id: str
    timestamp: datetime = field(default_factory=utc_now)
    job_id: str | None = None
    reason_code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_aware(self.timestamp, "timestamp")


@dataclass(frozen=True, slots=True)
class SafeResponse:
    status: int
    url: str
    headers: dict[str, str]
    body: bytes
    redirect_history: tuple[str, ...] = ()


class ScopeDenied(PermissionError):
    """Raised whenever a target or destination is outside the granted scope."""

    def __init__(self, message: str, *, reason_code: str = "scope_denied") -> None:
        super().__init__(message)
        self.reason_code = reason_code


class RequestLimitExceeded(RuntimeError):
    pass


class ResponseTooLarge(RuntimeError):
    pass


class JobDeadlineExceeded(TimeoutError):
    pass
