"""WebGuard Phase 3: authorization, scope validation, and SSRF defenses."""
from .authorization import AuthorizationRegistry
from .client import ScopeBoundHttpClient
from .models import (
    AuditEvent, JobDeadlineExceeded, JobLimits, RequestLimitExceeded, ResponseTooLarge,
    SafeResponse, ScopeDenied, SecuritySettings, TargetAuthorization, ValidatedURL,
)
from .resolver import ScopeBoundResolver
from .urls import assert_ip_allowed, host_matches, normalize_hostname, validate_url

__all__ = [
    "AuditEvent", "AuthorizationRegistry", "JobDeadlineExceeded", "JobLimits",
    "RequestLimitExceeded", "ResponseTooLarge", "SafeResponse", "ScopeBoundHttpClient",
    "ScopeBoundResolver", "ScopeDenied", "SecuritySettings", "TargetAuthorization",
    "ValidatedURL", "assert_ip_allowed", "host_matches", "normalize_hostname", "validate_url",
]
