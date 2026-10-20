"""Small registry abstraction for grants and audit events.

Replace this in-memory implementation with the application's persistent repository
and transaction layer before multi-worker/production deployment.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from threading import RLock
from typing import Awaitable

from .models import AuditEvent, TargetAuthorization

AuditSink = Callable[[AuditEvent], object | Awaitable[object]]


class AuthorizationRegistry:
    def __init__(self, audit_sink: AuditSink | None = None) -> None:
        self._grants: dict[str, TargetAuthorization] = {}
        self._lock = RLock()
        self._audit_sink = audit_sink

    def register(self, grant: TargetAuthorization, *, actor_id: str) -> TargetAuthorization:
        if not grant.grant_id:
            raise ValueError("grant_id is required")
        with self._lock:
            if grant.grant_id in self._grants:
                raise ValueError("grant_id already exists")
            self._grants[grant.grant_id] = grant
        self._emit(AuditEvent("scope.created", "changed", grant.target_id, actor_id,
                              details={"grant_id": grant.grant_id, "hosts": list(grant.allowed_hosts),
                                       "ports": list(grant.allowed_ports)}))
        return grant

    def get(self, grant_id: str) -> TargetAuthorization | None:
        with self._lock:
            return self._grants.get(grant_id)

    def is_current(self, grant: TargetAuthorization) -> bool:
        """Return False if the grant was revoked or changed after a job loaded it."""
        with self._lock:
            return self._grants.get(grant.grant_id) == grant

    def update(self, grant: TargetAuthorization, *, actor_id: str) -> TargetAuthorization:
        if not grant.grant_id:
            raise ValueError("grant_id is required")
        with self._lock:
            if grant.grant_id not in self._grants:
                raise KeyError("grant_id does not exist")
            self._grants[grant.grant_id] = grant
        self._emit(AuditEvent("scope.updated", "changed", grant.target_id, actor_id,
                              details={"grant_id": grant.grant_id, "hosts": list(grant.allowed_hosts),
                                       "ports": list(grant.allowed_ports)}))
        return grant

    def revoke(self, grant_id: str, *, actor_id: str) -> bool:
        with self._lock:
            grant = self._grants.pop(grant_id, None)
        if grant is None:
            return False
        self._emit(AuditEvent("scope.revoked", "changed", grant.target_id, actor_id,
                              details={"grant_id": grant_id}))
        return True

    def _emit(self, event: AuditEvent) -> None:
        if self._audit_sink is None:
            return
        result = self._audit_sink(event)
        if inspect.isawaitable(result):
            # Registry operations are synchronous; async persistence must be handled by
            # an adapter at the service boundary rather than silently scheduling work.
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError("Use a synchronous audit sink with AuthorizationRegistry")
