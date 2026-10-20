"""Scope-bound HTTP client with manual redirect checks and bounded resource use."""
from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

import aiohttp

from .models import (AuditEvent, JobDeadlineExceeded, JobLimits, RequestLimitExceeded,
                     ResponseTooLarge, SafeResponse, ScopeDenied, SecuritySettings,
                     TargetAuthorization)
from .resolver import ScopeBoundResolver
from .urls import validate_url

AuditSink = Callable[[AuditEvent], object]
_REDIRECTS = {301, 302, 303, 307, 308}


class ScopeBoundHttpClient:
    """Restricted request client intended for one authorized job/grant.

    Redirects are never followed automatically. Each Location is checked again and the
    custom resolver validates the IP answers actually handed to the socket connector.
    This is not a general-purpose proxy and exposes no arbitrary forwarding endpoint.
    """

    def __init__(self, grant: TargetAuthorization, settings: SecuritySettings,
                 limits: JobLimits | None = None, *, actor_id: str, job_id: str | None = None,
                 audit_sink: AuditSink | None = None,
                 authorization_check: Callable[[], bool] | None = None) -> None:
        self.grant = grant
        self.settings = settings
        self.limits = limits or JobLimits()
        self.actor_id = actor_id
        self.job_id = job_id
        self.audit_sink = audit_sink
        self.authorization_check = authorization_check
        self._started = time.monotonic()
        self._requests = 0
        self._request_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(self.limits.max_concurrency)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "ScopeBoundHttpClient":
        resolver = ScopeBoundResolver(self.grant, self.settings, self.authorization_check)
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, ttl_dns_cache=0,
                                         limit=self.limits.max_concurrency, ssl=True)
        timeout = aiohttp.ClientTimeout(total=self.limits.request_timeout_seconds,
                                        connect=self.limits.request_timeout_seconds,
                                        sock_read=self.limits.request_timeout_seconds)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False,
                                              auto_decompress=False, raise_for_status=False)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _audit(self, event_type: str, outcome: str, *, reason_code: str | None = None,
                     url: str | None = None) -> None:
        if self.audit_sink is None:
            return
        event = AuditEvent(event_type, outcome, self.grant.target_id, self.actor_id,
                           job_id=self.job_id, reason_code=reason_code,
                           details={"url": url} if url else {})  # type: ignore[arg-type]
        result = self.audit_sink(event)
        if inspect.isawaitable(result):
            await result

    def _remaining(self) -> float:
        remaining = self.limits.max_job_duration_seconds - (time.monotonic() - self._started)
        if remaining <= 0:
            raise JobDeadlineExceeded("Maximum job duration exceeded")
        return remaining

    async def _reserve_request(self, url: str) -> None:
        async with self._request_lock:
            if self._requests >= self.limits.max_requests:
                await self._audit("request.denied", "denied", reason_code="request_limit", url=url)
                raise RequestLimitExceeded("Maximum request count exceeded for this job")
            self._requests += 1
        await self._audit("request.started", "allowed", url=url)

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                      body: bytes | None = None, max_redirects: int | None = None) -> SafeResponse:
        if self._session is None:
            raise RuntimeError("Use ScopeBoundHttpClient as an async context manager")
        method = method.upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            await self._audit("request.denied", "denied", reason_code="method_not_allowed", url=url)
            raise ScopeDenied("HTTP method is not supported", reason_code="method_not_allowed")
        if body is not None and not isinstance(body, bytes):
            raise TypeError("body must be bytes or None")
        redirects_limit = self.limits.max_redirects if max_redirects is None else max_redirects
        if redirects_limit < 0:
            raise ValueError("max_redirects must be >= 0")
        outgoing_headers = dict(headers or {})
        forbidden = {"host", "connection", "proxy-authorization", "proxy-connection", "transfer-encoding", "content-length"}
        if any(k.lower() in forbidden for k in outgoing_headers):
            await self._audit("request.denied", "denied", reason_code="unsafe_header", url=url)
            raise ScopeDenied("Caller-supplied routing headers are not allowed", reason_code="unsafe_header")

        try:
            async with self._semaphore:
                return await self._execute(method, url, outgoing_headers, body, redirects_limit)
        except asyncio.CancelledError:
            # Shield the audit write so cancellation does not silently skip the record.
            try:
                await asyncio.shield(self._audit("job.request_cancelled", "cancelled", reason_code="cancelled", url=url))
            finally:
                raise

    async def _execute(self, method: str, url: str, headers: dict[str, str], body: bytes | None,
                       redirects_limit: int) -> SafeResponse:
        assert self._session is not None
        current_url = url
        current_method = method
        current_body = body
        current_headers = dict(headers)
        history: list[str] = []
        for hop in range(redirects_limit + 1):
            if self.authorization_check is not None and not self.authorization_check():
                await self._audit("request.denied", "denied", reason_code="authorization_revoked", url=current_url)
                raise ScopeDenied("Authorization grant was revoked or changed", reason_code="authorization_revoked")
            try:
                remaining = self._remaining()
            except JobDeadlineExceeded:
                await self._audit("job.deadline_exceeded", "denied", reason_code="job_deadline", url=current_url)
                raise
            try:
                validated = validate_url(current_url, self.grant, self.settings)
            except ScopeDenied as exc:
                await self._audit("request.denied", "denied", reason_code=exc.reason_code, url=current_url)
                raise
            await self._reserve_request(validated.url)
            timeout_seconds = min(self.limits.request_timeout_seconds, remaining)
            try:
                async with asyncio.timeout(timeout_seconds):
                    async with self._session.request(
                        current_method, validated.url, headers=current_headers,
                        data=current_body, allow_redirects=False,
                    ) as response:
                        if response.status in _REDIRECTS and response.headers.get("Location"):
                            if hop >= redirects_limit:
                                raise ScopeDenied("Redirect limit exceeded", reason_code="redirect_limit")
                            next_url = urljoin(validated.url, response.headers["Location"])
                            current_url = next_url
                            next_validated = validate_url(current_url, self.grant, self.settings)
                            # Do not carry credentials across origins, even when both are
                            # in an operator-approved scope.
                            old_origin = urlsplit(validated.url)
                            new_origin = urlsplit(next_validated.url)
                            if (old_origin.scheme, old_origin.hostname, old_origin.port) != (
                                new_origin.scheme, new_origin.hostname, new_origin.port
                            ):
                                current_headers = {k: v for k, v in current_headers.items()
                                                   if k.lower() not in {"authorization", "cookie"}}
                            history.append(validated.url)
                            if response.status == 303 or (response.status in (301, 302) and current_method == "POST"):
                                current_method, current_body = "GET", None
                            current_url = next_validated.url
                            continue

                        chunks: list[bytes] = []
                        byte_count = 0
                        async for chunk in response.content.iter_chunked(64 * 1024):
                            byte_count += len(chunk)
                            if byte_count > self.limits.max_response_bytes:
                                await self._audit("response.too_large", "denied", reason_code="response_too_large", url=validated.url)
                                raise ResponseTooLarge("Response body exceeded configured byte limit")
                            chunks.append(chunk)
                        await self._audit("request.completed", "completed", url=validated.url)
                        return SafeResponse(response.status, str(response.url), dict(response.headers),
                                            b"".join(chunks), tuple(history))
            except asyncio.TimeoutError as exc:
                await self._audit("request.timed_out", "denied", reason_code="timeout", url=current_url)
                raise JobDeadlineExceeded("Request timed out or job deadline was reached") from exc
            except aiohttp.ClientConnectorDNSError as exc:
                original = getattr(exc, "os_error", None)
                denial = original if isinstance(original, ScopeDenied) else ScopeDenied(
                    "DNS resolution failed; request denied", reason_code="dns_resolution_failed"
                )
                await self._audit("request.denied", "denied", reason_code=denial.reason_code, url=current_url)
                raise denial from exc
            except ScopeDenied as exc:
                await self._audit("request.denied", "denied", reason_code=exc.reason_code, url=current_url)
                raise
        raise ScopeDenied("Redirect processing stopped unexpectedly", reason_code="redirect_error")

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> SafeResponse:
        return await self.request("GET", url, headers=headers)
