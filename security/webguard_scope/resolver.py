"""DNS resolver that validates every answer before aiohttp uses it for a socket."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable
from typing import Any

from aiohttp.abc import AbstractResolver

from .models import ScopeDenied, SecuritySettings, TargetAuthorization
from .urls import assert_ip_allowed, host_matches, normalize_hostname


class ScopeBoundResolver(AbstractResolver):
    """Resolve hosts and return only validated numeric addresses to the connector.

    aiohttp connects to the numeric address returned here while retaining the URL's
    original hostname for HTTP Host and TLS SNI. DNS caching is disabled by the client.
    """

    def __init__(self, grant: TargetAuthorization, settings: SecuritySettings,
                 authorization_check: Callable[[], bool] | None = None) -> None:
        self._grant = grant
        self._settings = settings
        self._authorization_check = authorization_check

    def _ensure_authorized(self) -> None:
        if not self._grant.is_active():
            raise ScopeDenied("Authorization grant has expired", reason_code="authorization_inactive")
        if self._authorization_check is not None and not self._authorization_check():
            raise ScopeDenied("Authorization grant was revoked or changed", reason_code="authorization_revoked")

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict[str, Any]]:
        self._ensure_authorized()
        try:
            normalized = normalize_hostname(host)
        except ScopeDenied:
            raise
        if not host_matches(normalized, self._grant.allowed_hosts):
            raise ScopeDenied("DNS resolver refused a hostname outside scope", reason_code="host_not_allowed")
        if port not in self._grant.allowed_ports:
            raise ScopeDenied("DNS resolver refused a disallowed port", reason_code="port_not_allowed")
        try:
            literal = ipaddress.ip_address(normalized)
        except ValueError:
            literal = None
        if literal is not None:
            assert_ip_allowed(literal, self._grant, self._settings)
            return [{"hostname": host, "host": str(literal), "port": port,
                     "family": socket.AF_INET6 if literal.version == 6 else socket.AF_INET,
                     "proto": 0, "flags": 0}]

        loop = asyncio.get_running_loop()
        # getaddrinfo is run by asyncio's resolver executor. Validate all answers;
        # mixed public/private answers fail closed instead of choosing a public one.
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(normalized, port, family=family, type=socket.SOCK_STREAM),
                timeout=self._settings.resolver_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise ScopeDenied("DNS resolution timed out", reason_code="dns_timeout") from exc
        except OSError as exc:
            raise ScopeDenied("DNS resolution failed", reason_code="dns_resolution_failed") from exc
        if not records:
            raise ScopeDenied("DNS returned no addresses", reason_code="dns_empty")

        answers: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for family_num, _type, proto, _canonname, sockaddr in records:
            address_text = sockaddr[0]
            try:
                address = ipaddress.ip_address(address_text.split("%", 1)[0])
            except ValueError as exc:
                raise ScopeDenied("DNS returned an invalid address", reason_code="dns_invalid_answer") from exc
            assert_ip_allowed(address, self._grant, self._settings)
            key = (str(address), family_num)
            if key in seen:
                continue
            seen.add(key)
            answers.append({"hostname": host, "host": str(address), "port": port,
                            "family": family_num, "proto": proto, "flags": 0})
        if not answers:
            raise ScopeDenied("DNS returned no usable addresses", reason_code="dns_empty")
        return answers

    async def close(self) -> None:
        return None
