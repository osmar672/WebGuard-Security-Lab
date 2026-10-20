import asyncio
import socket
from datetime import datetime, timedelta, timezone

import pytest

from webguard_scope import ScopeBoundResolver, ScopeDenied, SecuritySettings, TargetAuthorization


def make_grant(**kwargs):
    values = dict(target_id="t1", owner_id="u1", grant_id="g1", allowed_hosts=("target.example.test",),
                  allowed_ports=(443,), issued_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    values.update(kwargs)
    return TargetAuthorization(**values)


def record(address, family=None):
    family = family or (socket.AF_INET6 if ":" in address else socket.AF_INET)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443))


def test_dns_private_answer_fails_closed(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        async def fake_getaddrinfo(*args, **kwargs):
            return [record("10.0.0.8")]
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        resolver = ScopeBoundResolver(make_grant(), SecuritySettings())
        with pytest.raises(ScopeDenied) as error:
            await resolver.resolve("target.example.test", 443, socket.AF_UNSPEC)
        assert error.value.reason_code == "non_public_ip"
    asyncio.run(scenario())


def test_dns_mixed_public_private_answers_fail_closed(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        async def fake_getaddrinfo(*args, **kwargs):
            return [record("8.8.8.8"), record("10.0.0.8")]
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        resolver = ScopeBoundResolver(make_grant(), SecuritySettings())
        with pytest.raises(ScopeDenied):
            await resolver.resolve("target.example.test", 443, socket.AF_UNSPEC)
    asyncio.run(scenario())


def test_dns_public_answers_are_returned_as_numeric_pinned_addresses(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        async def fake_getaddrinfo(*args, **kwargs):
            return [record("8.8.8.8")]
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        resolver = ScopeBoundResolver(make_grant(), SecuritySettings())
        result = await resolver.resolve("target.example.test", 443, socket.AF_UNSPEC)
        assert result[0]["host"] == "8.8.8.8"
        assert result[0]["hostname"] == "target.example.test"
    asyncio.run(scenario())


def test_dns_timeout_fails_closed(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        async def fake_getaddrinfo(*args, **kwargs):
            await asyncio.sleep(0.1)
            return [record("8.8.8.8")]
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        resolver = ScopeBoundResolver(make_grant(), SecuritySettings(resolver_timeout_seconds=0.01))
        with pytest.raises(ScopeDenied) as error:
            await resolver.resolve("target.example.test", 443, socket.AF_UNSPEC)
        assert error.value.reason_code == "dns_timeout"
    asyncio.run(scenario())
