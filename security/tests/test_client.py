"""Network integration tests use an explicitly isolated loopback fixture only."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from webguard_scope import JobLimits, ScopeBoundHttpClient, ScopeDenied, SecuritySettings, TargetAuthorization


def grant(port, **kwargs):
    values = dict(target_id="local-fixture", owner_id="tester", grant_id="local-grant",
                  allowed_hosts=("127.0.0.1",), allowed_ports=(port,), allowed_path_prefixes=("/",),
                  issued_at=datetime.now(timezone.utc) - timedelta(seconds=1), isolated_lab=True)
    values.update(kwargs)
    return TargetAuthorization(**values)


def test_local_fixture_request_is_only_allowed_in_explicit_lab_mode():
    async def scenario():
        async def handler(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            body = b"webguard-test"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            url = f"http://127.0.0.1:{port}/ok"
            async with ScopeBoundHttpClient(grant(port), SecuritySettings(isolated_lab_enabled=True),
                                            JobLimits(max_requests=2), actor_id="tester") as client:
                response = await client.get(url)
            assert response.status == 200
            assert response.body == b"webguard-test"
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_request_denied_when_lab_setting_is_off():
    async def scenario():
        port = 12345
        async with ScopeBoundHttpClient(grant(port), SecuritySettings(), actor_id="tester") as client:
            with pytest.raises(ScopeDenied):
                await client.get(f"http://127.0.0.1:{port}/")
    asyncio.run(scenario())


def test_response_size_limit_is_enforced():
    async def scenario():
        async def handler(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            body = b"123456789"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with ScopeBoundHttpClient(grant(port), SecuritySettings(isolated_lab_enabled=True),
                                            JobLimits(max_response_bytes=4), actor_id="tester") as client:
                from webguard_scope import ResponseTooLarge
                with pytest.raises(ResponseTooLarge):
                    await client.get(f"http://127.0.0.1:{port}/large")
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_same_origin_redirect_is_revalidated_and_recorded():
    async def scenario():
        async def handler(reader, writer):
            request_line = await reader.readline()
            # Consume remaining headers.
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
            path = request_line.split(b" ")[1]
            if path == b"/redirect":
                writer.write(b"HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                body = b"redirect-ok"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with ScopeBoundHttpClient(grant(port), SecuritySettings(isolated_lab_enabled=True),
                                            JobLimits(max_requests=3), actor_id="tester") as client:
                response = await client.get(f"http://127.0.0.1:{port}/redirect")
            assert response.status == 200
            assert response.body == b"redirect-ok"
            assert len(response.redirect_history) == 1
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_redirect_to_disallowed_port_is_denied_before_second_connection():
    async def scenario():
        async def handler(reader, writer):
            await reader.readline()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
            location = b"http://127.0.0.1:12345/outside"
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: " + location + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with ScopeBoundHttpClient(grant(port), SecuritySettings(isolated_lab_enabled=True),
                                            actor_id="tester") as client:
                with pytest.raises(ScopeDenied) as error:
                    await client.get(f"http://127.0.0.1:{port}/redirect")
                assert error.value.reason_code == "port_not_allowed"
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_request_timeout_is_enforced():
    async def scenario():
        async def handler(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                await asyncio.sleep(0.3)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with ScopeBoundHttpClient(grant(port), SecuritySettings(isolated_lab_enabled=True),
                                            JobLimits(request_timeout_seconds=0.05, max_job_duration_seconds=1),
                                            actor_id="tester") as client:
                from webguard_scope import JobDeadlineExceeded
                with pytest.raises(JobDeadlineExceeded):
                    await client.get(f"http://127.0.0.1:{port}/slow")
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_revoked_or_changed_grant_is_denied_before_network_request():
    async def scenario():
        active = False
        async with ScopeBoundHttpClient(
            grant(12345), SecuritySettings(isolated_lab_enabled=True), actor_id="tester",
            authorization_check=lambda: active,
        ) as client:
            with pytest.raises(ScopeDenied) as error:
                await client.get("http://127.0.0.1:12345/never-connect")
            assert error.value.reason_code == "authorization_revoked"
    asyncio.run(scenario())


def test_dns_block_is_written_to_audit_sink(monkeypatch):
    import socket
    from webguard_scope import ScopeBoundHttpClient, TargetAuthorization

    async def scenario():
        loop = asyncio.get_running_loop()
        async def fake_getaddrinfo(host, port, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", port))]
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        test_grant = TargetAuthorization(
            target_id="dns-test", owner_id="tester", grant_id="dns-grant",
            allowed_hosts=("target.example.test",), allowed_ports=(80,),
            issued_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        events = []
        async with ScopeBoundHttpClient(test_grant, SecuritySettings(), actor_id="tester",
                                        audit_sink=events.append) as client:
            with pytest.raises(ScopeDenied) as error:
                await client.get("http://target.example.test/")
            assert error.value.reason_code == "non_public_ip"
        assert any(event.event_type == "request.denied" and event.outcome == "denied"
                   for event in events)
    asyncio.run(scenario())
