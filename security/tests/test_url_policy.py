from datetime import datetime, timedelta, timezone
import ipaddress

import pytest

from webguard_scope import (
    ScopeDenied, SecuritySettings, TargetAuthorization, assert_ip_allowed, validate_url,
)

NOW = datetime.now(timezone.utc)


def grant(**overrides):
    values = dict(
        target_id="target-1", owner_id="user-1", grant_id="grant-1",
        allowed_hosts=("example.test",), allowed_ports=(80, 443),
        allowed_path_prefixes=("/",), issued_at=NOW - timedelta(minutes=1),
    )
    values.update(overrides)
    return TargetAuthorization(**values)


def test_accepts_authorized_url_and_removes_fragment():
    result = validate_url("https://example.test/about?q=1#section", grant(), SecuritySettings())
    assert result.host == "example.test"
    assert result.port == 443
    assert result.url == "https://example.test/about?q=1"


@pytest.mark.parametrize("url,reason", [
    ("ftp://example.test/", "unsupported_scheme"),
    ("file:///etc/passwd", "unsupported_scheme"),
    ("http://user:pass@example.test/", "invalid_url_authority"),
    ("http://example.test:8080/", "port_not_allowed"),
    ("http://example.test/a/../admin", "path_traversal"),
    ("http://example.test/a%2fb", "invalid_path"),
    ("http://example.test/%252e%252e/admin", "invalid_path"),
    ("http://example.test\\@evil.test/", "invalid_url"),
    ("http://example.test:99999/", "invalid_url"),
])
def test_rejects_malformed_or_out_of_scope_urls(url, reason):
    with pytest.raises(ScopeDenied) as error:
        validate_url(url, grant(), SecuritySettings())
    assert error.value.reason_code == reason


def test_rejects_expired_grant():
    expired = grant(expires_at=NOW - timedelta(seconds=1))
    with pytest.raises(ScopeDenied, match="not active"):
        validate_url("https://example.test/", expired, SecuritySettings())


def test_exact_hosts_and_wildcards():
    wildcard = grant(allowed_hosts=("*.example.test",))
    assert validate_url("https://app.example.test/", wildcard, SecuritySettings()).host == "app.example.test"
    with pytest.raises(ScopeDenied):
        validate_url("https://example.test/", wildcard, SecuritySettings())
    with pytest.raises(ScopeDenied):
        validate_url("https://eviltest/", wildcard, SecuritySettings())


def test_path_prefix_matching_does_not_allow_sibling_prefix():
    scoped = grant(allowed_path_prefixes=("/api",))
    assert validate_url("https://example.test/api/v1", scoped, SecuritySettings())
    with pytest.raises(ScopeDenied):
        validate_url("https://example.test/apix", scoped, SecuritySettings())


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.1.2", "192.168.1.2", "169.254.1.2",
    "::1", "fc00::1", "fe80::1", "224.0.0.1", "255.255.255.255", "192.0.2.1",
])
def test_non_public_addresses_are_denied_in_normal_deployments(address):
    with pytest.raises(ScopeDenied):
        assert_ip_allowed(ipaddress.ip_address(address), grant(), SecuritySettings())


def test_global_address_is_allowed_when_scope_matches():
    assert_ip_allowed(ipaddress.ip_address("8.8.8.8"), grant(), SecuritySettings())


def test_local_addresses_require_both_lab_switches():
    address = ipaddress.ip_address("127.0.0.1")
    with pytest.raises(ScopeDenied):
        assert_ip_allowed(address, grant(isolated_lab=True), SecuritySettings())
    with pytest.raises(ScopeDenied):
        assert_ip_allowed(address, grant(), SecuritySettings(isolated_lab_enabled=True))
    assert_ip_allowed(address, grant(isolated_lab=True), SecuritySettings(isolated_lab_enabled=True))


def test_metadata_addresses_are_denied_even_in_lab():
    lab_grant = grant(allowed_hosts=("169.254.169.254",), isolated_lab=True)
    with pytest.raises(ScopeDenied) as error:
        validate_url("http://169.254.169.254/latest/meta-data/", lab_grant,
                     SecuritySettings(isolated_lab_enabled=True))
    assert error.value.reason_code == "metadata_destination"


def test_metadata_hostnames_are_denied_even_when_allowlisted():
    lab_grant = grant(allowed_hosts=("metadata.google.internal",), isolated_lab=True)
    with pytest.raises(ScopeDenied) as error:
        validate_url("http://metadata.google.internal/", lab_grant,
                     SecuritySettings(isolated_lab_enabled=True))
    assert error.value.reason_code == "metadata_destination"
