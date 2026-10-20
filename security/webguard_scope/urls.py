"""Strict URL and IP policy validation for authorized WebGuard requests."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from urllib.parse import unquote, urlsplit, urlunsplit

from .models import ScopeDenied, SecuritySettings, TargetAuthorization, ValidatedURL

_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_METADATA_HOSTS = {
    "metadata", "metadata.google.internal", "metadata.goog", "instance-data.ec2.internal",
    "metadata.azure.internal", "metadata.azure.com", "metadata.tencentyun.com",
}
_METADATA_IPS = tuple(ipaddress.ip_network(s) for s in (
    "169.254.169.254/32", "169.254.170.2/32", "100.100.100.200/32",
    "100.100.100.201/32", "168.63.129.16/32", "fd00:ec2::254/128", "fd20:ce::254/128",
))


def normalize_hostname(host: str) -> str:
    if not host or host != host.strip() or any(c.isspace() or ord(c) < 32 for c in host):
        raise ScopeDenied("Invalid hostname", reason_code="invalid_hostname")
    host = host.rstrip(".").lower()
    if not host or "%" in host or "\\" in host:
        raise ScopeDenied("Invalid hostname encoding", reason_code="invalid_hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeDenied("Invalid internationalized hostname", reason_code="invalid_hostname") from exc
    if len(ascii_host) > 253 or any(not label or len(label) > 63 for label in ascii_host.split(".")):
        raise ScopeDenied("Invalid hostname length", reason_code="invalid_hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in ascii_host.split(".")):
        raise ScopeDenied("Invalid hostname syntax", reason_code="invalid_hostname")
    return ascii_host


def normalize_host_entry(entry: str) -> str:
    if not isinstance(entry, str) or not entry:
        raise ValueError("host allowlist entries must be non-empty strings")
    if entry.startswith("*."):
        normalized = normalize_hostname(entry[2:])
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            return "*." + normalized
        raise ValueError("wildcards are not supported for IP addresses")
    return normalize_hostname(entry)


def normalize_path_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise ValueError("path prefixes must start with '/'")
    if "\\" in prefix or any(ord(c) < 32 for c in prefix) or _BAD_PERCENT.search(prefix):
        raise ValueError("invalid path prefix")
    if _ENCODED_SEPARATOR.search(prefix):
        raise ValueError("encoded path separators are not allowed in path prefixes")
    decoded = unquote(prefix)
    if decoded != unquote(decoded) or "\\" in decoded or any(p in (".", "..") for p in decoded.split("/")):
        raise ValueError("path prefixes must be canonical and cannot contain traversal")
    return decoded or "/"


def host_matches(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    for item in allowed_hosts:
        if item.startswith("*."):
            suffix = item[1:]  # .example.test
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == item:
            return True
    return False


def _path_is_in_scope(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
        if prefix.endswith("/") and path.startswith(prefix):
            return True
    return False


def validate_url(url: str, grant: TargetAuthorization, settings: SecuritySettings,
                 *, now: datetime | None = None) -> ValidatedURL:
    """Validate URL syntax and its host/port/path against an active grant."""
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ScopeDenied("URL is empty or too long", reason_code="invalid_url")
    if url != url.strip() or any(ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ScopeDenied("URL contains whitespace, control characters, or backslash", reason_code="invalid_url")
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ScopeDenied("Only http and https URLs are allowed", reason_code="unsupported_scheme")
        if not parts.netloc or parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ScopeDenied("URL must have a host and must not include credentials", reason_code="invalid_url_authority")
        raw_host = parts.hostname
        if raw_host is None:
            raise ScopeDenied("URL is missing a hostname", reason_code="invalid_url")
        host = normalize_hostname(raw_host)
        explicit_port = parts.port
    except ScopeDenied:
        raise
    except (ValueError, UnicodeError) as exc:
        raise ScopeDenied("Malformed URL or port", reason_code="invalid_url") from exc

    if not grant.is_active(now):
        raise ScopeDenied("Authorization grant is not active", reason_code="authorization_inactive")
    if not host_matches(host, grant.allowed_hosts):
        raise ScopeDenied("Hostname is outside the authorized scope", reason_code="host_not_allowed")

    default_port = 443 if scheme == "https" else 80
    port = explicit_port if explicit_port is not None else default_port
    if port not in grant.allowed_ports:
        raise ScopeDenied("Port is outside the authorized scope", reason_code="port_not_allowed")

    path = parts.path or "/"
    if _BAD_PERCENT.search(path) or _ENCODED_SEPARATOR.search(path):
        raise ScopeDenied("Malformed or encoded path separator", reason_code="invalid_path")
    decoded_path = unquote(path)
    if decoded_path != unquote(decoded_path) or "\\" in decoded_path or any(ord(c) < 32 for c in decoded_path):
        raise ScopeDenied("Non-canonical or unsafe path encoding", reason_code="invalid_path")
    if any(segment in (".", "..") for segment in decoded_path.split("/")):
        raise ScopeDenied("Path traversal is not allowed", reason_code="path_traversal")
    if not _path_is_in_scope(decoded_path, grant.allowed_path_prefixes):
        raise ScopeDenied("Path is outside the authorized scope", reason_code="path_not_allowed")

    # Deny known metadata names regardless of authorization wildcard or lab mode.
    if any(host == blocked or host.endswith("." + blocked) for blocked in _METADATA_HOSTS):
        raise ScopeDenied("Cloud metadata hostnames are always denied", reason_code="metadata_destination")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip_literal = False
    else:
        ip_literal = True
        assert_ip_allowed(ip, grant, settings)

    # Remove fragments: they are client-side only and are never sent over HTTP.
    normalized_netloc = f"[{host}]" if ":" in host else host
    if port != default_port:
        normalized_netloc += f":{port}"
    normalized_url = urlunsplit((scheme, normalized_netloc, path or "/", parts.query, ""))
    return ValidatedURL(url, normalized_url, scheme, host, port, decoded_path, ip_literal)


def assert_ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      grant: TargetAuthorization, settings: SecuritySettings) -> None:
    """Reject non-public IPs unless both isolated-lab switches are explicitly enabled."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        assert_ip_allowed(ip.ipv4_mapped, grant, settings)
        return
    if any(ip in net for net in _METADATA_IPS):
        raise ScopeDenied("Cloud metadata IP addresses are always denied", reason_code="metadata_destination")
    if (ip.is_multicast or ip.is_unspecified or ip.is_reserved or
            (isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"))):
        raise ScopeDenied("Reserved, multicast, broadcast, or unspecified IP is denied", reason_code="non_public_ip")
    if ip.is_global:
        return
    lab_enabled = settings.isolated_lab_enabled and grant.isolated_lab
    if lab_enabled and (ip.is_loopback or ip.is_private or ip.is_link_local):
        return
    raise ScopeDenied("Non-public IP destination is denied outside explicit isolated-lab mode", reason_code="non_public_ip")
