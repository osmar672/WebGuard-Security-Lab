"""Conservative URL and DNS policy for target registration.

Registration-time checks are defense in depth only. Any future job must use the
scope-bound client in security/webguard_scope at connection time and enforce egress
policy outside the process as well.
"""
import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

Resolver = Callable[[str], list[str]]

METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "metadata.azure.internal"}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),
}
_CONTROL = re.compile(r"[\x00-\x20\x7f\\]")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class ScopeError(ValueError):
    pass


def default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"hostname '{host}' could not be resolved") from exc
    return sorted({info[4][0].split("%")[0] for info in infos})


def _is_always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_reserved or ip.is_multicast or ip.is_unspecified or ip in METADATA_IPS


def _is_non_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_private or ip.is_link_local or not ip.is_global


def validate_target_url(url: str, *, allow_lab: bool, resolver: Resolver = default_resolver) -> tuple[str, str, bool]:
    """Return (canonical URL, hostname, is_lab_target), failing closed on invalid scope.

    This validates registration only; the network request layer must repeat it per
    request and redirect using a resolver/transport that pins validated addresses.
    """
    if not isinstance(url, str) or not url or _CONTROL.search(url) or _BAD_PERCENT.search(url):
        raise ScopeError("URL is malformed")
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        port = parts.port  # can raise for invalid or out-of-range ports
    except ValueError as exc:
        raise ScopeError("URL contains an invalid hostname or port") from exc
    if scheme not in {"http", "https"}:
        raise ScopeError("only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ScopeError("credentials in URLs are not allowed")
    if parts.query or parts.fragment:
        raise ScopeError("target base URL cannot contain a query string or fragment")
    if not parts.netloc or not parts.hostname:
        raise ScopeError("URL must include a hostname")

    raw_host = parts.hostname.lower().rstrip(".")
    if not raw_host or len(raw_host) > 253:
        raise ScopeError("hostname is invalid")
    try:
        literal = ipaddress.ip_address(raw_host.split("%")[0])
        host = literal.compressed.lower()
        addrs = [literal]
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError("hostname is invalid") from exc
        if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", host):
            raise ScopeError("hostname is invalid")
        if host in METADATA_HOSTS:
            raise ScopeError("cloud metadata endpoints are never allowed")
        try:
            resolved = resolver(host)
            addrs = [ipaddress.ip_address(address.split("%")[0]) for address in resolved]
        except ScopeError:
            raise
        except (ValueError, TypeError) as exc:
            raise ScopeError("hostname returned an invalid DNS address") from exc
        if not addrs:
            raise ScopeError("hostname resolved to no addresses")

    if any(address in METADATA_IPS for address in addrs):
        raise ScopeError("cloud metadata endpoints are never allowed")
    if any(_is_always_blocked(address) for address in addrs):
        raise ScopeError("reserved, multicast, and unspecified destinations are never allowed")

    non_public = [_is_non_public(address) for address in addrs]
    # A host with a public/private mixed DNS answer is unsafe even in lab mode.
    if any(non_public) and not all(non_public):
        raise ScopeError("hostname resolves to a mixture of public and non-public addresses")
    if all(non_public) and not allow_lab:
        raise ScopeError("target resolves to a loopback/private/link-local address; isolated-lab mode is disabled")

    if port is not None and not 1 <= port <= 65535:
        raise ScopeError("port is outside the valid range")
    display_host = f"[{host}]" if ":" in host else host
    explicit_port = f":{port}" if port is not None else ""
    normalized = f"{scheme}://{display_host}{explicit_port}{parts.path or '/'}"
    return normalized, host, bool(all(non_public))
