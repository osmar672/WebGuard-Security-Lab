"""Bounded, allow-listed tool adapters. Never executes a command supplied by a caller."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from app.config import Settings
from app.models import Target
from app.tooling.catalog import get_tool

PROFILE_LIMITS = {
    "quick": {"timeout": 35, "requests": 12, "concurrency": 1, "vus": 1, "duration": "10s", "examples": 5, "rate": 2},
    "standard": {"timeout": 120, "requests": 30, "concurrency": 2, "vus": 3, "duration": "30s", "examples": 15, "rate": 5},
    "exhaustive": {"timeout": 300, "requests": 50, "concurrency": 3, "vus": 5, "duration": "60s", "examples": 30, "rate": 8},
}
MAX_TOOL_OUTPUT_BYTES = 10 * 1024 * 1024
SENSITIVE_KEYS = {"secret", "secretvalue", "password", "token", "authorization", "apikey", "api_key", "privatekey", "private_key", "match", "raw"}


class ToolExecutionError(RuntimeError):
    """Safe error message suitable for persistence and user display."""


def _profile(profile: str) -> dict[str, Any]:
    if profile not in PROFILE_LIMITS:
        raise ToolExecutionError("Unsupported tool profile")
    return PROFILE_LIMITS[profile]


def _severity(value: Any) -> str:
    text = str(value or "info").lower()
    mapping = {
        "critical": "critical", "fatal": "critical", "high": "high", "error": "high",
        "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
        "low": "low", "info": "info", "informational": "info", "unknown": "info",
    }
    return mapping.get(text, "info")


def _finding(title: str, severity: str = "info", *, url: str | None = None,
             description: str = "", evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "title": str(title or "Untitled finding")[:300],
        "severity": _severity(severity),
        "url": str(url)[:2048] if url else None,
        "description": str(description or "")[:4000],
        "evidence": _redact(evidence or {}),
    }


def _redact(value: Any, key: str = "") -> Any:
    """Remove likely credentials / matched secret text before DB persistence or UI display."""
    if key.lower().replace("-", "").replace("_", "") in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            normalized = str(k).lower().replace("-", "").replace("_", "")
            if normalized in {"secret", "secretvalue", "password", "token", "authorization", "apikey", "privatekey", "match", "raw"}:
                out[str(k)] = "[REDACTED]"
            else:
                out[str(k)] = _redact(v, str(k))
        return out
    if isinstance(value, (list, tuple)):
        return [_redact(v, key) for v in value[:100]]
    if isinstance(value, str):
        # Avoid storing typical bearer/API key values in accidental free-form tool output.
        text = value[:4000]
        text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", text)
        return text
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:1000]


def _result(engine: str, summary: dict[str, Any], findings: list[dict[str, Any]], *, notes: list[str] | None = None) -> dict[str, Any]:
    safe_findings = [_redact(f) for f in findings[:1000]]
    return {
        "engine": engine,
        "summary": _redact(summary),
        "findings": safe_findings,
        "finding_count": len(safe_findings),
        "notes": (notes or [])[:30],
        "finished_at": datetime.now(UTC).isoformat(),
    }


def _make_grant(target: Target, settings: Settings, cancel_check: Callable[[], bool] | None = None):
    from webguard_scope.models import TargetAuthorization
    parsed = urlsplit(target.base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    rules = target.scope_rules or {}
    prefixes = rules.get("allowed_path_prefixes", ["/"]) if isinstance(rules, dict) else ["/"]
    if not isinstance(prefixes, list) or not prefixes or any(not isinstance(p, str) or not p.startswith("/") for p in prefixes):
        prefixes = ["/"]
    # Network scope stays pinned to the registered hostname and origin port. Arbitrary
    # scope_rules are not allowed to expand DNS/port scope; expanding scope needs a reviewed grant flow.
    allowed_hosts = [target.hostname]
    allowed_ports = [port]
    grant = TargetAuthorization(
        target_id=target.id,
        owner_id=target.owner_user_id or "admin-authorized",
        allowed_hosts=tuple(allowed_hosts),
        allowed_ports=tuple(set(allowed_ports)),
        allowed_path_prefixes=tuple(prefixes),
        authorization_reference=(target.authorization_note or "registered owner authorization"),
        isolated_lab=bool(target.is_lab_target),
        grant_id=f"target-{target.id}",
    )
    security = __import__("webguard_scope.models", fromlist=["SecuritySettings"]).SecuritySettings(
        isolated_lab_enabled=bool(settings.allow_lab_targets)
    )
    return grant, security


async def _safe_response(target: Target, settings: Settings, cancel_check: Callable[[], bool] | None = None):
    from webguard_scope.client import ScopeBoundHttpClient
    from webguard_scope.models import JobLimits
    grant, security = _make_grant(target, settings, cancel_check)
    limits = JobLimits(
        max_requests=12, max_concurrency=1, request_timeout_seconds=8,
        max_response_bytes=512_000, max_job_duration_seconds=min(settings.tool_job_timeout_seconds, 45),
        max_redirects=3,
    )
    async with ScopeBoundHttpClient(grant, security, limits, actor_id=target.owner_user_id or "worker",
                                   authorization_check=cancel_check) as client:
        return await client.request("GET", target.base_url, headers={"User-Agent": "WebGuard-Security-Lab/0.7"})


async def _dns_records(target: Target, settings: Settings, cancel_check: Callable[[], bool] | None = None) -> list[dict[str, Any]]:
    from webguard_scope.resolver import ScopeBoundResolver
    grant, security = _make_grant(target, settings, cancel_check)
    parsed = urlsplit(target.base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolver = ScopeBoundResolver(grant, security, authorization_check=cancel_check)
    try:
        return await resolver.resolve(target.hostname, port)
    finally:
        await resolver.close()


def _dns_audit(target: Target, settings: Settings, cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    records = asyncio.run(_dns_records(target, settings, cancel_check))
    addresses = sorted({record["host"] for record in records})
    findings: list[dict[str, Any]] = []
    if len(addresses) > 1:
        findings.append(_finding(
            "Hostname has multiple validated DNS addresses", "info", url=target.base_url,
            description="The resolver returned multiple public or explicitly authorized lab addresses. All returned addresses were validated by the scope-aware resolver.",
            evidence={"address_count": len(addresses), "addresses": addresses},
        ))
    return _result("dns_audit", {"hostname": target.hostname, "validated_addresses": addresses, "address_count": len(addresses)}, findings)


def _headers_audit(target: Target, settings: Settings, engine: str = "http_headers", cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    response = asyncio.run(_safe_response(target, settings, cancel_check))
    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    findings: list[dict[str, Any]] = []
    https = urlsplit(target.base_url).scheme == "https"
    checks = [
        ("content-security-policy", "Content Security Policy is missing", "medium"),
        ("x-content-type-options", "X-Content-Type-Options is missing", "low"),
        ("referrer-policy", "Referrer-Policy is missing", "low"),
        ("permissions-policy", "Permissions-Policy is missing", "info"),
    ]
    if https:
        checks.append(("strict-transport-security", "HTTP Strict Transport Security is missing", "medium"))
    if not any(token in headers.get("content-security-policy", "").lower() for token in ["frame-ancestors"]):
        if "x-frame-options" not in headers:
            findings.append(_finding("Clickjacking defense was not observed", "low", url=response.url,
                                     description="Neither X-Frame-Options nor a CSP frame-ancestors directive was found."))
    for key, title, severity in checks:
        if not headers.get(key):
            findings.append(_finding(title, severity, url=response.url, description=f"The response did not contain the {key} header."))
    server = headers.get("server")
    if server:
        findings.append(_finding("Server header reveals implementation details", "info", url=response.url,
                                 description="Review whether the Server header needs to disclose product/version information.",
                                 evidence={"server_header_present": True}))
    return _result(engine, {"http_status": response.status, "checked_url": response.url,
                            "headers_present": sorted(headers.keys()), "header_count": len(headers)}, findings,
                   notes=["A header-only check cannot prove an application secure; review headers and application behavior manually."])


def _auth_surface(target: Target, settings: Settings, cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    response = asyncio.run(_safe_response(target, settings, cancel_check))
    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    findings: list[dict[str, Any]] = []
    cookies = headers.get("set-cookie", "")
    if cookies:
        lower = cookies.lower()
        for token, label, severity in [
            ("secure", "Cookie lacks the Secure attribute", "medium"),
            ("httponly", "Cookie lacks the HttpOnly attribute", "medium"),
            ("samesite", "Cookie lacks the SameSite attribute", "low"),
        ]:
            # Conservative string test; a production parser should process every cookie separately.
            if token not in lower:
                findings.append(_finding(label, severity, url=response.url,
                                         description="At least one observed Set-Cookie response did not advertise this attribute."))
    else:
        findings.append(_finding("No Set-Cookie header observed on the landing page", "info", url=response.url,
                                 description="This is informational only; the page may not set cookies until a login flow is used."))
    if not headers.get("www-authenticate") and response.status in (401, 403):
        findings.append(_finding("Unauthorized response lacks WWW-Authenticate", "info", url=response.url,
                                 description="Review whether the API or endpoint needs a challenge header for its authentication scheme."))
    return _result("auth_surface", {"http_status": response.status, "cookie_header_observed": bool(cookies),
                                    "www_authenticate_observed": bool(headers.get("www-authenticate"))}, findings,
                   notes=["No credentials were submitted and no login guessing or brute force was performed."])


def _tls_audit(target: Target, settings: Settings, engine: str = "tls_audit", cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    parsed = urlsplit(target.base_url)
    if parsed.scheme != "https":
        return _result(engine, {"applicable": False, "reason": "Target base URL is HTTP, not HTTPS."}, [],
                       notes=["Register an HTTPS base URL to run certificate checks."])
    grant, security = _make_grant(target, settings, cancel_check)
    from webguard_scope.resolver import ScopeBoundResolver

    async def resolve_checked():
        resolver = ScopeBoundResolver(grant, security, authorization_check=cancel_check)
        port = parsed.port or 443
        try:
            records = await resolver.resolve(target.hostname, port)
            return records
        finally:
            await resolver.close()

    records = asyncio.run(resolve_checked())
    port = parsed.port or 443
    context = ssl.create_default_context()
    details: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    connected = False
    for record in records[:4]:
        try:
            # Connect to the resolver-validated numeric address, while preserving SNI and hostname verification.
            with socket.create_connection((record["host"], port), timeout=8) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=target.hostname) as tls_socket:
                    cert = tls_socket.getpeercert()
                    cipher = tls_socket.cipher()
                    connected = True
                    not_after = cert.get("notAfter") if cert else None
                    expires_days = None
                    if not_after:
                        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
                        expires_days = int((expires - datetime.now(UTC)).total_seconds() // 86400)
                    details = {"hostname": target.hostname, "port": port, "tls_version": tls_socket.version(),
                               "cipher": cipher[0] if cipher else None, "certificate_subject": _cert_name(cert.get("subject", [])),
                               "certificate_issuer": _cert_name(cert.get("issuer", [])), "expires_at": not_after,
                               "certificate_days_remaining": expires_days, "validated_ip": record["host"],
                               "san_count": len(cert.get("subjectAltName", []))}
                    if expires_days is not None and expires_days < 0:
                        findings.append(_finding("TLS certificate is expired", "high", url=target.base_url,
                                                 description="The certificate presented by the server is past its notAfter date.", evidence={"days_expired": abs(expires_days)}))
                    elif expires_days is not None and expires_days <= 30:
                        findings.append(_finding("TLS certificate expires within 30 days", "medium", url=target.base_url,
                                                 description="Schedule certificate renewal before it expires.", evidence={"days_remaining": expires_days}))
                    if tls_socket.version() in {"TLSv1", "TLSv1.1"}:
                        findings.append(_finding("Deprecated TLS version negotiated", "high", url=target.base_url,
                                                 description="The negotiated TLS protocol is obsolete; disable legacy protocol versions."))
                    break
        except Exception as exc:
            errors.append(type(exc).__name__)
    if not connected:
        findings.append(_finding("TLS handshake or certificate validation failed", "high", url=target.base_url,
                                 description="A TLS handshake could not be completed with a certificate trusted by the worker's trust store.", evidence={"error_types": sorted(set(errors))}))
    return _result(engine, details or {"hostname": target.hostname, "port": port, "validated_ip_count": len(records)}, findings,
                   notes=["The check connects directly to a DNS-validated IP address while verifying the expected hostname.",
                          "The worker trust store is used for certificate validation; this is not a full cipher-suite audit."])


def _cert_name(value: Any) -> str | None:
    try:
        return ", ".join("=".join(pair) for item in value for pair in item)[:500] or None
    except Exception:
        return None


def _playwright_check(target: Target, settings: Settings, *, accessibility: bool,
                      cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    if not settings.playwright_enabled:
        raise ToolExecutionError("Playwright is disabled; set WEBGUARD_PLAYWRIGHT_ENABLED=true and install Chromium")
    try:
        import playwright  # noqa: F401
    except ImportError as exc:
        raise ToolExecutionError("Playwright Python package is not installed in the worker environment") from exc
    script = Path(__file__).resolve().parent.parent / "tool_scripts" / "browser_probe.py"
    with tempfile.TemporaryDirectory(prefix="webguard-browser-") as scratch:
        output = Path(scratch) / "result.json"
        argv = [os.sys.executable, str(script), "--target", target.base_url, "--hostname", target.hostname,
                "--output", str(output), "--allow-lab" if target.is_lab_target and settings.allow_lab_targets else "--public-only",
                "--accessibility" if accessibility else "--browser"]
        completed = _run_command(argv, timeout=min(settings.tool_job_timeout_seconds, 90), cwd=Path(scratch),
                                 cancel_check=cancel_check,
                                 env_extra={"PYTHONPATH": str(Path(__file__).resolve().parents[2])})
        if completed["returncode"] != 0:
            raise ToolExecutionError("Playwright browser check failed to launch or complete; see worker logs for the non-sensitive error category")
        try:
            data = json.loads(output.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ToolExecutionError("Playwright did not produce a valid JSON result") from exc
    findings = data.get("findings", []) if isinstance(data, dict) else []
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    return _result("accessibility" if accessibility else "playwright", summary, findings,
                   notes=["Every top-level navigation and subresource is intercepted; off-scope hosts are blocked.",
                          "A browser runner still requires deployment-level egress filtering to protect against DNS rebinding."])


def _workspace_root(settings: Settings) -> Path:
    configured = settings.workspace_scan_root
    if not configured:
        raise ToolExecutionError("Code scanning is not configured. Set WEBGUARD_WORKSPACE_SCAN_ROOT on the server.")
    root = Path(configured).expanduser().resolve(strict=True)
    if not root.is_dir() or root == Path("/") or root == Path.home().resolve():
        raise ToolExecutionError("Configured workspace scan root is not an allowed project directory")
    return root


def _external_command(engine: str, target: Target | None, settings: Settings, profile: str, temp: Path) -> tuple[list[str], Path | None]:
    limits = _profile(profile)
    target_url = target.base_url if target else None
    parsed = urlsplit(target_url) if target_url else None
    if engine == "nuclei":
        path = shutil.which(settings.nuclei_path)
        if not path: raise ToolExecutionError("Nuclei executable is unavailable in the worker PATH")
        return [path, "-u", target_url or "", "-jsonl", "-silent", "-rate-limit", str(limits["rate"]),
                "-concurrency", str(limits["concurrency"]), "-retries", "0", "-timeout", "5",
                "-disable-redirects", "-tags", "misconfig,exposure", "-disable-update-check"], None
    if engine == "schemathesis":
        path = shutil.which(settings.schemathesis_path)
        if not path: raise ToolExecutionError("Schemathesis executable is unavailable in the worker PATH")
        spec_url = target_url.rstrip("/") + "/openapi.json"
        return [path, "run", spec_url, "--max-examples", str(limits["examples"]), "--workers", "1",
                "--max-response-time", "5000"], None
    if engine == "k6":
        path = shutil.which(settings.k6_path)
        if not path: raise ToolExecutionError("k6 executable is unavailable in the worker PATH")
        script = temp / "webguard-k6.js"
        summary = temp / "k6-summary.json"
        script.write_text(
            "import http from 'k6/http';\nimport { check, sleep } from 'k6';\n"
            f"export const options = {{ vus: {limits['vus']}, duration: '{limits['duration']}', maxRedirects: 0, "
            "thresholds: { http_req_failed: ['rate<0.05'], http_req_duration: ['p(95)<2000'] } };\n"
            "export default function () { const r = http.get(__ENV.WEBGUARD_TARGET, { timeout: '5s', redirects: 0 }); "
            "check(r, { 'status is below 500': (x) => x.status < 500 }); sleep(1); }\n",
            encoding="utf-8",
        )
        return [path, "run", "--summary-export", str(summary), str(script)], summary
    if engine == "testssl":
        path = shutil.which(settings.testssl_path)
        if not path: raise ToolExecutionError("testssl.sh executable is unavailable in the worker PATH")
        if parsed is None or parsed.scheme != "https":
            raise ToolExecutionError("testssl.sh requires an HTTPS target")
        port = parsed.port or 443
        report = temp / "testssl.json"
        return [path, "--quiet", "--warnings", "batch", "--color", "0", "--fast", "--jsonfile-pretty", str(report),
                f"{parsed.hostname}:{port}"], report
    if engine in {"trivy", "semgrep", "gitleaks", "sbom"}:
        root = _workspace_root(settings)
        if engine == "trivy":
            path = shutil.which(settings.trivy_path)
            if not path: raise ToolExecutionError("Trivy executable is unavailable in the worker PATH")
            return [path, "fs", "--no-progress", "--format", "json", "--scanners", "vuln,misconfig,secret", str(root)], None
        if engine == "sbom":
            path = shutil.which(settings.trivy_path)
            if not path: raise ToolExecutionError("Trivy executable is unavailable in the worker PATH")
            report = temp / "sbom.cdx.json"
            return [path, "fs", "--no-progress", "--format", "cyclonedx", "--output", str(report), str(root)], report
        if engine == "semgrep":
            path = shutil.which(settings.semgrep_path)
            if not path: raise ToolExecutionError("Semgrep executable is unavailable in the worker PATH")
            return [path, "scan", "--config", "p/security-audit", "--json", "--metrics=off", "--timeout", "30", str(root)], None
        path = shutil.which(settings.gitleaks_path)
        if not path: raise ToolExecutionError("Gitleaks executable is unavailable in the worker PATH")
        report = temp / "gitleaks.json"
        return [path, "dir", "--report-format", "json", "--report-path", str(report), "--redact", str(root)], report
    raise ToolExecutionError(f"No command adapter exists for engine '{engine}'")


def _run_command(argv: list[str], *, timeout: int, cwd: Path, cancel_check: Callable[[], bool] | None,
                 env_extra: dict[str, str] | None = None) -> dict[str, Any]:
    """Run a fixed argv without shell interpolation, with timeout and bounded output files."""
    if not argv or not Path(argv[0]).is_absolute():
        raise ToolExecutionError("Tool executable path is invalid")
    stdout_path, stderr_path = cwd / "stdout.log", cwd / "stderr.log"
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(cwd), "TMPDIR": str(cwd), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "NO_PROXY": "*", "no_proxy": "*", "CI": "1",
        "PLAYWRIGHT_BROWSERS_PATH": os.environ.get("PLAYWRIGHT_BROWSERS_PATH", str(Path.home() / ".cache" / "ms-playwright")),
    }
    if env_extra: env.update(env_extra)

    def limits() -> None:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES))
            cpu_seconds = max(10, min(timeout + 5, 610))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        except Exception:
            pass

    start = time.monotonic()
    try:
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, shell=False, close_fds=True,
                                       start_new_session=True, preexec_fn=limits if os.name == "posix" else None)
            while process.poll() is None:
                if cancel_check and cancel_check():
                    try: os.killpg(process.pid, 15)
                    except (ProcessLookupError, PermissionError): process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, 9)
                        except (ProcessLookupError, PermissionError): process.kill()
                    raise ToolExecutionError("Tool run was cancelled")
                if time.monotonic() - start > timeout:
                    try: os.killpg(process.pid, 15)
                    except (ProcessLookupError, PermissionError): process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, 9)
                        except (ProcessLookupError, PermissionError): process.kill()
                    raise ToolExecutionError(f"Tool exceeded its {timeout}-second execution timeout")
                time.sleep(0.15)
            returncode = process.returncode
        if stdout_path.stat().st_size > MAX_TOOL_OUTPUT_BYTES or stderr_path.stat().st_size > MAX_TOOL_OUTPUT_BYTES:
            raise ToolExecutionError("Tool output exceeded the configured size limit")
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")[-12000:]
        # Persist only the stderr category, not arbitrary diagnostic output which can contain secrets.
        return {"returncode": returncode, "stdout": stdout[:MAX_TOOL_OUTPUT_BYTES],
                "stderr_tail": stderr, "duration_seconds": round(time.monotonic() - start, 2)}
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"Tool executable not found: {Path(argv[0]).name}") from exc


def _parse_jsonl(text: str, engine: str, target_url: str | None) -> list[dict[str, Any]]:
    findings = []
    for line in text.splitlines()[:5000]:
        try: item = json.loads(line)
        except Exception: continue
        info = item.get("info") or {}
        if engine == "nuclei":
            findings.append(_finding(info.get("name") or item.get("template-id") or "Nuclei finding",
                                     info.get("severity"), url=item.get("matched-at") or target_url,
                                     description=info.get("description") or info.get("name") or "Template matched.",
                                     evidence={"template_id": item.get("template-id"), "matcher_name": item.get("matcher-name")}))
    return findings


def _parse_trivy(data: dict[str, Any], root_url: str | None) -> list[dict[str, Any]]:
    findings = []
    for result in (data.get("Results") or [])[:500]:
        target = result.get("Target", "")
        for vuln in (result.get("Vulnerabilities") or [])[:500]:
            findings.append(_finding(
                f"{vuln.get('VulnerabilityID', 'Vulnerability')} — {vuln.get('PkgName', 'package')}",
                vuln.get("Severity"), description=vuln.get("Title") or vuln.get("Description") or "Dependency vulnerability reported by Trivy.",
                evidence={"target": target, "vulnerability_id": vuln.get("VulnerabilityID"), "installed_version": vuln.get("InstalledVersion"),
                          "fixed_version": vuln.get("FixedVersion"), "primary_url": vuln.get("PrimaryURL")}))
        for item in (result.get("Misconfigurations") or [])[:500]:
            findings.append(_finding(item.get("Title") or item.get("ID") or "Misconfiguration", item.get("Severity"),
                                     description=item.get("Description") or item.get("Message") or "Configuration issue reported by Trivy.",
                                     evidence={"target": target, "id": item.get("ID"), "resolution": item.get("Resolution")}))
        for item in (result.get("Secrets") or [])[:500]:
            findings.append(_finding(item.get("Title") or item.get("RuleID") or "Potential secret detected", item.get("Severity", "high"),
                                     description="A possible secret was detected. WebGuard intentionally does not store the matched value.",
                                     evidence={"target": target, "rule_id": item.get("RuleID"), "category": item.get("Category")}))
    return findings[:1000]


def _parse_external(engine: str, stdout: str, report_path: Path | None, target_url: str | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    report_data: Any = None
    if report_path and report_path.exists() and report_path.stat().st_size <= MAX_TOOL_OUTPUT_BYTES:
        try: report_data = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except Exception: report_data = None
    if report_data is None and engine == "semgrep" and stdout.strip():
        try:
            report_data = json.loads(stdout)
        except Exception:
            report_data = None
    if report_data is None and engine == "testssl" and stdout.strip():
        # Some testssl.sh releases emit JSON on stdout instead of the configured report file.
        try:
            report_data = json.loads(stdout)
        except Exception:
            report_data = None
    if engine == "nuclei":
        findings = _parse_jsonl(stdout, engine, target_url)
    elif engine == "schemathesis":
        findings = []
        for line in stdout.splitlines()[-40:]:
            if any(token in line.lower() for token in ("failure", "error", "failed")):
                findings.append(_finding("Schemathesis reported an API test failure", "medium", url=target_url,
                                         description=line[:800], evidence={"source": "bounded CLI summary"}))
        report_data = {"output_tail": "\n".join(stdout.splitlines()[-80:])[:6000]}
    elif engine == "k6":
        metrics = (report_data or {}).get("metrics", {}) if isinstance(report_data, dict) else {}
        failed = metrics.get("http_req_failed", {}).get("values", {}) if isinstance(metrics, dict) else {}
        duration = metrics.get("http_req_duration", {}).get("values", {}) if isinstance(metrics, dict) else {}
        failed_rate = failed.get("rate") if isinstance(failed, dict) else None
        p95 = duration.get("p(95)") if isinstance(duration, dict) else None
        if isinstance(failed_rate, (int, float)) and failed_rate > 0.05:
            findings.append(_finding("Load test exceeded HTTP failure threshold", "high", url=target_url,
                                     description="More than 5% of requests failed during the bounded k6 profile.", evidence={"failure_rate": failed_rate}))
        if isinstance(p95, (int, float)) and p95 > 2000:
            findings.append(_finding("Load test exceeded p95 latency threshold", "medium", url=target_url,
                                     description="The p95 HTTP request duration was above the configured 2000 ms threshold.", evidence={"p95_ms": p95}))
    elif engine == "trivy" and isinstance(report_data, dict):
        findings = _parse_trivy(report_data, target_url)
    elif engine == "semgrep" and isinstance(report_data, dict):
        for item in (report_data.get("results") or [])[:1000]:
            extra = item.get("extra") or {}
            findings.append(_finding(extra.get("message") or item.get("check_id") or "Semgrep finding", extra.get("severity"),
                                     description=extra.get("message") or "Static analysis rule matched.",
                                     evidence={"rule_id": item.get("check_id"), "path": item.get("path"),
                                               "line": (item.get("start") or {}).get("line"), "column": (item.get("start") or {}).get("col")}))
    elif engine == "gitleaks" and isinstance(report_data, list):
        for item in report_data[:1000]:
            findings.append(_finding(f"Potential secret: {item.get('RuleID', 'rule')}", "high",
                                     description=(item.get("Description") or "Gitleaks detected a potential secret.") + " Matched secret text is not stored.",
                                     evidence={"rule_id": item.get("RuleID"), "file": item.get("File"), "line": item.get("StartLine")}))
    elif engine == "testssl" and isinstance(report_data, (list, dict)):
        entries = report_data if isinstance(report_data, list) else report_data.get("scanResult", [])
        if isinstance(entries, list):
            for item in entries[:1000]:
                if not isinstance(item, dict):
                    continue
                severity = item.get("severity") or item.get("severity_local") or item.get("finding") or "info"
                if str(severity).lower() in {"high", "critical", "medium", "low", "warning"} or item.get("id"):
                    findings.append(_finding(item.get("finding") or item.get("id") or "TLS finding", severity,
                                             url=target_url, description=item.get("cve") or item.get("severity_local") or "TLS test result.",
                                             evidence={"id": item.get("id"), "severity": item.get("severity"), "ip": item.get("ip")}))
    elif engine == "zap" and isinstance(report_data, list):
        for item in report_data[:1000]:
            risk_map = {"0": "info", "1": "low", "2": "medium", "3": "high"}
            findings.append(_finding(item.get("alert") or "ZAP alert", risk_map.get(str(item.get("riskcode")), "info"),
                                     url=item.get("url") or target_url, description=item.get("description") or "ZAP passive alert.",
                                     evidence={"plugin_id": item.get("pluginId"), "confidence": item.get("confidence"), "cweid": item.get("cweid")}))
    summary: dict[str, Any] = {"returncode": 0, "parsed_findings": len(findings)}
    if engine == "k6" and isinstance(report_data, dict):
        summary["metrics"] = _redact(report_data.get("metrics", {}))
    elif engine == "schemathesis":
        summary["summary"] = report_data
    elif engine in {"trivy", "semgrep", "gitleaks", "testssl", "zap"}:
        summary["report_available"] = report_data is not None
    return summary, findings


def _zap_run(target: Target, settings: Settings, profile: str, temp: Path, cancel_check: Callable[[], bool] | None) -> dict[str, Any]:
    if not settings.zap_api_url or not settings.zap_api_key:
        raise ToolExecutionError("Configure WEBGUARD_ZAP_API_URL and WEBGUARD_ZAP_API_KEY")
    if not settings.external_tools_enabled or not settings.egress_policy_confirmed:
        raise ToolExecutionError("External engines require explicit enablement and deployment-level egress controls")
    import httpx
    base = settings.zap_api_url.rstrip("/")
    parsed = urlsplit(target.base_url)
    # New context avoids inheriting arbitrary include/exclude rules from a shared ZAP session.
    context_name = f"webguard-{target.id[:8]}-{int(time.time())}"
    headers = {"X-ZAP-API-Key": settings.zap_api_key, "Accept": "application/json"}
    timeout = min(settings.tool_job_timeout_seconds, PROFILE_LIMITS[profile]["timeout"])
    report_path = temp / "zap-alerts.json"
    escaped_origin = re.escape(f"{parsed.scheme}://{parsed.netloc}")
    scope_regex = "^" + escaped_origin + re.escape(parsed.path or "/") + ".*$"
    with httpx.Client(timeout=8, headers=headers, follow_redirects=False) as client:
        def call(component: str, params: dict[str, Any]) -> dict[str, Any]:
            try:
                response = client.get(f"{base}/JSON/{component}/", params=params)
                response.raise_for_status()
                data = response.json()
            except Exception as exc:
                raise ToolExecutionError(f"ZAP API call failed in {component.split('/')[0]} ({type(exc).__name__})") from exc
            if not isinstance(data, dict) or data.get("code") == "error":
                raise ToolExecutionError("ZAP returned an invalid API response")
            return data
        call("context/action/newContext", {"contextName": context_name})
        call("context/action/includeInContext", {"contextName": context_name, "regex": scope_regex})
        spider = call("spider/action/scan", {"url": target.base_url, "contextName": context_name,
                                              "maxChildren": 10 if profile == "quick" else 30,
                                              "recurse": "true", "subtreeOnly": "true"})
        scan_id = str(spider.get("scan", "0"))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cancel_check and cancel_check():
                raise ToolExecutionError("Tool run was cancelled")
            status = call("spider/view/status", {"scanId": scan_id}).get("status", "0")
            if str(status) == "100": break
            time.sleep(1)
        else:
            raise ToolExecutionError("ZAP spider exceeded the configured timeout")
        # Wait for passive scan queue to drain; never call the active scanner API.
        while time.monotonic() < deadline:
            if cancel_check and cancel_check(): raise ToolExecutionError("Tool run was cancelled")
            remaining = call("pscan/view/recordsToScan", {}).get("recordsToScan", "0")
            if str(remaining) in {"0", "0.0"}: break
            time.sleep(1)
        alerts = call("core/view/alerts", {"baseurl": target.base_url, "start": 0, "count": 1000}).get("alerts", [])
        if not isinstance(alerts, list): alerts = []
        report_path.write_text(json.dumps(alerts[:1000]), encoding="utf-8")
    summary, findings = _parse_external("zap", "", report_path, target.base_url)
    summary.update({"scan_type": "spider_and_passive_only", "alert_count": len(findings)})
    return _result("zap", summary, findings, notes=["ZAP active scan endpoints are not called by this adapter.",
                                                       "The ZAP instance must be isolated and constrained by an outbound firewall."])


def execute_target_tool(engine: str, target: Target, settings: Settings, profile: str,
                        *, cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    definition = get_tool(engine)
    if definition is None or not definition.requires_target:
        raise ToolExecutionError("Unknown target tool")
    if not settings.tool_execution_enabled:
        raise ToolExecutionError("Tool execution is disabled. Set WEBGUARD_TOOL_EXECUTION_ENABLED=true after reviewing the safety guide.")
    if target.authorization_status.value != "authorized":
        raise ToolExecutionError("Target authorization has not been verified")
    if target.is_lab_target and not settings.allow_lab_targets:
        raise ToolExecutionError("Local lab targets require WEBGUARD_ALLOW_LAB_TARGETS=true")
    if definition.kind == "external" and (not settings.external_tools_enabled or not settings.egress_policy_confirmed):
        raise ToolExecutionError("External engines require explicit enablement and deployment-level egress controls")
    if engine == "dns_audit": return _dns_audit(target, settings, cancel_check)
    if engine == "http_headers": return _headers_audit(target, settings, cancel_check=cancel_check)
    if engine == "tls_audit": return _tls_audit(target, settings, cancel_check=cancel_check)
    if engine == "auth_surface": return _auth_surface(target, settings, cancel_check)
    if engine == "playwright": return _playwright_check(target, settings, accessibility=False, cancel_check=cancel_check)
    if engine == "accessibility": return _playwright_check(target, settings, accessibility=True, cancel_check=cancel_check)
    if engine == "zap":
        if not settings.external_tools_enabled or not settings.egress_policy_confirmed:
            raise ToolExecutionError("External engines require explicit enablement and deployment-level egress controls")
        with tempfile.TemporaryDirectory(prefix="webguard-zap-") as td:
            return _zap_run(target, settings, profile, Path(td), cancel_check)
    if definition.kind == "external" and (not settings.external_tools_enabled or not settings.egress_policy_confirmed):
        raise ToolExecutionError("External engines require explicit enablement and deployment-level egress controls")
    limits = _profile(profile)
    with tempfile.TemporaryDirectory(prefix=f"webguard-{engine}-") as td:
        temp = Path(td)
        command, report = _external_command(engine, target, settings, profile, temp)
        env_extra = {"WEBGUARD_TARGET": target.base_url} if engine == "k6" else None
        command_timeout = min(settings.tool_job_timeout_seconds, limits["timeout"])
        executed = _run_command(command, timeout=command_timeout, cwd=temp, cancel_check=cancel_check, env_extra=env_extra)
        if executed["returncode"] != 0 and not executed["stdout"].strip() and not (report and report.exists()):
            # Tool output can contain credentials or local paths; only surface command/exit categories.
            raise ToolExecutionError(f"{engine} exited with code {executed['returncode']}; inspect worker logs for details")
        summary, findings = _parse_external(engine, executed["stdout"], report, target.base_url)
        summary.update({"duration_seconds": executed["duration_seconds"], "returncode": executed["returncode"]})
        if executed["returncode"] != 0:
            notes = [f"The tool exited with non-zero status {executed['returncode']}; results may be partial."]
        else:
            notes = []
        # Never return raw tool stdout/stderr; some tools may print tokens or matched secret text.
        return _result(engine, summary, findings, notes=notes)


def execute_workspace_tool(engine: str, settings: Settings, profile: str,
                           *, cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    if engine not in {"trivy", "semgrep", "gitleaks", "sbom"}:
        raise ToolExecutionError("Only the configured source-security tools may scan a workspace")
    if not settings.tool_execution_enabled or not settings.external_tools_enabled or not settings.egress_policy_confirmed:
        raise ToolExecutionError("Workspace scanners require tool execution and external engines enabled with egress policy confirmed")
    if engine == "semgrep" and not settings.semgrep_path:
        raise ToolExecutionError("Configure WEBGUARD_SEMGREP_PATH")
    limits = _profile(profile)
    with tempfile.TemporaryDirectory(prefix=f"webguard-{engine}-") as td:
        temp = Path(td)
        command, report = _external_command(engine, None, settings, profile, temp)
        executed = _run_command(command, timeout=min(settings.tool_job_timeout_seconds, limits["timeout"]),
                                cwd=temp, cancel_check=cancel_check)
        if executed["returncode"] != 0 and not executed["stdout"].strip() and not (report and report.exists()):
            raise ToolExecutionError(f"{engine} exited with code {executed['returncode']}; inspect worker logs for details")
        stdout = executed["stdout"]
        sbom_document = None
        if engine == "trivy":
            try: data = json.loads(stdout)
            except Exception as exc: raise ToolExecutionError("Trivy output was not valid JSON") from exc
            findings = _parse_trivy(data, None)
            summary = {"targets_scanned": len(data.get("Results") or []), "duration_seconds": executed["duration_seconds"], "returncode": executed["returncode"]}
        elif engine == "sbom":
            if not report or not report.exists() or report.stat().st_size > 5 * 1024 * 1024:
                raise ToolExecutionError("CycloneDX SBOM is missing or exceeds the 5 MiB storage limit")
            try: sbom_document = json.loads(report.read_text(encoding="utf-8"))
            except Exception as exc: raise ToolExecutionError("Trivy output was not valid CycloneDX JSON") from exc
            components = sbom_document.get("components", []) if isinstance(sbom_document, dict) else []
            if not isinstance(components, list) or len(components) > 10000:
                raise ToolExecutionError("CycloneDX SBOM has an invalid or excessive component count")
            summary = {"format": "CycloneDX", "component_count": len(components),
                       "spec_version": sbom_document.get("specVersion"), "duration_seconds": executed["duration_seconds"],
                       "returncode": executed["returncode"], "sbom_document_available": True}
            findings = []
        else:
            summary, findings = _parse_external(engine, stdout, report, None)
            summary.update({"duration_seconds": executed["duration_seconds"], "returncode": executed["returncode"]})
        root = _workspace_root(settings)
        result = _result(engine, {**summary, "workspace_label": root.name}, findings,
                         notes=["Scan scope comes from WEBGUARD_WORKSPACE_SCAN_ROOT; API clients cannot submit filesystem paths.",
                                "Secret match contents are intentionally omitted from stored findings."])
        if sbom_document is not None:
            result["sbom_document"] = sbom_document
        return result
