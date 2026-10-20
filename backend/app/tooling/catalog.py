"""Single source of truth for tools shown by the API and dashboard."""
from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass
from typing import Literal

from app.config import Settings

Category = Literal["web_security", "api_testing", "browser", "performance", "code_security", "configuration"]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    id: str
    name: str
    category: Category
    description: str
    kind: Literal["builtin", "external"]
    profiles: tuple[str, ...] = ("quick", "standard", "exhaustive")
    requires_target: bool = True
    active_testing: bool = True
    executable_setting: str | None = None
    built_in_module: str | None = None


TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition("http_headers", "HTTP Security Headers", "configuration", "Inspect response headers, cookie attributes and basic browser security policy using the scope-bound HTTP client.", "builtin", active_testing=False, built_in_module="headers"),
    ToolDefinition("dns_audit", "DNS Exposure Audit", "configuration", "Resolve the authorized hostname and reject non-public or mixed destinations according to the configured scope policy.", "builtin", active_testing=False, built_in_module="dns"),
    ToolDefinition("tls_audit", "TLS Certificate Audit", "configuration", "Inspect the TLS certificate chain, expiry and negotiated TLS parameters for the authorized hostname.", "builtin", active_testing=False, built_in_module="tls"),
    ToolDefinition("auth_surface", "Authentication Surface Review", "web_security", "Check observable authentication-related headers and cookie flags without brute forcing accounts or submitting credentials.", "builtin", active_testing=False, built_in_module="auth"),
    ToolDefinition("zap", "OWASP ZAP Baseline", "web_security", "Run ZAP spider/passive analysis through a separately configured ZAP API; active attack scanning is not enabled by this adapter.", "external", executable_setting="zap_api_url"),
    ToolDefinition("nuclei", "Nuclei Safe Templates", "web_security", "Run a rate-limited template scan using misconfiguration/exposure tags and no redirects by default.", "external", executable_setting="nuclei_path"),
    ToolDefinition("schemathesis", "Schemathesis API Tests", "api_testing", "Exercise an OpenAPI endpoint with bounded property-based cases and a single worker.", "external", executable_setting="schemathesis_path"),
    ToolDefinition("k6", "Grafana k6 Performance", "performance", "Run a bounded load profile with fixed low virtual-user limits and explicit HTTP latency/error thresholds.", "external", executable_setting="k6_path"),
    ToolDefinition("playwright", "Playwright Browser Audit", "browser", "Open the authorized URL in a headless browser, record console/network errors and inspect the DOM; cross-origin requests are blocked.", "external", executable_setting="playwright_enabled"),
    ToolDefinition("accessibility", "Browser Accessibility Checks", "browser", "Run practical DOM accessibility checks for labels, image text, button names, document language and heading structure.", "external", executable_setting="playwright_enabled"),
    ToolDefinition("trivy", "Trivy Dependency / Misconfiguration Scan", "code_security", "Inspect the server-configured source workspace for dependency vulnerabilities, misconfiguration and exposed secrets; no client-supplied path is accepted.", "external", requires_target=False, executable_setting="trivy_path"),
    ToolDefinition("sbom", "CycloneDX SBOM Export", "code_security", "Generate a machine-readable CycloneDX software bill of materials from the server-configured workspace using Trivy.", "external", requires_target=False, active_testing=False, executable_setting="trivy_path"),
    ToolDefinition("semgrep", "Semgrep SAST", "code_security", "Run static application-security rules against the server-configured source workspace.", "external", requires_target=False, executable_setting="semgrep_path"),
    ToolDefinition("gitleaks", "Gitleaks Secret Scan", "code_security", "Search the server-configured source workspace for accidental secrets without returning secret values in findings.", "external", requires_target=False, executable_setting="gitleaks_path"),
    ToolDefinition("testssl", "testssl.sh TLS Audit", "configuration", "Inspect TLS protocols and cryptographic configuration for the authorized host/port.", "external", executable_setting="testssl_path"),
    ToolDefinition("reports", "Report Export & Regression", "configuration", "Export normalized findings as JSON, HTML or SARIF and compare two runs for new/resolved findings.", "builtin", requires_target=False, active_testing=False, built_in_module="reports"),
)


def catalog(settings: Settings) -> list[dict]:
    output = []
    for tool in TOOLS:
        detail = ""
        state = "available"
        if tool.id == "reports":
            state = "available"
            detail = "Report export and baseline comparison are built into the API; they do not run target traffic."
        elif not settings.tool_execution_enabled:
            state = "disabled"
            detail = "Set WEBGUARD_TOOL_EXECUTION_ENABLED=true after reviewing the deployment safety guide."
        elif tool.kind == "external":
            if not settings.external_tools_enabled or not settings.egress_policy_confirmed:
                state = "disabled"
                detail = "External engines are disabled until WEBGUARD_EXTERNAL_TOOLS_ENABLED=true and outbound network controls are confirmed."
            elif tool.id == "zap":
                if not settings.zap_api_url or not settings.zap_api_key:
                    state = "not_configured"
                    detail = "Configure WEBGUARD_ZAP_API_URL and WEBGUARD_ZAP_API_KEY for a dedicated ZAP instance."
                else:
                    state = "available"
                    detail = "ZAP API configured; only the adapter's scoped baseline workflow is used."
            elif tool.id in {"playwright", "accessibility"}:
                if not settings.playwright_enabled:
                    state = "not_configured"
                    detail = "Set WEBGUARD_PLAYWRIGHT_ENABLED=true and install the optional browser dependency and Chromium."
                elif importlib.util.find_spec("playwright") is None:
                    state = "unavailable"
                    detail = "Playwright Python package is not installed in the worker environment."
                else:
                    state = "available"
                    detail = "Playwright Python package is installed; verify Chromium is installed in the worker image."
            else:
                if not tool.requires_target and not settings.workspace_scan_root:
                    state = "not_configured"
                    detail = "Set WEBGUARD_WORKSPACE_SCAN_ROOT to an explicitly selected source project directory; client paths are never accepted."
                    output.append({
                        "id": tool.id, "name": tool.name, "category": tool.category,
                        "description": tool.description, "kind": tool.kind, "state": state, "detail": detail,
                        "profiles": list(tool.profiles), "requires_target": tool.requires_target,
                        "active_testing": tool.active_testing,
                    })
                    continue
                setting = getattr(settings, tool.executable_setting or "", None)
                binary = shutil.which(setting) if setting else None
                if not setting:
                    state = "not_configured"
                    detail = f"Configure {tool.executable_setting} for this engine."
                elif not binary:
                    state = "unavailable"
                    detail = f"Executable '{setting}' was not found on the worker PATH."
                else:
                    state = "available"
                    detail = "Executable found on the worker PATH; job arguments are generated by WebGuard, not by clients."
        else:
            detail = "Runs through WebGuard's scope-aware request and resolver layer; requires an authorized target at launch."
        output.append({
            "id": tool.id,
            "name": tool.name,
            "category": tool.category,
            "description": tool.description,
            "kind": tool.kind,
            "state": state,
            "detail": detail,
            "profiles": list(tool.profiles),
            "requires_target": tool.requires_target,
            "active_testing": tool.active_testing,
        })
    return output


def get_tool(tool_id: str) -> ToolDefinition | None:
    return next((tool for tool in TOOLS if tool.id == tool_id), None)
