# WebGuard Tool Center — engine setup and operating guide

## Capabilities in this release

The Tool Center UI provides an engine catalog, bounded test profiles, run state/cancellation, normalized findings, regression comparison and report/SBOM export. Tool adapters use one database-persisted job queue and normalize their results into `Finding` records. It is not a claim that every listed binary ships preinstalled: missing dependencies must remain unavailable in the catalog. The catalog reports whether each adapter is available, disabled, not configured, or missing a dependency.

| Engine | Purpose | Adapter behavior | Dependency |
|---|---|---|---|
| HTTP Security Headers | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and clickjacking headers | Built-in, bounded GET through the scope-aware transport | none |
| DNS Exposure Audit | Resolve a target and validate each returned address | Built-in resolver rejects blocked address classes | none |
| TLS Certificate Audit | Validated TLS handshake, expiry and negotiated cipher | Built-in; only connects to resolver-approved numeric addresses | none |
| Authentication Surface Review | Observe cookie attributes and auth challenge headers | Built-in, no password guessing or credentials submitted | none |
| OWASP ZAP Baseline | Spider and passive alerts only | Configured dedicated ZAP API; active scanner API is never called | ZAP API URL and API key |
| Nuclei Safe Templates | Limited misconfiguration/exposure templates | Fixed flags, bounded rate/concurrency, no redirects, no client templates | `nuclei` |
| Schemathesis | Bounded OpenAPI property-based API tests | Uses `{target}/openapi.json`, limited cases, one worker | `schemathesis` CLI |
| k6 | Load profiles with latency/error thresholds | Fixed script, bounded VUs/time and redirects disabled | `k6` |
| Playwright | Browser navigation errors and DOM state | Headless Chromium, intercepts and blocks off-origin browser requests | Python Playwright and Chromium |
| Accessibility | Basic DOM checks for image alt, form labels, button names, `lang` and heading jumps | Automated heuristics; not a WCAG conformance certification | Python Playwright and Chromium |
| Trivy | Filesystem dependency/misconfiguration/secret scan | Server-configured workspace only; matched secret values are not stored | `trivy` |
| CycloneDX SBOM Export | Software component inventory / supply-chain handoff | Trivy emits a bounded CycloneDX JSON document; stored output capped at 5 MiB and 10,000 components | `trivy` |
| Semgrep | Static application-security rules | Fixed `p/security-audit` rules and server-configured workspace only | `semgrep` |
| Gitleaks | Secret detection | Server-configured workspace; redacted mode | `gitleaks` |
| testssl.sh | TLS protocol/cryptographic checks | HTTPS targets only; external engine safety gate applies | `testssl.sh` |
| Reports & regression | JSON, escaped HTML, SARIF export and audit comparison | Uses persisted actual results; never generates synthetic findings | Built in |

## Optional Python engines on Arch/CachyOS

```bash
./scripts/install-python-engines.sh
./scripts/check-tool-engines.sh
```

The installer uses pinned versions in `backend/requirements-tools.txt` (Playwright 1.64.0, Schemathesis 4.32.0, Semgrep 1.181.0 as checked on 2026-10-19) and installs Chromium using the matching Playwright package. Browser binaries must be updated whenever the Python Playwright version changes. Official instructions: <https://playwright.dev/python/docs/browsers> and <https://playwright.dev/python/docs/intro>.

Install binary tools only from official sources and pin versions in your deployment/OS packaging:

- Nuclei: <https://github.com/projectdiscovery/nuclei/releases>
- k6: <https://grafana.com/docs/k6/latest/set-up/install-k6/>
- Trivy: <https://github.com/aquasecurity/trivy/releases>
- Gitleaks: <https://github.com/gitleaks/gitleaks/releases>
- testssl.sh: <https://github.com/testssl/testssl.sh/releases>
- Semgrep: <https://semgrep.dev/docs/getting-started/>
- Schemathesis: <https://schemathesis.github.io/schemathesis/guides/>
- ZAP: <https://www.zaproxy.org/docs/desktop/start/features/> and <https://www.zaproxy.org/docs/automate/automation-framework/>

`./scripts/check-tool-engines.sh` reports binaries visible in the current shell. It does not prove that databases/rules are current, that Chromium can launch, or that a network route is safe. WebGuard's catalog performs its own worker-side checks too. It reports the latest heartbeat; the production API fails closed for run requests when the worker heartbeat is absent or older than 45 seconds.

## Enabling the local worker

The standard install leaves all job execution disabled. After reviewing your target authorization and network policy, set these backend variables in `backend/.env`:

```dotenv
WEBGUARD_TOOL_EXECUTION_ENABLED=true
WEBGUARD_EXTERNAL_TOOLS_ENABLED=false
WEBGUARD_EGRESS_POLICY_CONFIRMED=false
```

Restart with `./start.sh`. The development script starts the worker only when `WEBGUARD_TOOL_EXECUTION_ENABLED=true` is set as an exact line. Built-in header, DNS, TLS and authentication-surface checks can then run against explicitly authorized targets. External engines remain disabled.

## Production worker and network policy

The production worker is optional and only starts with Compose profile `tools`. Before enabling it, an operator must configure host/network egress filtering so engine processes cannot reach loopback, private, link-local, reserved, multicast or cloud metadata destinations; a settings flag is an operator attestation, not a firewall. DNS answers and redirects must be revalidated. The browser and external CLI adapters can still have DNS check/use gaps because some tools resolve targets themselves. Do not enable external engines until this limitation is covered by deployment-level controls and the isolation is tested.

To use external engines, both flags are required:

```dotenv
WEBGUARD_TOOL_EXECUTION_ENABLED=true
WEBGUARD_EXTERNAL_TOOLS_ENABLED=true
WEBGUARD_EGRESS_POLICY_CONFIRMED=true
```

These flags do not install external programs. Missing tools stay `unavailable` in the catalog. In production, a live worker heartbeat is required before the API advertises runnable tools or accepts a new job; it expires after 45 seconds. The worker-only image installs pinned Python integrations (Playwright, Schemathesis, Semgrep) and Chromium. Native CLIs (Nuclei, k6, Trivy, Gitleaks, testssl.sh) must be added to the worker image from official, pinned releases; do not put those binaries in the API image. ZAP should be a dedicated, isolated instance with an API key not shared with any public network. WebGuard's ZAP adapter only calls spider and passive-scan APIs; it never calls the active scanner API.

## Job state, persistence and limits

Jobs are stored in SQLite for development and PostgreSQL in production. A separate worker claims queued `ScanJob` and `WorkspaceScan` rows, rechecks target authorization, runs a fixed allow-listed command without a shell, persists sanitized normalized findings, and records lifecycle events. Per-job runtime, profile-specific requests/rate/virtual users, output byte caps, per-user queue rate limits and active-job caps are enforced by WebGuard.

Cancellation is cooperative between polls and terminates a child process group. A process/container kill can interrupt this handling; clean up stale `running` jobs operationally if the worker is forcibly terminated. Multi-worker rate limits are currently process-local, not a shared distributed limiter.

## Report and regression semantics

Report API formats: `json`, `html`, `pdf`, `sarif`; completed SBOM workspace scans additionally support raw `cyclonedx` JSON export. SARIF output is version 2.1.0. Regression comparison requires two audits of the same target and matches title, severity and URL path. A finding missing from the newer audit is called “resolved / no longer observed”; that alone does not prove remediation succeeded. Verify with a repeat test and manual validation before closing an issue.

## Explicit limitations

- Accessibility checks are practical DOM heuristics, not a complete automated WCAG audit.
- Schemathesis only tests the default `{base_url}/openapi.json` path in this release; custom schema paths and authentication profiles are not yet configurable.
- ZAP is passive-only in this adapter.
- Code engines and SBOM generation scan one administrator-configured `WEBGUARD_WORKSPACE_SCAN_ROOT`; API callers cannot choose a host filesystem path. SBOM JSON is stored in the DB up to a 5 MiB output cap.
- There is no distributed queue broker or shared rate limiter yet. The worker heartbeat is for liveness, not a distributed lease/leader-election mechanism. Run a single worker unless you have verified DB locking and cancellation behavior with your PostgreSQL deployment.
- Reports are generated on request from persisted run records, not stored as separate versioned immutable report artifacts. The minimal PDF renderer prioritizes printable summaries and does not embed the full SBOM; download the CycloneDX format for the complete component inventory.

## Additional Tool Center features

- **Run profiles** provide bounded request counts, runtime and concurrency; they are ceilings, not performance promises.
- **Normalized findings** are stored with the run/audit, and lifecycle actions are recorded as audit events.
- **Regression comparisons** compare two completed runs for the same authorized target using stable finding keys. “No longer observed” is deliberately not equal to “proven fixed”.
- **Report exports**: JSON, escaped HTML, PDF summary, SARIF 2.1.0; completed SBOM runs may export CycloneDX JSON.
- **Workspace scans** operate only on an administrator-configured path; in Compose a read-only mount is supplied through `compose.workspace.override.example.yaml`. Never mount the host root, home directory, credentials or Docker socket.
- **AI Copilot** remains advisory-only; its output is untrusted and does not execute tests or grant authorization.

Suggested operational add-ons: keep a signed allowlist of exact scanner image digests, define retention/deletion for evidence, run a restore exercise, and wire job queue length, failed jobs, worker heartbeat age and engine availability into monitoring/alerting.
