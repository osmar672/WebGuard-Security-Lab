# WebGuard Security Lab

**Release:** 0.9.0 — Tool Center integration beta

WebGuard is an authorized web-security assessment control plane combining a React/TypeScript dashboard, FastAPI API, SQLAlchemy/Alembic persistence, a scope-aware SSRF boundary, optional Groq AI Copilot, a database-backed worker, tool adapters and normalized findings/reports.

> **Release status: internal beta, not yet cleared for public production.** Tool integration code and queueing are implemented, but external engines remain disabled by default. A real deployment still needs tested network egress filtering for workers, dependency installation, actual Docker start/restore drills, shared rate limiting, operational monitoring, and security review. The catalog reports a dependency as available only when its local server-side configuration permits it.

## Tool Center 0.9.0

The Tool Center includes a shared engine catalog, database-backed job/run records, bounded profiles, authorization and revocation checks, worker readiness heartbeat, cancellation, normalized findings, regression comparison, reports (JSON/HTML/PDF/SARIF), and CycloneDX SBOM export for configured workspace scans. Engine adapters do not mean every binary ships installed: the dashboard reflects actual worker capabilities and dependencies.

Supported adapter families: built-in HTTP security headers, DNS exposure, TLS certificate and authentication-surface checks; OWASP ZAP passive baseline; Nuclei; Schemathesis; k6; Playwright and accessibility heuristics; Trivy; Semgrep; Gitleaks; testssl.sh; and CycloneDX SBOM. See `docs/TOOL_CENTER.md` for dependency/setup status and safety gates.

## Modules

```text
frontend/                 React, TypeScript, Vite dashboard, Tool Center, Reports/Regression
backend/app/              FastAPI, auth/RBAC, persistence, tool catalog/adapters/worker and AI Copilot
backend/alembic/          Versioned database migrations
backend/tooling/           (in app/tooling) adapters, output normalization and PDF reporting
security/webguard_scope/  Scope-aware URL, resolver and HTTP client boundary
docs/                     API/data/architecture/security/deployment/tool setup docs
deploy/                   Caddy HTTPS edge and frontend image
compose.yaml               PostgreSQL, API, worker profile and HTTPS edge
scripts/                  Setup, start, tool checks, optional install, tests and backup preflight
```

## Local development on Arch Linux / CachyOS

### Requirements

```bash
sudo pacman -S --needed python python-pip nodejs npm
```

Use Python 3.11+ and Node.js 22+. Initial setup requires access to PyPI and npm.

### Install and start

From the extracted project root:

```bash
chmod +x setup.sh start.sh scripts/*.sh
./setup.sh
./start.sh
```

Open `http://127.0.0.1:5173`. API health is at `http://127.0.0.1:8000/api/health` and development API docs are at `http://127.0.0.1:8000/docs`. The setup creates a virtual environment, installs core dependencies, migrates the development database and asks to create an initial admin. In non-interactive use, create an admin with:

```bash
cd backend
../.venv/bin/python -m app.cli create-user --role admin
cd ..
```

### Enable safe built-in tests locally

The queue is off by default. Review `docs/TOOL_CENTER.md` and target scope, then set the following in `backend/.env`:

```dotenv
WEBGUARD_TOOL_EXECUTION_ENABLED=true
WEBGUARD_EXTERNAL_TOOLS_ENABLED=false
WEBGUARD_EGRESS_POLICY_CONFIRMED=false
```

Restart with `./start.sh`. The local worker starts when the tool execution flag is `true`. Register a target and explicitly authorize it before queuing a built-in test. Loopback/private targets remain denied unless the isolated lab is configured explicitly.

### Optional engines

```bash
./scripts/install-python-engines.sh
./scripts/check-tool-engines.sh
```

The local optional installer pins Playwright, Schemathesis and Semgrep and downloads the matching Chromium runtime. The production `ToolWorker.Dockerfile` includes those Python integrations and Chromium in a worker-only image, separate from the API. Nuclei, k6, Trivy, Gitleaks and testssl.sh are wired through fixed-argument adapters but their native binaries are not baked into this image; install them from the official vendor releases and verify checksums as documented in `docs/TOOL_CENTER.md`. ZAP is connected as a separate, API-key-protected instance. Do not enable external engines until the worker has an enforced, tested egress policy. The boolean `WEBGUARD_EGRESS_POLICY_CONFIRMED=true` is only operator attestation; it does not create a firewall.

### Reports and SBOM

The Reports page exports persisted audit/workspace results as JSON, escaped HTML, PDF and SARIF. Trivy can generate a CycloneDX SBOM from the administrator-configured source tree; SBOM downloads use `format=cyclonedx`. For production source scans, copy `compose.workspace.override.example.yaml` to a private override file and set `WEBGUARD_WORKSPACE_HOST_PATH` to the exact host project directory. Regression comparison matches results from two completed runs of the same target. A finding absent from a later run is “no longer observed”, not automatic proof of remediation.

### Production composition

Use `docs/PRODUCTION_DEPLOYMENT.md`, `docs/SECURITY_REVIEW.md` and `scripts/production-preflight.sh`. `compose.yaml` uses PostgreSQL, Caddy HTTPS and an optional worker profile (`docker compose --env-file .env.production -f compose.yaml --profile tools up -d --build`). The optional worker profile builds `backend/ToolWorker.Dockerfile`, which adds pinned Python security-testing dependencies and Chromium without bloating the API image. External native CLIs remain unavailable until installed in the worker image. The `tool_egress` network in Compose is not an egress firewall; configure actual network policy before enabling external engines.

## Verification

```bash
cd backend && python -m pytest -q
cd ../security && python -m pytest -q
cd ..
python -m compileall -q backend/app backend/tests security/webguard_scope security/tests
python -m json.tool MODULE_MANIFEST.json
bash -n setup.sh start.sh scripts/*.sh
```

Frontend gates (`npm ci`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`) need registry connectivity and should run before release. `TEST_RESULTS.md` records which checks actually ran in the build environment.

## Security and boundaries

- Test only targets you own or have explicit permission to assess.
- The server rechecks authorization and target scope before queueing and while a job runs.
- External tools are disabled by default; CLI/browser tools can have DNS check/use gaps, so worker egress filtering is required.
- The Groq AI Copilot is advisory only and cannot start a scan or mutate scope.
- Tool execution runs allow-listed commands without a shell, with bounded execution time and output size.
- Queue locking and rate limits are suitable only for a single-worker internal beta until distributed coordination is added.
- See `docs/SECURITY_REVIEW.md` for residual risks.
