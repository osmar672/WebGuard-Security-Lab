# WebGuard Security Lab 0.9.0 — Tool Center validation results

Date: 2026-10-19 (America/Costa_Rica). Commands below were run against the source tree used for this ZIP. This report deliberately separates successful checks from unavailable build infrastructure.

## Python test suites

Backend/API, auth/RBAC, tool queue, worker heartbeat, tool parsers, catalog and report code:

```bash
cd backend && python -m pytest -q
```

**PASS — 53 passed in 7.67s.** The suite includes fail-closed behavior when the production worker heartbeat is absent/stale, cancellation/authorization boundaries, bounded tool command construction, CycloneDX command selection, configured Playwright browser-path preservation and adapter/report parsing.

SSRF/scope security boundary:

```bash
cd security && PYTHONPATH=. python -m pytest -q tests
```

**PASS — 42 passed in 0.45s.** Tests use mocked DNS, unit fixtures and local isolated targets; they do not probe public systems.

Total Python test count: **95 passed** across the two suites.

## Static and configuration checks

Executed successfully:

```bash
python -m compileall -q backend/app backend/tests security/webguard_scope security/tests
python -m json.tool MODULE_MANIFEST.json >/dev/null
python -m json.tool integration/PHASE3_SECURITY_BOUNDARY_MANIFEST.json >/dev/null
bash -n setup.sh start.sh scripts/*.sh
```

The following YAML files also parsed successfully using `yaml.safe_load`: `compose.yaml`, `compose.workspace.override.example.yaml`, `.github/workflows/ci.yml`, `.github/dependabot.yml`.

Frontend TypeScript/TSX syntax transpile using the globally installed TypeScript compiler: **30 files, zero syntax diagnostics**. This is a syntax-only check, not a strict project type-check.

The production preflight was previously exercised using a synthetic production config and a stubbed `docker` command; that validates config parsing only, not an actual Compose build or deployment.

## Checks blocked / not run

- `npm ci --offline` failed with `ENOTCACHED`: the npm cache does not contain `yocto-queue@0.1.0`. The earlier online installation was also blocked by DNS (`EAI_AGAIN registry.npmjs.org`). Therefore ESLint, strict TypeScript project check, Vitest and the Vite production build were **not** run successfully for this build.
- Ruff lint was not run because `ruff` is not installed in the environment (`No module named ruff`).
- Docker Compose image builds and real service startup were not run because the Docker CLI is not installed in this environment.
- No live Groq provider request was made; a usable provider key was not supplied.
- No external target scans were performed. The safety flags are disabled by default.

## Engine installation status

- The optional worker image pins Playwright, Schemathesis and Semgrep Python packages and installs Chromium. It is a separate image from the API.
- The engine adapters, availability detection, job queue, worker heartbeat, output parsers, normalized findings, cancellation checks, regression comparison and report exporters (JSON/HTML/PDF/SARIF/CycloneDX) are present in source and covered by backend tests where applicable.
- Native CLI binaries for Nuclei, k6, Trivy, Gitleaks and testssl.sh are **not** baked into `backend/ToolWorker.Dockerfile` in this release. Those adapters must remain unavailable until these binaries are installed from official, pinned releases and their checksums are verified. ZAP must be separately deployed and configured with a non-public API key.
- Docker Compose's `tool_egress` network is not a firewall. Do not enable external engines until network egress policy blocks loopback, private, link-local, reserved, multicast and cloud metadata destinations and that restriction has been tested against the worker and browser traffic.

## Release assessment

Version 0.9.0 integrates the Tool Center UI and backend workflow for bounded runs, worker readiness, authorization checks, persistence, normalized results, cancellation, exports and comparisons. It is an **internal beta**, not certified public production software. A release candidate still needs: live npm install + front-end gates, Docker build and staged Compose smoke test, actual native engine installation/verification, egress enforcement tests, backup/restore drill, monitoring/rate-limiting review, and external security testing.
