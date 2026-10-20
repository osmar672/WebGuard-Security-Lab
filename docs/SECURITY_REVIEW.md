# WebGuard security review and release gate

Review scope: source archive provided for this delivery, updated frontend/backend/authentication configuration, SSRF library, Docker Compose and operational scripts. This is an engineering review, not a formal penetration test or certification.

## Implemented in this release

- Password hashing with Argon2id defaults supplied by `argon2-cffi`.
- Short-lived (15-minute) JWT access tokens, fixed HS256 algorithm, issuer/audience checks, current-user lookup and disabled-account check.
- Role guards for target creation (`admin`/`operator`) and row-level data filtering to a user's owned targets/audits/findings; admins can inspect all records.
- Generic login error messages and a 10-failed-attempt/15-minute in-memory per-IP limiter. A regression test covers the counter.
- CLI-only user provisioning; password length is at least 14 characters; no public registration endpoint.
- Production settings fail closed unless there is a unique secret, PostgreSQL URL, explicit host list and local-lab mode disabled.
- CORS is same-origin by default; production OpenAPI/docs endpoints are disabled; trusted-host validation and security headers enabled.
- Caddy TLS/reverse proxy, restrictive CSP, request body limit, private service network, API not publicly port-published, API read-only root filesystem, non-root API user, dropped API Linux capabilities, no-new-privileges.
- Safer URL parsing and DNS destination validation for target registration, including loopback/private/link-local/reserved/cloud metadata denial by default.
- Production preflight no longer `source`s `.env.production`; encrypted `age` backup script writes no plaintext dump to disk.
- CI definition for lint, type check, unit tests, build, npm audit and pip-audit.
- Optional AI Copilot with local rules fallback, server-side provider key, minimized task context, best-effort credential redaction, bounded response/time, per-user process-local rate limit, audit event and no tools/scan execution.

## Important limits / release blockers

1. **Not a full scanner product.** Scanner, Playwright browser, k6 and reports have no real task queue/worker execution. Status endpoints correctly mark them as unimplemented or not configured.
2. **SSRF boundary is not wired to a production worker because workers do not exist yet.** A target registration check cannot protect later requests on its own. A future worker must load grants from trusted persistence and use the scope-bound transport for every HTTP redirect/request; browser network activity also needs isolated egress policy.
3. **Authorization evidence is attestation, not independent proof.** Targets remain `unverified`; no automatic authorization approval is inferred from a checkbox.
4. **Rate limiting is process-local.** It is not shared across Uvicorn workers/replicas and is insufficient alone against distributed credential stuffing. Add a shared proxy/WAF or Redis-backed limiter before public exposure.
5. **Identity lifecycle is minimal.** No MFA/SSO, email verification, password reset, role management UI, API token revocation list, refresh tokens, or interactive logout revocation. Tokens expire after 15 minutes; client logout only clears browser state. The frontend holds the short-lived bearer token in `sessionStorage`; an XSS flaw could read it, so retain the strict CSP and consider a reviewed HttpOnly-cookie/BFF design if your threat model requires it.
6. **Supply-chain pinning not complete.** Python requirement ranges and container base tags are not fully locked by version/digest; review vulnerability reports and pin digests before a regulated or high-assurance release. CI audit jobs must be run by the repository's CI runner.
7. **Operations need owner/infra validation.** This package cannot verify DNS, firewall, public TLS issuance, server hardening, secrets manager, off-site backup retention, disaster recovery, monitoring or alert delivery.
8. **No third-party pentest was performed.** Validate the threat model, tenancy/isolation, authorization flows, SSRF and container boundaries independently before processing sensitive targets/data.
9. **Python dependency lock.** The backend uses bounded version ranges, not a generated hash-locked full transitive lockfile. Use a reviewed lock/constraints workflow to make production rebuilds reproducible.
10. **Request size enforcement:** application middleware checks declared `Content-Length`; production Caddy adds a request-body size boundary. Do not deploy the API directly to the internet without that edge boundary or equivalent ASGI-level streaming enforcement.
11. **AI Copilot is advisory, not autonomous.** The remote provider is optional, and common secret formats are redacted on a best-effort basis only. Review all provider data handling, constrain egress, apply shared rate/cost controls across workers, monitor spend and never automate a scan or authorization change from model output. Prompt injection or hallucinations remain possible; require human validation.

## Go/no-go guidance

- **Reasonable target:** controlled internal beta of the dashboard/control plane after reviewing `.env.production`, DNS/TLS and backup setup.
- **Not approved by this review:** unrestricted public multi-tenant launch, sensitive regulated data, or running active scan/load jobs against targets.
- **Before public launch:** fix the blockers above that apply to your threat model; conduct a clean build from lockfiles; test all role/tenant boundaries; run dependency/image scans; verify encrypted restore; obtain external security review and sign off with an owner.


## Tool Center implementation update (2026-10-19)

The current code now includes a database-backed worker and bounded adapters for built-in header/DNS/TLS/auth-surface checks, ZAP passive baseline, Nuclei, Schemathesis, k6, Playwright/navigation/accessibility, Trivy, Semgrep, Gitleaks, testssl.sh, CycloneDX SBOM output and report/regression exports. These capabilities do not mean all binaries are bundled or active: most external commands are intentionally reported as unavailable until installed, and execution is disabled unless server flags are set.

Release gates still open: enforce and test the real worker egress firewall (Compose `tool_egress` alone is not sufficient); install and pin each external engine in a dedicated worker image; run strict frontend typecheck/tests/Vite build in a connected environment; test queue/migration/restore/monitoring on actual deployment infrastructure; add shared rate limits and worker leases before horizontal scaling; and commission a security review/penetration test. Do not describe the product as production-certified before these are closed.
