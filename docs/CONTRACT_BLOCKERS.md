# Current implementation limits and integration decisions

This file records the limits that remain after authentication and production hardening. It supersedes earlier baseline notes that said authentication was missing.

## Implemented and wired

- React/Vite frontend and authenticated routing use documented API paths.
- Target/audit/finding data is decoded from the API; the UI uses true empty states.
- FastAPI, SQLAlchemy, Alembic migrations, SQLite development and PostgreSQL production configuration.
- Argon2 password hashes, short-lived JWTs, admin/operator/viewer roles, protected data routes, target ownership scoping and CLI-only user provisioning.
- Production Caddy/Compose scaffolding, config preflight, explicit migrations, and encrypted age backup path.
- Reusable SSRF/scope package with tests; registration-time checks remain separate from future execution-time enforcement.

## Remaining limits / blockers

- Scanner engine workers, durable job queue, Playwright browser bots, k6 load generation, reports, job cancellation and event stream are not implemented.
- No validated authorization-evidence workflow, approval expiry, target revocation workflow or persisted grant registry is wired to execution.
- The process-local login throttle is not a distributed rate limiter; use a shared edge/WAF/Redis throttle before public exposure.
- No admin user management UI, password reset, MFA/SSO, or token revocation list exists.
- Python transitive dependency hash lock and container image digest pins remain release-engineering tasks.
- Actual Docker image build/start, public DNS/TLS, host firewall, off-host retention, restore drill and external penetration test must be run by the deployment owner; local source tests cannot prove these.
- Full SSRF protection is not yet active on scanner traffic because scanner workers are absent. Network-time validation and container/network egress enforcement are mandatory before enabling them.

## Safe defaults

- `WEBGUARD_ALLOW_LAB_TARGETS=false` in production.
- Local development servers bind to `127.0.0.1`.
- Frontend `VITE_*` configuration contains no secrets.
- No scan, browser navigation, load test, or report job starts from the frontend.
- Targets created through the current API remain `unverified`; an attestation is not treated as proof of authorization.
