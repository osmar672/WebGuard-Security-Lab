# Contract alignment — integrated project

This repository combines the Phase 1 frontend, backend/control plane, and reusable scope/SSRF boundary. `docs/API_CONTRACT.md` is the source of truth for the currently implemented API paths and envelopes; `docs/SECURITY_REVIEW.md` lists release blockers.

| Contract / module | Current implementation | Status |
|---|---|---|
| API/database health | `GET /api/health` | Implemented; public and minimal |
| Authentication | `POST /api/auth/login`, `GET /api/auth/me` | Implemented; short-lived JWT, Argon2, per-process login throttle |
| Role and data ownership | Auth dependencies and `Target.owner_user_id` | Implemented for current read/create routes; admin/operator/viewer |
| Dashboard summary | `GET /api/dashboard/summary` | Implemented; authenticated and tenant-scoped |
| Target registration/list | `GET/POST /api/targets` | Implemented; registration-only scope check; full lifecycle/approval UI pending |
| Audit list | `GET /api/audits` | Implemented; caller-owned scope, read-only; no job-creation route |
| Findings list | `GET /api/findings` | Implemented; caller-owned scope, read-only |
| Engine readiness | `GET /api/engines/status` | Implemented; does not run engines |
| Docker production delivery | Compose, Caddy TLS, preflight, migration runbook, encrypted backup script | Implemented scaffolding; environment/DNS/firewall/restore must be verified by deployer |
| Scanner workers, browser bots, load generation, reports | No execution endpoints/workers in current release | Not implemented; UI must remain disabled/coming soon |
| Recent event feed | No event-feed route | Not implemented; don't infer feed data from `AuditEvent` |
| SSRF boundary | `security/webguard_scope/` plus registration-time checks | Library implemented and tested; not yet wired into an execution worker |

Before any worker is introduced, load the persisted approved scope and apply the Phase 3 boundary on every request/navigation, including redirect hops and DNS resolution, with network-level egress restrictions. The target-registration check is defense in depth, not an execution grant.
