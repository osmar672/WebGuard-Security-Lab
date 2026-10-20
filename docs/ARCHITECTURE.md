# WebGuard Security Lab — Architecture

WebGuard is a modular control plane for **authorized** web security assessments, controlled browser automation and bounded performance testing. The current releasable software is the dashboard/API/target inventory/security boundary foundation; the active scan workers and report pipeline remain future modules.

## Repository layout and ownership

| Path | Owner / module | Responsibility |
|---|---|---|
| `docs/`, `integration/` | Shared contracts | Architecture, API, data, security and operational agreements |
| `frontend/` | Phase 1 | React + TypeScript + Vite dashboard, login, authenticated routing and centralized API client |
| `backend/app/`, `backend/alembic/`, `backend/tests/` | Backend/control plane | FastAPI, Pydantic schemas, SQLAlchemy persistence, auth/roles, access scoping and migrations |
| `security/webguard_scope/`, `security/tests/` | Phase 3 security boundary | Explicit grants, URL scope checks, safe DNS resolver, bounded HTTP client, redirect validation and audit hooks |
| `deploy/`, `compose.yaml`, `scripts/` | Delivery/SRE | HTTPS edge, image builds, preflight, migrations, local development, tests and encrypted backup |
| `backend/app/engines/` | Future engine modules | Scanner, browser automation and load-test workers; not implemented in this baseline |
| `backend/app/reports/` | Future reports module | Report generation/storage; not implemented in this baseline |

## Shared conventions

- Python 3.11+, type annotations, pytest, Ruff and isolated temporary SQLite databases.
- TypeScript strict mode, ESLint, Vitest; Vite content-hashed production assets.
- `WEBGUARD_*` backend environment variables; frontend `VITE_*` variables are public and must never contain secrets.
- IDs are UUID4 strings; timestamps are UTC ISO-8601.
- Never commit `.env`, secret material, local databases, `.venv`, `node_modules`, backups, or build caches.
- Local servers bind to `127.0.0.1`; the production API is private behind Caddy and HTTPS.

## Identity and ownership

Access tokens are short-lived JWTs. Every non-health data endpoint requires an active database user. Roles are `admin`, `operator`, and `viewer`; targets are assigned to the authenticated principal, and downstream audit/finding reads are filtered through those targets. The admin CLI provisions users; no open registration route exists. Login throttling is currently per-process and must be supplemented by a shared edge limit for public deployment.

## Job states and module interfaces

The shared job-state vocabulary is `pending`, `queued`, `running`, `completed`, `failed`, and `cancelled`. No scanner, browser or load-test worker is started in this release; the engine endpoint reports `not_configured` / `not_implemented` truthfully. Unsupported execute/report/event routes remain absent rather than returning fabricated results.

Any future execution worker must load current authorization scope from trusted persistence and enforce it on each request/navigation. Target-registration validation alone is insufficient. The `webguard_scope` package should protect HTTP requests, DNS resolution and redirects; browser engines additionally need network isolation and egress enforcement for subresources, WebSockets, downloads and worker processes.

## Environments

- Development: SQLite and Vite proxy; `./setup.sh` then `./start.sh`.
- Production: PostgreSQL and Caddy TLS reverse proxy using `compose.yaml`; reviewed config in `.env.production`; explicit Alembic migrations before API rollout; see `PRODUCTION_DEPLOYMENT.md`.
