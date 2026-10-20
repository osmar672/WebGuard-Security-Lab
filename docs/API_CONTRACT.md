# API contract — current control-plane release

Base path: `/api`. Request/response payloads are JSON. The frontend sends `Authorization: Bearer <access_token>` for protected routes. Access tokens are valid for 15 minutes by default. Production disables `/docs`, `/redoc`, and `/openapi.json`; development enables them.

## Envelopes

Success for ordinary routes: `{"data": <payload>, "meta": null}`. Paginated list success: `{"data": [...], "meta": {"page": 1, "page_size": 20, "total": 3}}`. Authentication endpoints return their documented payload directly rather than a generic envelope. Health also returns a direct health payload.

Error: `{"error": {"code": "validation_error", "message": "...", "details": [...], "request_id": "..."}}`. Every API response includes `x-request-id`. Internal 5xx errors do not expose tracebacks or exception text.

Error codes include `validation_error` (422), `scope_violation` (400), `conflict` (409), `not_found` (404), `method_not_allowed` (405), `unauthorized` (401), `forbidden` (403), `rate_limited` (429), `payload_too_large` (413) and `internal_error` (500).

## Authentication and roles

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | Public, rate-limited | Email/password; returns short-lived bearer token and user object |
| GET | `/api/auth/me` | Authenticated | Returns current active user |
| GET | `/api/health` | Public | API/database health only; does not expose credentials |

Login request:

```json
{"email":"operator@example.com","password":"a long secret password"}
```

Successful login response:

```json
{
  "access_token": "<short-lived JWT>",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {"id":"<uuid>","email":"operator@example.com","role":"operator","is_active":true,"created_at":"2026-01-01T00:00:00Z"}
}
```

Roles: `admin` can see all current tenant-owned records; `operator` can register targets and sees their own records; `viewer` can read their own records but cannot register targets. User creation is CLI-only. There is no public sign-up endpoint. Target creation assigns ownership from the token subject; the client cannot choose `owner_user_id`.

## Current endpoints

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/api/dashboard/summary` | Authenticated | Real target/audit/finding counts and up to 5 recent audits scoped to the caller's targets |
| GET | `/api/targets?page=1&page_size=20` | Authenticated | Targets owned by the caller; admins can see all. Paginated, newest first |
| POST | `/api/targets` | Admin/operator | Validates URL and DNS during registration, records audit event, owner derived from principal |
| GET | `/api/audits?target_id=&state=` | Authenticated | Caller-owned records (admins can see all) |
| GET | `/api/findings?audit_id=&severity=&status=` | Authenticated | Findings associated with caller-owned targets |
| GET | `/api/engines/status` | Authenticated | Reports readiness from the tool registry and worker configuration |
| GET | `/api/tools/catalog` | Authenticated | Returns engine capabilities, dependency state and latest worker heartbeat readiness |
| POST | `/api/targets/{id}/authorize` | Admin/operator | Explicitly authorize registered scope with a reference/reason |
| POST | `/api/targets/{id}/revoke` | Admin/operator | Revoke scope and cancel queued/running jobs |
| POST/GET | `/api/tools/runs` | Admin/operator / authenticated | Queue bounded tests against authorized registered targets and list accessible runs |
| GET | `/api/tools/runs/{id}` | Authenticated | Retrieve a scoped run and normalized results |
| POST | `/api/tools/runs/{id}/cancel` | Admin/operator | Request cancellation of a pending/running target job |
| POST/GET | `/api/tools/workspace-runs` | Admin / authenticated | Queue and list code-security/SBOM scans against server-configured source workspace only |
| POST | `/api/tools/workspace-runs/{id}/cancel` | Admin/operator | Request cancellation of an owned workspace scan |
| GET | `/api/audits/{id}/regression?baseline_audit_id=...` | Authenticated | Compare findings between two completed runs of the same target |
| GET | `/api/reports/export?audit_id=...&format=json\|html\|pdf\|sarif` | Authenticated | Export persisted audit findings |
| GET | `/api/reports/export?workspace_scan_id=...&format=json\|html\|pdf\|sarif\|cyclonedx` | Authenticated | Export persisted workspace findings or a CycloneDX SBOM from an SBOM run |
| GET | `/api/history` | Authenticated | Paginated, scoped audit/job history |
| GET | `/api/ai/status` | Authenticated | Reports AI mode/capabilities; never exposes provider secrets |
| POST | `/api/ai/assist` | Authenticated | Bounded advisory analysis from caller-owned records; no job execution |

All filters are optional. Page starts at 1; page size defaults to 20 and is capped at 100 by default (`WEBGUARD_MAX_PAGE_SIZE`). Timestamps are UTC ISO-8601. IDs are UUID4 strings.

## Target registration

```json
{
  "name": "My staging system",
  "base_url": "https://staging.example.com/",
  "authorization_confirmed": true,
  "authorization_note": "Owned by my team; authorization ticket SEC-123",
  "scope_rules": {"paths": ["/"]}
}
```

Response is `201` with a target representation. `authorization_status` remains `unverified` until a future reviewed authorization workflow changes it; a checkbox/text statement is not treated as independent proof. Normal mode denies loopback, private, link-local, reserved, multicast and cloud metadata targets. Registration-time DNS validation is **not sufficient** for future scan execution: every future HTTP request/redirect must go through the scope-bound transport, with network-level egress controls.

## AI Copilot

`POST /api/ai/assist` accepts `{ "task": "process_review|audit_summary|finding_triage|remediation_plan|general", "question": "...", "audit_id": "optional UUID" }`. `question` is capped at 3,000 characters. Results include `mode` (`remote_model` or `local_rules`), provider/model metadata, timestamp and advisory disclaimer. The request is rate-limited per authenticated user per API process. See `docs/AI_COPILOT.md` for provider setup, privacy and security boundaries.

The optional remote model is configured only through backend environment values; never use a frontend `VITE_*` variable for the provider key. No scan execution or other side effects are exposed to the model.

## Tool engine scope and status

A database-backed worker is implemented for the registered engine adapters. Built-in HTTP header, DNS, TLS certificate and authentication-surface checks use the WebGuard scope-aware HTTP/resolver layer. Optional adapters include ZAP spider/passive scan, Nuclei, Schemathesis, k6, Playwright, basic accessibility heuristics, Trivy, Semgrep, Gitleaks, testssl.sh and CycloneDX SBOM generation. Adapters are only executable when the server configuration, worker dependencies, target authorization and deployment network controls are satisfied; unavailable engines must stay unavailable in the catalog.

The security review remains a release gate: external CLI/browser tools can resolve destinations independently and retain DNS rebinding risk unless the actual worker egress firewall is enforced and tested. Rate limiting is process-local, the queue uses the database rather than a dedicated broker, reports are generated from stored rows on request, and accessibility checks are heuristics rather than a WCAG certification. This code is an internal beta until those deployment and validation gates are satisfied.
