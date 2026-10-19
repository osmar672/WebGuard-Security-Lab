# Phase 1 — Contract blockers and decisions

## Source inspected

- `00_ARCHITECTURE_CONTRACTS.md`, supplied as the Phase 0 requirements brief.
- `01_FRONTEND_DASHBOARD.md`, supplied Phase 1 implementation brief.
- `03_SCOPE_AUTH_SSRF.md` and the provided Phase 3 ZIP, inspected to understand ownership boundaries.

## Blockers before enabling real dashboard data

The supplied Phase 0 brief lists the contract components that must exist but does not define the approved REST endpoint paths or actual response/error envelopes and schemas. Therefore the frontend cannot safely infer:

- Health and database health paths/DTOs.
- Target and audit count paths/DTOs.
- Recent-job, engine-status, and activity paths/DTOs.
- List/filter/pagination response shapes for target, finding, report, and audit-history pages.
- Any authorized mutation/action paths.

## Decisions made

- Added central HTTP client and environment-based base URL.
- Kept endpoint paths empty by default and moved their names to `.env.example`.
- Marked local dashboard display interfaces/decoders as placeholders.
- Displayed `Not configured`, `No records loaded`, or `Coming soon` rather than fictional metrics or successful runs.
- No database access from the browser, no credentials in Vite variables, and no operational scan/browser/load-test actions.
- API client omits cookies, uses an 8-second timeout, rejects redirects, checks the endpoint origin, and validates JSON through decoders.

## Integration required

The backend owner must provide the authoritative API contract and align `src/api/dashboardService.ts` decoders to it. Once paths/schemas exist, configure `.env.local`, run the checks in `TEST_RESULTS.md`, then test against an authorized local development backend before enabling production deployment.
