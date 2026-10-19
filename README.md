# WebGuard Security Lab — Phase 1 Frontend

Frontend module built with React, TypeScript, Vite, React Router, and Lucide icons. It provides a responsive security-lab dashboard with dark/light themes, navigation, honest backend empty/configuration states, centralized HTTP handling, and disabled placeholders for modules that do not yet have a verified backend contract.

## Important contract blocker

The provided Phase 0 file (`00_ARCHITECTURE_CONTRACTS.md`) is a requirements brief. It says an API contract must define endpoint paths, response/error envelopes, schemas, pagination, timestamps, and identifiers, but the supplied file does not actually contain those approved paths/schemas or an `API_CONTRACT.md` artifact.

For that reason, this frontend **does not guess API routes, does not seed fake metrics or activity, and does not start scans, browser automation, or load tests**. Endpoint variables in `.env.example` are blank intentionally. The display DTOs and decoders in `src/api/dashboardService.ts` are clearly marked placeholders and must be aligned to the approved backend contract before using real endpoints.

## Requirements

- Node.js 20 or newer (Node 22 recommended)
- npm
- WebGuard backend URL, once available

## Run on CachyOS / Arch Linux

```bash
# 1. Extract the ZIP and enter the project folder
cd webguard-phase1

# 2. Install Node.js/npm if they are not already installed
sudo pacman -S --needed nodejs npm

# 3. Install frontend dependencies
npm install

# 4. Create local environment configuration
cp .env.example .env.local

# 5. Start Vite
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`).

## Backend configuration

1. Ask the backend owner for the approved Phase 0 API contract including exact paths, methods, request/response schemas, error envelope and pagination.
2. Set `VITE_API_BASE_URL` in `.env.local` to the backend origin.
3. Fill the endpoint path variables with **approved relative paths only**. Do not invent paths to make a green status appear.
4. Update and test the decoder/display adapter in `src/api/dashboardService.ts` against the confirmed DTO schemas.
5. Restart Vite after changing environment values.

Vite's `VITE_*` variables are public to the browser. Never store API keys, passwords, bearer tokens, database credentials or other secrets in them. The HTTP client omits cookies/credentials and rejects redirects and endpoint paths that leave the configured API origin.

## Verification commands

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

See `TEST_RESULTS.md` for the exact checks actually executed in the packaging environment.

## Screens and navigation

- Dashboard: backend/database health, target and audit counts, recent jobs, engine statuses, recent activity, and module shortcuts.
- Targets, scanner, browser bots, load tests, findings, reports, history: explicit contract-not-configured or coming-soon states.
- Settings: displays API base URL status and all endpoint environment variables.
- Theme selector: dark/light mode, persisted locally where browser storage is available.

## Safety boundary

The browser must not decide whether a target is authorized. All target authorization, scope checks, redirect validation, DNS/IP policy, job limits, and audit recording must be enforced in the server-side execution path. The frontend is display/navigation only and does not replace Phase 3 enforcement.
