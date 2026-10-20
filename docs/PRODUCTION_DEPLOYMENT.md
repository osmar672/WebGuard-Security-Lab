# Production deployment runbook

This runbook deploys the WebGuard dashboard/API behind Caddy with HTTPS and PostgreSQL. The optional database-backed worker has bounded adapters for built-in HTTP/DNS/TLS checks and external engines. External engine execution remains disabled by default and depends on a separately built, reviewed worker image, approved target authorization, and enforced network egress policy. Do not advertise coverage beyond the engines actually installed and shown as available in the live catalog.

## Requirements before deployment

- A Linux server maintained with security updates; Docker Engine and Docker Compose v2.
- A real DNS name whose A record points to the server. Add an AAAA record only if IPv6 routing/firewall are correctly configured.
- Inbound TCP ports 80/443 and UDP 443 (HTTP-01/TLS and optional HTTP/3). SSH should be restricted separately.
- A trusted route for managing the host, monitored disk space, and an external encrypted backup destination.
- A release owner responsible for security updates, incidents, restore drills, and rotating credentials.

## 1. Configure secrets

```bash
cp .env.production.example .env.production
chmod 600 .env.production
openssl rand -hex 48  # copy output to WEBGUARD_SECRET_KEY
openssl rand -hex 32  # copy output to POSTGRES_PASSWORD
```

Edit `.env.production` and set:

- `WEBGUARD_DOMAIN`: the DNS hostname users will open.
- `WEBGUARD_ALLOWED_HOSTS`: exactly the same hostname.
- `WEBGUARD_SECRET_KEY`: output of `openssl rand -hex 48`.
- `POSTGRES_DB` and `POSTGRES_USER`: letters, numbers, underscores only.
- `POSTGRES_PASSWORD`: output of `openssl rand -hex 32`.
- Leave `WEBGUARD_ENV=production`, `WEBGUARD_ALLOW_LAB_TARGETS=false`; keep CORS empty when UI/API are served from the same origin.
- `WEBGUARD_BACKUP_AGE_RECIPIENT`: public `age` recipient key used for encrypted database backups. Generate the private key on a separate administration machine with `age-keygen -o ~/webguard-backup-key.txt`, store that private file offline/securely, and copy only the printed `age1...` recipient to the server environment. Keep the private key off the server.
- Optional AI Copilot: leave `WEBGUARD_AI_API_KEY` blank for local rules mode, or set `WEBGUARD_AI_BASE_URL=https://api.groq.com/openai/v1`, `WEBGUARD_AI_API_KEY` to your Groq key, `WEBGUARD_AI_MODEL=openai/gpt-oss-120b`, and `WEBGUARD_AI_RATE_LIMIT_REQUESTS` to approved values. Keep the provider key only in `.env.production`/a secrets manager, chmod `600` on that file, review provider data-retention terms, and restrict API egress to the approved provider destinations. See `docs/AI_COPILOT.md`.

The simple hex-only password policy is intentional because Compose constructs the PostgreSQL URL from the password. Do not put secrets in Git, in `VITE_*`, logs, screenshots, or issue trackers. If Docker networks `172.30.80.0/24` (proxy) or `172.30.81.0/24` (database) overlap with your host's existing networks, change the subnet and fixed API/Caddy IPs together; keep Uvicorn's trusted-proxy IP aligned with Caddy's proxy-network address.

## 2. Preflight and build

```bash
./scripts/production-preflight.sh
docker compose --env-file .env.production -f compose.yaml build api web
docker compose --env-file .env.production -f compose.yaml up -d --wait db
```

The preflight safely parses the environment file without evaluating it as shell code. It validates the variable formats and the Compose model; it does not prove public DNS, firewall, TLS issuance, backups or external security posture. A configured AI provider is called from the API server; apply outbound egress restrictions and an external/shared rate limit before allowing broad access.

## 3. Apply migrations and start services

Run migrations as a one-off command rather than automatically in every API worker (avoids competing migration jobs):

```bash
docker compose --env-file .env.production -f compose.yaml run --rm --no-deps api alembic upgrade head
docker compose --env-file .env.production -f compose.yaml up -d api web
```

Create the first administrator interactively. Passwords need at least 14 characters; use a unique password from a password manager:

```bash
docker compose --env-file .env.production -f compose.yaml exec api python -m app.cli create-user --role admin
```

Create additional users from the same CLI with `--role operator` or `--role viewer`. There is no public user-registration endpoint by design.

## 4. Optional Tool Center worker

The worker is separate from the API and remains disabled unless its compose profile is started and execution flags are approved. Before starting it, ensure the configured binaries show as available in the dashboard and enforce outbound network filtering at the host/container boundary; `tool_egress` alone is not a firewall.

```bash
docker compose --env-file .env.production -f compose.yaml --profile tools build worker
docker compose --env-file .env.production -f compose.yaml --profile tools up -d worker
docker compose --env-file .env.production -f compose.yaml logs -f worker
```

The worker image installs the pinned Python engine packages (Playwright, Schemathesis, Semgrep) and Chromium. Native binaries for Nuclei, k6, Trivy, Gitleaks and testssl.sh are not bundled; add pinned vendor releases to a reviewed custom worker image before enabling those adapters. ZAP remains a separate service: configure `WEBGUARD_ZAP_API_URL` and `WEBGUARD_ZAP_API_KEY` on the worker only, and do not expose its API port publicly. In production, the dashboard will not advertise executable tools or accept jobs without a recent worker heartbeat.

For source scans, create a private override based on `compose.workspace.override.example.yaml`, set `WEBGUARD_WORKSPACE_HOST_PATH` to a selected source folder and mount it read-only. Never mount `/`, the home directory, secrets folders or the host Docker socket. API clients cannot select paths.

## 5. Verify deployment

```bash
docker compose --env-file .env.production -f compose.yaml ps
docker compose --env-file .env.production -f compose.yaml logs --tail=100 api web db
curl --fail --show-error https://YOUR_DOMAIN/api/health
```

Also open `https://YOUR_DOMAIN`, sign in as the admin, verify that a viewer cannot register targets, and confirm that an unauthenticated `GET /api/dashboard/summary` returns `401`. The public health route returns only API/database state and version. OpenAPI/docs are disabled when `WEBGUARD_ENV=production`.

## Backups and restore drills

Install `age` on the host. Generate a private key outside the server and securely store it; put only its public recipient (`age1...`) in `WEBGUARD_BACKUP_AGE_RECIPIENT`.

```bash
sudo pacman -S --needed age  # Arch/CachyOS
./scripts/backup-postgres.sh
sha256sum -c backups/webguard-*.sql.gz.age.sha256
```

The backup is encrypted before being written to disk. Copy encrypted files to a separate system/object store; local retention is only 14 days. A successful backup is not enough: regularly perform a restore drill in an isolated environment using the private age key and verify application-level records.

Example restore pipeline for an **empty, isolated recovery database** after setting Compose variables and selecting one backup file:

```bash
age --decrypt -i /secure/offline/backup-age-key.txt backups/webguard-TIMESTAMP.sql.gz.age \
  | gzip -dc \
  | docker compose --env-file .env.production -f compose.yaml exec -T db \
      sh -ec 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

Do not restore over production without a reviewed recovery plan. Test decryption and SQL restore in staging first.

## Updates and rollback

1. Review the release notes and security advisories for Python, Node, Caddy, PostgreSQL, and direct/transitive packages.
2. Make an encrypted backup and verify its checksum before changing schema or images.
3. Build and test the release in CI; run the migration explicitly as above.
4. Recreate services and smoke-test login, access-control boundaries, health, and target ownership.
5. Keep the previous known-good image digest and a tested DB restore plan. A database downgrade is not a safe substitute for restore testing.

## Minimum operational controls still needed for a real public launch

- Put a shared edge/WAF rate limit or distributed login throttle in front of the API; the API's current 10-failure/15-minute limiter is in-memory and per worker only.
- Implement admin user lifecycle (disable/reset/role changes), password recovery policy, MFA/SSO if required, and token revocation/session review.
- Configure central alerting/log retention with secrets and target evidence redacted, plus monitoring for disk, memory, CPU, database pool and certificate renewal.
- Pin container images by digest and produce/protect an SBOM/release provenance for regulated/reproducible deployments.
- Confirm backups are off-host and encrypted; complete restore exercises and an external penetration test.
- Before enabling external scans, enforce and test network egress restrictions for every worker/container (including browser subresources and ZAP), validate the distributed rate-limit strategy, and exercise queue recovery after forced worker termination. The database-backed queue and single-worker adapter are present, but cross-worker coordination and shared distributed rate limits still need implementation before horizontal scaling.

Do not expose the scanner as production-ready until these items are accepted by the release owner.
