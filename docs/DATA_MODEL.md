# Data model

All IDs are UUID4 strings. Timestamps are UTC. Enums are stored as strings so SQLite (development) and PostgreSQL (production) can share the model. Use Alembic migrations; do not let application startup mutate production schema.

| Table | Key columns | Relations / constraints |
|---|---|---|
| `users` | email (unique/indexed), Argon2 password hash, role (`admin/operator/viewer`), `is_active` | Principal for authentication; never store plaintext passwords |
| `targets` | name, base_url (unique), hostname (indexed), scope_rules JSON, authorization_status (`unverified/authorized/revoked`), authorization_note, is_lab_target, owner_user_id | `owner_user_id` FK to `users`, nullable only to preserve pre-auth historical rows; has many audits |
| `audits` | name, state (job state), started_at, finished_at | FK target (cascade); index on state/created_at |
| `scan_jobs` | engine, state, progress 0–100, config JSON, error_message | FK audit (cascade); CHECK progress |
| `load_tests` | state, virtual_users 1–500, duration_seconds 1–3600, results JSON | FK audit (cascade); CHECKs |
| `findings` | title, severity (`info/low/medium/high/critical`), status (`open/confirmed/false_positive/resolved`), url, description, evidence JSON | FK audit (cascade), FK scan_job (set null) |
| `reports` | format (`json/html/pdf/sarif`), state, storage_path | FK audit (cascade) |
| `audit_events` | entity_type, entity_id, event_type, payload JSON, actor_user_id | Actor FK to `users` (set null); entity/created index |
| `worker_heartbeats` | worker_id, last_seen_at, capabilities JSON, status | Worker ID primary/unique identifier; consumed by API readiness checks; stale heartbeat fails closed in production |

`authorization_confirmed` in the API is an operator attestation and does not automatically change a target's persisted `authorization_status` from `unverified`. The application does not yet have a workflow for validating authorization evidence or revoking grants.

Migrations: `backend/alembic/versions/0001_initial_schema.py`, `0002_authentication_and_ownership.py`, `0003_tool_center.py`, and `0004_worker_heartbeat.py`. Local development uses SQLite; production validation requires PostgreSQL through `WEBGUARD_DATABASE_URL`.
