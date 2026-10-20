import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import inspect

from app.models import Audit, Finding, JobState, Severity, Target, WorkspaceScan

GOOD = {"name": "Shop", "base_url": "https://example.com/", "authorization_confirmed": True}


def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["api"] == "ok" and body["database"] == "ok" and body["status"] == "ok"


def test_health_reports_db_unavailable(client):
    client.app.state.db.ping = lambda: False
    body = client.get("/api/health").json()
    assert body["api"] == "ok" and body["database"] == "unavailable" and body["status"] == "degraded"


def test_create_and_list_target_persists(client):
    r = client.post("/api/targets", json=GOOD)
    assert r.status_code == 201, r.text
    t = r.json()["data"]
    assert t["hostname"] == "example.com" and t["authorization_status"] == "unverified"
    listing = client.get("/api/targets").json()
    assert listing["meta"]["total"] == 1 and listing["data"][0]["id"] == t["id"]


def test_duplicate_target_conflict(client):
    client.post("/api/targets", json=GOOD)
    r = client.post("/api/targets", json=GOOD)
    assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"


def test_authorization_must_be_confirmed(client):
    r = client.post("/api/targets", json={**GOOD, "authorization_confirmed": False})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "validation_error" and err["details"] and err["request_id"]


def test_private_and_loopback_denied_by_default(client):
    for url in ["http://127.0.0.1/", "http://10.1.2.3/", "http://rebind.test/", "http://[::1]/", "http://169.254.169.254/"]:
        r = client.post("/api/targets", json={**GOOD, "base_url": url})
        assert r.status_code == 400, url
        assert r.json()["error"]["code"] == "scope_violation"


def test_metadata_denied_even_in_lab_mode(make_client):
    c = make_client(allow_lab_targets=True)
    for metadata_url in [
        "http://169.254.169.254/latest",
        "http://[::ffff:169.254.169.254]/latest",
        "http://[::ffff:100.100.100.200]/latest",
    ]:
        r = c.post("/api/targets", json={**GOOD, "base_url": metadata_url})
        assert r.status_code == 400, metadata_url


def test_lab_mode_allows_loopback_and_flags_it(make_client):
    c = make_client(allow_lab_targets=True)
    r = c.post("/api/targets", json={**GOOD, "base_url": "http://lab.local:3000/"})
    assert r.status_code == 201 and r.json()["data"]["is_lab_target"] is True


def test_rejects_non_http_and_userinfo(client):
    for url in ["ftp://example.com/", "https://user:pw@example.com/"]:
        assert client.post("/api/targets", json={**GOOD, "base_url": url}).status_code == 400


def test_pagination_caps_page_size(client):
    r = client.get("/api/targets?page_size=1000")
    assert r.json()["meta"]["page_size"] == 100


def test_not_found_uses_error_envelope(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_unhandled_error_hides_details(client):
    @client.app.get("/api/boom")
    def boom():
        raise RuntimeError("secret-token-123")

    r = client.get("/api/boom")
    assert r.status_code == 500
    assert "secret-token-123" not in r.text and r.json()["error"]["code"] == "internal_error"


def test_dashboard_summary_counts(client):
    db = client.app.state.db.SessionLocal()
    t = Target(name="x", base_url="https://example.com/", hostname="example.com")
    a = Audit(target=t, name="a1", state=JobState.completed)
    db.add_all([t, a, Finding(audit=a, title="XSS", severity=Severity.high), Finding(audit=a, title="hdr", severity=Severity.low)])
    db.commit()
    d = client.get("/api/dashboard/summary").json()["data"]
    assert d["targets"] == 1 and d["audits_by_state"]["completed"] == 1
    assert d["findings_by_severity"]["high"] == 1 and d["open_findings"] == 2
    assert len(client.get("/api/findings?severity=high").json()["data"]) == 1
    assert client.get("/api/audits?state=completed").json()["meta"]["total"] == 1


def test_engines_never_report_fake_success(client):
    data = client.get("/api/engines/status").json()["data"]
    by_name = {engine["name"]: engine for engine in data}
    expected = {"http_headers", "dns_audit", "tls_audit", "auth_surface", "zap", "nuclei", "schemathesis",
                "playwright", "accessibility", "k6", "trivy", "semgrep", "gitleaks", "testssl", "sbom", "reports"}
    assert expected <= set(by_name)
    assert by_name["reports"]["state"] == "available"
    assert all(engine["state"] == "disabled" for name, engine in by_name.items() if name != "reports")


def test_tool_catalog_only_advertises_executable_builtin_when_enabled(make_client):
    client = make_client(tool_execution_enabled=True)
    data = client.get("/api/tools/catalog").json()["data"]
    by_id = {tool["id"]: tool for tool in data}
    assert by_id["http_headers"]["state"] == "available"
    assert by_id["dns_audit"]["state"] == "available"
    assert by_id["reports"]["state"] == "available"
    assert by_id["nuclei"]["state"] == "disabled"
    assert by_id["trivy"]["state"] in {"disabled", "not_configured", "unavailable"}


def test_production_tool_center_fails_closed_when_worker_is_offline(make_client):
    client = make_client(tool_execution_enabled=True)
    # Set after app creation to exercise production catalog/queue policy with the SQLite test fixture.
    client.app.state.settings.env = "production"
    response = client.get("/api/tools/catalog")
    assert response.status_code == 200
    data = response.json()["data"]
    assert all(item["state"] != "available" for item in data if item["id"] != "reports")
    queued = client.post("/api/tools/runs", json={"engine": "http_headers", "target_id": "00000000-0000-4000-8000-000000000001",
                         "profile": "quick", "authorization_confirmed": True})
    assert queued.status_code == 503
    assert queued.json()["error"]["code"] == "tool_worker_offline"


def test_live_worker_heartbeat_overrides_api_local_tool_catalog(client):
    from datetime import UTC, datetime
    from app.models import WorkerHeartbeat

    with client.app.state.db.SessionLocal() as db:
        current = client.get("/api/tools/catalog").json()["data"]
        advertised = [dict(item) for item in current]
        nuclei = next(item for item in advertised if item["id"] == "nuclei")
        nuclei["state"] = "available"
        nuclei["detail"] = "Available in the isolated worker image."
        db.add(WorkerHeartbeat(id="primary", status="online", capabilities=advertised, last_seen=datetime.now(UTC)))
        db.commit()

    response = client.get("/api/tools/catalog")
    assert response.status_code == 200
    catalog = {item["id"]: item for item in response.json()["data"]}
    assert catalog["nuclei"]["state"] == "available"
    assert "/usr/" not in catalog["nuclei"]["detail"]


def test_stale_worker_heartbeat_falls_back_to_api_catalog(client):
    from datetime import UTC, datetime, timedelta
    from app.models import WorkerHeartbeat

    with client.app.state.db.SessionLocal() as db:
        db.add(WorkerHeartbeat(id="primary", status="online", capabilities=[{"id": "nuclei", "state": "available"}],
                               last_seen=datetime.now(UTC) - timedelta(minutes=5)))
        db.commit()
    response = client.get("/api/tools/catalog")
    assert response.status_code == 200
    nuclei = next(item for item in response.json()["data"] if item["id"] == "nuclei")
    assert nuclei["state"] != "available"


def test_tool_run_requires_authorization_and_persists_queue(make_client):
    client = make_client(tool_execution_enabled=True)
    created = client.post("/api/targets", json={"name": "Training target", "base_url": "https://example.com/",
        "authorization_confirmed": True, "authorization_note": "Initial registration declaration"})
    assert created.status_code == 201, created.text
    target = created.json()["data"]
    body = {"engine": "http_headers", "target_id": target["id"], "profile": "quick", "authorization_confirmed": True}
    denied = client.post("/api/tools/runs", json=body)
    assert denied.status_code == 409 and denied.json()["error"]["code"] == "authorization_not_active"
    authorized = client.post(f"/api/targets/{target['id']}/authorize", json={"confirmed": True, "note": "Approved work order SEC-2026-008"})
    assert authorized.status_code == 200, authorized.text
    queued = client.post("/api/tools/runs", json=body)
    assert queued.status_code == 202, queued.text
    job = queued.json()["data"]
    assert job["state"] == "queued" and job["engine"] == "http_headers"
    assert client.get("/api/tools/runs").json()["data"][0]["id"] == job["id"]


def test_report_formats_are_exported_and_html_is_escaped(client):
    db = client.app.state.db.SessionLocal()
    user_id = client.test_user_id
    target = Target(name="Report target", base_url="https://example.com/", hostname="example.com", owner_user_id=user_id)
    audit = Audit(target=target, name="Report audit", state=JobState.completed)
    db.add_all([target, audit]); db.flush()
    db.add(Finding(audit_id=audit.id, title="<script>alert(1)</script>", severity=Severity.high, url="https://example.com/"))
    db.commit()
    response = client.get(f"/api/reports/export?audit_id={audit.id}&format=html")
    assert response.status_code == 200 and "&lt;script&gt;" in response.text and "<script>alert(1)</script>" not in response.text
    sarif = client.get(f"/api/reports/export?audit_id={audit.id}&format=sarif")
    assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
    json_report = client.get(f"/api/reports/export?audit_id={audit.id}&format=json")
    assert json_report.status_code == 200 and json_report.json()["findings"][0]["title"] == "<script>alert(1)</script>"
    pdf = client.get(f"/api/reports/export?audit_id={audit.id}&format=pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"].startswith("application/pdf") and pdf.content.startswith(b"%PDF-1.4")
    db.close()


def test_alembic_migration_matches_models(tmp_path):
    url = f"sqlite:///{tmp_path}/mig.db"
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "WEBGUARD_DATABASE_URL": url}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=root, env=env, check=True)
    from app.db import make_engine

    tables = set(inspect(make_engine(url)).get_table_names())
    assert {"targets", "audits", "findings", "scan_jobs", "load_tests", "reports", "audit_events", "users", "workspace_scans", "worker_heartbeats"} <= tables
    subprocess.run([sys.executable, "-m", "alembic", "downgrade", "base"], cwd=root, env=env, check=True)


def test_protected_api_requires_bearer_token(client):
    from fastapi.testclient import TestClient

    unauthenticated = TestClient(client.app, raise_server_exceptions=False)
    response = unauthenticated.get("/api/dashboard/summary")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"


def test_login_returns_short_lived_bearer_token_and_me(client):
    response = client.post("/api/auth/login", json={"email": "ADMIN@example.com", "password": "test-password-123456"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token_type"] == "bearer" and payload["expires_in"] == 900
    assert payload["user"]["role"] == "admin"
    from fastapi.testclient import TestClient

    authenticated = TestClient(client.app)
    authenticated.headers["Authorization"] = f"Bearer {payload['access_token']}"
    me = authenticated.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["email"] == "admin@example.com"


def test_viewer_cannot_register_target_and_cannot_read_other_owners_data(client):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token, hash_password
    from app.models import User

    with client.app.state.db.SessionLocal() as db:
        viewer = User(email="viewer@example.com", password_hash=hash_password("viewer-test-password-123"), role="viewer")
        db.add(viewer)
        db.commit()
        db.refresh(viewer)
        token, _ = create_access_token(viewer, client.app.state.settings)
        viewer_id = viewer.id
    viewer_client = TestClient(client.app, raise_server_exceptions=False)
    viewer_client.headers["Authorization"] = f"Bearer {token}"
    assert viewer_client.post("/api/targets", json=GOOD).status_code == 403
    # Admin-created targets are not exposed to a viewer's tenant scope.
    client.post("/api/targets", json=GOOD)
    listing = viewer_client.get("/api/targets")
    assert listing.status_code == 200 and listing.json()["meta"]["total"] == 0
    assert viewer_id


def test_login_uses_generic_error_for_unknown_user_and_wrong_password(client):
    unknown = client.post("/api/auth/login", json={"email": "missing@example.com", "password": "wrong-password"})
    wrong = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "wrong-password"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["error"]["code"] == wrong.json()["error"]["code"] == "invalid_credentials"


def test_production_settings_fail_closed():
    import pytest
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(env="production")
    safe = Settings(
        env="production",
        database_url="postgresql+psycopg://wg:longpassword@db:5432/webguard",
        secret_key="a" * 96,
        allowed_hosts="webguard.example.com",
        cors_origins="",
        allow_lab_targets=False,
    )
    assert safe.env == "production"


def test_invalid_port_and_mixed_dns_are_denied(client):
    for url in ["http://example.com:bad/", "http://mixed.test/"]:
        response = client.post("/api/targets", json={**GOOD, "base_url": url})
        assert response.status_code == 400, response.text
        assert response.json()["error"]["code"] == "scope_violation"


def test_login_rate_limit_counts_failures_per_ip(client):
    bad = {"email": "missing@example.com", "password": "wrong-password"}
    for _ in range(10):
        response = client.post("/api/auth/login", json=bad)
        assert response.status_code == 401
    blocked = client.post("/api/auth/login", json=bad)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert blocked.headers["retry-after"] == "900"


def test_production_rejects_insecure_cross_origin_cors():
    import pytest
    from pydantic import ValidationError
    from app.config import Settings

    common = {
        "env": "production",
        "database_url": "postgresql+psycopg://wg:longpassword@db:5432/webguard",
        "secret_key": "b" * 96,
        "allowed_hosts": "webguard.example.com",
        "allow_lab_targets": False,
    }
    with pytest.raises(ValidationError):
        Settings(**common, cors_origins="http://another.example.com")
    valid = Settings(**common, cors_origins="https://another.example.com")
    assert valid.cors_origins == "https://another.example.com"


def test_audit_and_finding_data_isolated_by_target_owner(client):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token, hash_password
    from app.models import User

    created = client.post("/api/targets", json=GOOD)
    target_id = created.json()["data"]["id"]
    with client.app.state.db.SessionLocal() as db:
        audit = Audit(target_id=target_id, name="test audit", state=JobState.completed)
        db.add(audit)
        db.flush()
        db.add(Finding(audit_id=audit.id, title="sample finding", severity=Severity.high))
        viewer = User(email="limited@example.com", password_hash=hash_password("viewer-test-password-123"), role="viewer")
        db.add(viewer)
        db.commit()
        db.refresh(viewer)
        token, _ = create_access_token(viewer, client.app.state.settings)
    other = TestClient(client.app, raise_server_exceptions=False)
    other.headers["Authorization"] = f"Bearer {token}"
    assert other.get("/api/audits").json()["meta"]["total"] == 0
    assert other.get("/api/findings").json()["meta"]["total"] == 0
    assert other.get("/api/dashboard/summary").json()["data"]["targets"] == 0


def test_regression_comparison_requires_same_owned_target_and_reports_changes(client):
    db = client.app.state.db.SessionLocal()
    target = Target(name="Regression target", base_url="https://example.com/", hostname="example.com", owner_user_id=client.test_user_id)
    baseline = Audit(target=target, name="baseline", state=JobState.completed)
    current = Audit(target=target, name="current", state=JobState.completed)
    db.add_all([target, baseline, current]); db.flush()
    db.add_all([
        Finding(audit_id=baseline.id, title="Old header issue", severity=Severity.low, url="https://example.com/old"),
        Finding(audit_id=baseline.id, title="Still broken", severity=Severity.medium, url="https://example.com/common"),
        Finding(audit_id=current.id, title="New finding", severity=Severity.high, url="https://example.com/new"),
        Finding(audit_id=current.id, title="Still broken", severity=Severity.medium, url="https://example.com/common"),
    ])
    db.commit(); baseline_id = baseline.id; current_id = current.id; db.close()
    response = client.get(f"/api/audits/{current_id}/regression?baseline_audit_id={baseline_id}")
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert [item["title"] for item in data["new_findings"]] == ["New finding"]
    assert [item["title"] for item in data["resolved_findings"]] == ["Old header issue"]
    assert data["unchanged_findings"] == 1


def test_sbom_scan_exports_cyclonedx_only_to_owning_admin(client):
    db = client.app.state.db.SessionLocal()
    scan = WorkspaceScan(owner_user_id=client.test_user_id, engine="sbom", profile="quick", state=JobState.completed,
                         progress=100, results={"format": "CycloneDX", "sbom_document": {"bomFormat": "CycloneDX",
                         "specVersion": "1.6", "version": 1, "components": [{"name": "demo", "version": "1.0.0", "type": "library"}]}})
    db.add(scan); db.commit(); scan_id = scan.id; db.close()
    response = client.get(f"/api/reports/export?workspace_scan_id={scan_id}&format=cyclonedx")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert response.json()["bomFormat"] == "CycloneDX" and response.json()["components"][0]["name"] == "demo"
    invalid = client.get(f"/api/reports/export?workspace_scan_id={scan_id}&format=sarif")
    assert invalid.status_code == 200 and invalid.json()["version"] == "2.1.0"


def test_cyclonedx_export_rejects_normal_audit_source(client):
    db = client.app.state.db.SessionLocal()
    target = Target(name="Report target", base_url="https://example.com/", hostname="example.com", owner_user_id=client.test_user_id)
    audit = Audit(target=target, name="Regular audit", state=JobState.completed)
    db.add_all([target, audit]); db.commit(); audit_id = audit.id; db.close()
    response = client.get(f"/api/reports/export?audit_id={audit_id}&format=cyclonedx")
    assert response.status_code == 400 and response.json()["error"]["code"] == "invalid_report_format"
