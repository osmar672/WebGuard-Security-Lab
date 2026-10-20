def test_ai_status_uses_local_mode_without_exposing_secrets(client):
    response = client.get("/api/ai/status")
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["configured"] is False
    assert data["mode"] == "local_rules"
    assert "WEBGUARD_AI_API_KEY" not in response.text


def test_ai_process_review_returns_real_empty_state_and_audits_usage(client):
    response = client.post("/api/ai/assist", json={"task": "process_review"})
    assert response.status_code == 200, response.text
    result = response.json()["data"]
    assert result["mode"] == "local_rules"
    assert "Objetivos registrados: **0**" in result["answer"]
    assert "no sustituye" in result["answer"].lower() or "reglas locales" in result["answer"].lower()


def test_ai_triage_uses_owned_findings_but_not_evidence_blobs(client):
    from app.models import Audit, Finding, FindingStatus, JobState, Severity, Target

    secret_marker = "do-not-send-evidence-secret-9182"
    with client.app.state.db.SessionLocal() as db:
        target = Target(name="Authorized lab", base_url="https://example.com/", hostname="example.com",
                        owner_user_id=client.test_user_id)
        audit = Audit(target=target, name="Assessment", state=JobState.completed)
        db.add_all([target, audit])
        db.flush()
        db.add(Finding(audit_id=audit.id, title="Missing security header", severity=Severity.high,
                       status=FindingStatus.open, description="A response header is absent.",
                       evidence={"token": secret_marker}))
        db.commit()

    response = client.post("/api/ai/assist", json={"task": "finding_triage"})
    assert response.status_code == 200, response.text
    body = response.json()["data"]["answer"]
    assert "Missing security header" in body
    assert secret_marker not in body


def test_ai_audit_summary_does_not_disclose_audit_outside_user_scope(make_client):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token, hash_password
    from app.models import Audit, JobState, Target, User

    client = make_client()
    with client.app.state.db.SessionLocal() as db:
        owner = User(email="other-owner@example.com", password_hash=hash_password("owner-safe-password-123"), role="operator")
        viewer = User(email="viewer@example.com", password_hash=hash_password("viewer-safe-password-123"), role="viewer")
        target = Target(name="Private target", base_url="https://example.com/", hostname="example.com", owner=owner)
        audit = Audit(target=target, name="Private audit", state=JobState.completed)
        db.add_all([owner, viewer, target, audit])
        db.commit()
        db.refresh(viewer)
        audit_id = audit.id
        viewer_token, _ = create_access_token(viewer, client.app.state.settings)
    viewer_client = TestClient(client.app, raise_server_exceptions=False)
    viewer_client.headers.update({"Authorization": f"Bearer {viewer_token}"})
    response = viewer_client.post("/api/ai/assist", json={"task": "audit_summary", "audit_id": audit_id})
    assert response.status_code == 404
    assert "Private audit" not in response.text


def test_ai_provider_uses_backend_configuration_without_frontend_tools(client, monkeypatch):
    import app.main as main_module

    client.app.state.settings.ai_api_key = "backend-only-secret"
    client.app.state.settings.ai_model = "test-model"
    captured = {}

    async def fake_completion(settings, system, prompt):
        captured["system"] = system
        captured["prompt"] = prompt
        return "Prioridad 1: revisar configuración."

    monkeypatch.setattr(main_module, "remote_completion", fake_completion)
    status = client.get("/api/ai/status").json()["data"]
    assert status["configured"] is True
    assert "backend-only-secret" not in str(status)
    question_with_secret = "¿Cómo priorizo tareas? api_key=sk-12345678901234567890ABCDEF"
    result = client.post("/api/ai/assist", json={"task": "general", "question": question_with_secret})
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["mode"] == "remote_model"
    assert data["answer"] == "Prioridad 1: revisar configuración."
    assert "authorized web-security" in captured["system"]
    assert "¿Cómo priorizo tareas?" in captured["prompt"]
    assert "12345678901234567890ABCDEF" not in captured["prompt"]
    assert "[REDACTED]" in captured["prompt"]


def test_ai_request_validation_rejects_overlong_question(client):
    response = client.post("/api/ai/assist", json={"task": "general", "question": "x" * 3001})
    assert response.status_code == 422


def test_production_ai_provider_requires_https():
    import pytest
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            env="production",
            database_url="postgresql+psycopg://wg:longpassword@db:5432/webguard",
            secret_key="c" * 96,
            allowed_hosts="webguard.example.com",
            ai_api_key="example-secret",
            ai_base_url="http://api.example.com/v1",
        )


def test_ai_request_limit_is_enforced_per_authenticated_user(client):
    client.app.state.settings.ai_rate_limit_requests = 1
    first = client.post("/api/ai/assist", json={"task": "process_review"})
    second = client.post("/api/ai/assist", json={"task": "process_review"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"


def test_ai_prompt_redacts_common_credentials_before_provider_submission():
    from app.ai_service import build_remote_prompt

    prompt = build_remote_prompt(
        "general",
        "Please help. Authorization: Bearer eyJabcdefghij.abcdefghijk.abcdefghijk password=hunter2 sk-12345678901234567890ABCDEF",
        {"finding": "access_token=secret-value"},
    )
    assert "hunter2" not in prompt
    assert "12345678901234567890ABCDEF" not in prompt
    assert "secret-value" not in prompt
    assert "[REDACTED]" in prompt or "[REDACTED_JWT]" in prompt


def test_ai_provider_failure_falls_back_without_breaking_process_review(client, monkeypatch):
    import app.main as main_module
    from app.ai_service import AIProviderError

    client.app.state.settings.ai_api_key = "backend-only-secret"

    async def provider_down(settings, system, prompt):
        raise AIProviderError("provider unavailable")

    monkeypatch.setattr(main_module, "remote_completion", provider_down)
    response = client.post("/api/ai/assist", json={"task": "process_review"})
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["mode"] == "local_rules"
    assert "Objetivos registrados: **0**" in data["answer"]


def test_ai_defaults_to_groq_provider_and_supported_model():
    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.ai_provider_name == "Groq"
    assert settings.ai_base_url == "https://api.groq.com/openai/v1"
    assert settings.ai_model == "openai/gpt-oss-120b"


def test_ai_prompt_redacts_groq_api_keys():
    from app.ai_service import build_remote_prompt

    prompt = build_remote_prompt(
        "general",
        "Please inspect this log containing gsk_1234567890abcdefghijklmnopqrstuv",
        {"log_line": "gsk_abcdefghijklmnop1234567890"},
    )
    assert "gsk_1234567890abcdefghijklmnopqrstuv" not in prompt
    assert "gsk_abcdefghijklmnop1234567890" not in prompt
    assert "[REDACTED_GROQ_API_KEY]" in prompt
