from __future__ import annotations

from app.models import Audit, AuditEvent, AuthorizationStatus, Finding, JobState, ScanJob, Severity, Target
from app.tooling import worker


def test_worker_persists_real_normalized_result(client, monkeypatch):
    db = client.app.state.db.SessionLocal()
    target = Target(name="worker target", base_url="https://example.com/", hostname="example.com",
                    authorization_status=AuthorizationStatus.authorized, owner_user_id=client.test_user_id,
                    authorization_note="Authorized in test fixture")
    db.add(target)
    db.flush()
    audit = Audit(target_id=target.id, name="HTTP header check", state=JobState.queued)
    db.add(audit)
    db.flush()
    job = ScanJob(audit_id=audit.id, engine="http_headers", state=JobState.queued, progress=0,
                  config={"profile": "quick", "authorization_confirmed": True}, results={})
    db.add(job)
    db.commit()
    job_id = job.id
    db.close()

    def fake_execute(engine, _target, _settings, profile, *, cancel_check=None):
        assert engine == "http_headers" and profile == "quick"
        assert cancel_check is not None
        return {"engine": engine, "summary": {"http_status": 200}, "finding_count": 1,
                "findings": [{"title": "Missing security header", "severity": "medium",
                              "url": "https://example.com/", "description": "CSP missing", "evidence": {"header": "content-security-policy"}}],
                "notes": [], "finished_at": "2026-10-19T00:00:00+00:00"}

    monkeypatch.setattr(worker, "execute_target_tool", fake_execute)
    assert worker.process_one(client.app.state.db, settings=client.app.state.settings) is True
    with client.app.state.db.SessionLocal() as check:
        finished = check.get(ScanJob, job_id)
        assert finished.state == JobState.completed and finished.progress == 100
        assert finished.results["finding_count"] == 1
        finding = check.query(Finding).filter(Finding.scan_job_id == job_id).one()
        assert finding.title == "Missing security header" and finding.severity == Severity.medium
        assert check.query(AuditEvent).filter(AuditEvent.entity_id == job_id, AuditEvent.event_type == "tool.completed").count() == 1


def test_worker_fails_closed_after_authorization_revoked(client, monkeypatch):
    db = client.app.state.db.SessionLocal()
    target = Target(name="revoked target", base_url="https://example.com/", hostname="example.com",
                    authorization_status=AuthorizationStatus.revoked, owner_user_id=client.test_user_id)
    db.add(target)
    db.flush()
    audit = Audit(target_id=target.id, name="No longer authorized", state=JobState.queued)
    db.add(audit)
    db.flush()
    job = ScanJob(audit_id=audit.id, engine="http_headers", state=JobState.queued, progress=0,
                  config={"profile": "quick"}, results={})
    db.add(job); db.commit(); job_id = job.id; db.close()
    monkeypatch.setattr(worker, "execute_target_tool", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run")))
    assert worker.process_one(client.app.state.db, settings=client.app.state.settings) is True
    with client.app.state.db.SessionLocal() as check:
        assert check.get(ScanJob, job_id).state == JobState.failed
