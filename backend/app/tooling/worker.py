"""Persistent database-backed worker for bounded WebGuard tool executions."""
from __future__ import annotations

import argparse
import logging
import time
import threading
from datetime import UTC, datetime

from sqlalchemy import select

from app.config import get_settings
from app.db import Database
from app.models import Audit, AuditEvent, Finding, FindingStatus, JobState, ScanJob, Severity, Target, User, WorkspaceScan, WorkerHeartbeat
from app.tooling.runner import ToolExecutionError, execute_target_tool, execute_workspace_tool

LOG = logging.getLogger("webguard.worker")


def _cancel_check(database: Database, job_id: str, *, workspace: bool = False, target_id: str | None = None) -> bool:
    with database.SessionLocal() as db:
        if workspace:
            row = db.get(WorkspaceScan, job_id)
            return row is None or row.state == JobState.cancelled
        row = db.get(ScanJob, job_id)
        if row is None or row.state == JobState.cancelled:
            return True
        if target_id:
            target = db.get(Target, target_id)
            return target is None or target.authorization_status.value != "authorized"
        return False


def process_one(database: Database, *, settings=None) -> bool:
    settings = settings or get_settings()
    claimed_type = None
    claimed_id = None
    target_id = None
    with database.SessionLocal() as db:
        # Worker deployment should normally run one process per queue, but SELECT FOR UPDATE
        # prevents duplicate claims when the database supports SKIP LOCKED.
        query = select(ScanJob).where(ScanJob.state == JobState.queued).order_by(ScanJob.created_at.asc()).with_for_update(skip_locked=True)
        job = db.scalars(query.limit(1)).first()
        if job is not None:
            audit = db.get(Audit, job.audit_id)
            target = db.get(Target, audit.target_id) if audit else None
            if not audit or not target:
                job.state = JobState.failed
                job.error_message = "Target or audit record is missing"
                job.finished_at = datetime.now(UTC)
                db.commit()
                return True
            if target.authorization_status.value != "authorized":
                job.state = JobState.failed
                job.error_message = "Target authorization is not active"
                job.finished_at = datetime.now(UTC)
                audit.state = JobState.failed
                audit.finished_at = datetime.now(UTC)
                db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.denied",
                                  payload={"engine": job.engine, "reason": "authorization_not_active"},
                                  actor_user_id=target.owner_user_id))
                db.commit()
                return True
            job.state = JobState.running
            job.started_at = datetime.now(UTC)
            job.progress = 5
            audit.state = JobState.running
            audit.started_at = datetime.now(UTC)
            db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.started",
                              payload={"engine": job.engine, "profile": job.config.get("profile", "quick")},
                              actor_user_id=target.owner_user_id))
            claimed_type, claimed_id, target_id = "target", job.id, target.id
            engine, profile = job.engine, job.config.get("profile", "quick")
            db.commit()
        else:
            workspace_query = select(WorkspaceScan).where(WorkspaceScan.state == JobState.queued).order_by(WorkspaceScan.created_at.asc()).with_for_update(skip_locked=True)
            scan = db.scalars(workspace_query.limit(1)).first()
            if scan is not None:
                scan.state = JobState.running
                scan.started_at = datetime.now(UTC)
                scan.progress = 5
                db.add(AuditEvent(entity_type="workspace_scan", entity_id=scan.id, event_type="workspace_scan.started",
                                  payload={"engine": scan.engine, "profile": scan.profile}, actor_user_id=scan.owner_user_id))
                claimed_type, claimed_id = "workspace", scan.id
                engine, profile = scan.engine, scan.profile
                db.commit()
    if not claimed_id:
        return False

    try:
        if claimed_type == "target":
            with database.SessionLocal() as db:
                target = db.get(Target, target_id)
                if target is None:
                    raise ToolExecutionError("Target no longer exists")
                result = execute_target_tool(
                    engine, target, settings, profile,
                    cancel_check=lambda: _cancel_check(database, claimed_id, target_id=target_id),
                )
        else:
            result = execute_workspace_tool(
                engine, settings, profile,
                cancel_check=lambda: _cancel_check(database, claimed_id, workspace=True),
            )
        _complete(database, claimed_type, claimed_id, result)
    except Exception as exc:
        safe_message = str(exc)[:1000] if isinstance(exc, ToolExecutionError) else f"Tool execution failed ({type(exc).__name__}). See protected worker logs."
        LOG.warning("Tool job %s failed: %s", claimed_id, safe_message)
        _fail(database, claimed_type, claimed_id, safe_message)
    return True


def _complete(database: Database, claimed_type: str, job_id: str, result: dict) -> None:
    now = datetime.now(UTC)
    findings = result.get("findings", []) if isinstance(result, dict) else []
    with database.SessionLocal() as db:
        if claimed_type == "target":
            job = db.get(ScanJob, job_id)
            if job is None: return
            audit = db.get(Audit, job.audit_id)
            target = db.get(Target, audit.target_id) if audit else None
            if job.state == JobState.cancelled or (target and target.authorization_status.value != "authorized"):
                job.state = JobState.cancelled
                job.finished_at = now
                if audit:
                    audit.state = JobState.cancelled
                    audit.finished_at = now
                return db.commit()
            job.state = JobState.completed
            job.progress = 100
            job.results = result
            job.finished_at = now
            if audit:
                audit.state = JobState.completed
                audit.finished_at = now
            for item in findings:
                db.add(Finding(
                    audit_id=audit.id if audit else None,
                    scan_job_id=job.id,
                    title=str(item.get("title", "Tool finding"))[:300],
                    severity=Severity(item.get("severity", "info")),
                    status=FindingStatus.open,
                    url=item.get("url"), description=item.get("description"), evidence=item.get("evidence", {}),
                ))
            db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.completed",
                              payload={"engine": job.engine, "finding_count": len(findings)},
                              actor_user_id=target.owner_user_id if target else None))
        else:
            scan = db.get(WorkspaceScan, job_id)
            if scan is None: return
            if scan.state == JobState.cancelled:
                scan.finished_at = now
                return db.commit()
            scan.state = JobState.completed
            scan.progress = 100
            scan.results = result
            scan.finished_at = now
            for item in findings:
                db.add(Finding(
                    audit_id=None,
                    workspace_scan_id=scan.id,
                    title=str(item.get("title", "Source finding"))[:300],
                    severity=Severity(item.get("severity", "info")),
                    status=FindingStatus.open,
                    url=item.get("url"), description=item.get("description"), evidence=item.get("evidence", {}),
                ))
            db.add(AuditEvent(entity_type="workspace_scan", entity_id=scan.id, event_type="workspace_scan.completed",
                              payload={"engine": scan.engine, "finding_count": len(findings)}, actor_user_id=scan.owner_user_id))
        db.commit()


def _fail(database: Database, claimed_type: str, job_id: str, message: str) -> None:
    now = datetime.now(UTC)
    with database.SessionLocal() as db:
        if claimed_type == "target":
            job = db.get(ScanJob, job_id)
            if job is None: return
            audit = db.get(Audit, job.audit_id)
            target = db.get(Target, audit.target_id) if audit else None
            if job.state != JobState.cancelled:
                job.state = JobState.failed
                job.error_message = message[:1000]
            job.finished_at = now
            if audit:
                audit.state = JobState.cancelled if job.state == JobState.cancelled else JobState.failed
                audit.finished_at = now
            db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.failed",
                              payload={"engine": job.engine, "error_category": message.split(";")[0][:200]},
                              actor_user_id=target.owner_user_id if target else None))
        else:
            scan = db.get(WorkspaceScan, job_id)
            if scan is None: return
            if scan.state != JobState.cancelled:
                scan.state = JobState.failed
                scan.error_message = message[:1000]
            scan.finished_at = now
            db.add(AuditEvent(entity_type="workspace_scan", entity_id=scan.id, event_type="workspace_scan.failed",
                              payload={"engine": scan.engine, "error_category": message.split(";")[0][:200]},
                              actor_user_id=scan.owner_user_id))
        db.commit()


def _publish_heartbeat(database: Database, settings, status: str = "online") -> None:
    from app.tooling.catalog import catalog
    with database.SessionLocal() as db:
        row = db.get(WorkerHeartbeat, "primary")
        if row is None:
            row = WorkerHeartbeat(id="primary", status=status, capabilities=catalog(settings), last_seen=datetime.now(UTC))
            db.add(row)
        else:
            row.status = status
            row.capabilities = catalog(settings)
            row.last_seen = datetime.now(UTC)
        db.commit()


def _heartbeat_loop(database: Database, settings, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            _publish_heartbeat(database, settings, "online")
        except Exception:
            LOG.exception("Could not publish tool worker heartbeat")
        stop_event.wait(10)
    try:
        _publish_heartbeat(database, settings, "offline")
    except Exception:
        LOG.exception("Could not mark tool worker offline")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the WebGuard tool queue worker")
    parser.add_argument("--poll-interval", type=float, default=1.5)
    args = parser.parse_args()
    settings = get_settings()
    if not settings.tool_execution_enabled:
        LOG.error("Tool worker will not start: WEBGUARD_TOOL_EXECUTION_ENABLED is false")
        return 2
    database = Database(settings.database_url)
    stop_event = threading.Event()
    heartbeat = threading.Thread(target=_heartbeat_loop, args=(database, settings, stop_event),
                                 name="webguard-worker-heartbeat", daemon=True)
    heartbeat.start()
    LOG.info("WebGuard tool worker started; external engines enabled=%s", settings.external_tools_enabled)
    try:
        while True:
            if not process_one(database, settings=settings):
                time.sleep(max(0.25, min(args.poll_interval, 30)))
    except KeyboardInterrupt:
        LOG.info("WebGuard tool worker stopped")
        stop_event.set()
        heartbeat.join(timeout=3)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
