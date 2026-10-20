"""FastAPI application factory, authenticated API, and strict target validation."""
import html
import json
import logging
import shutil
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from time import monotonic
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import errors
from app.auth import DUMMY_PASSWORD_HASH, create_access_token, get_current_user, require_operator, verify_password
from app.ai_service import AIProviderError, build_remote_prompt, local_recommendation, remote_completion, status_payload, system_prompt
from app.config import Settings, get_settings
from app.db import Database
from app.logging_setup import configure_logging
from app.models import (
    Audit, AuditEvent, AuthorizationStatus, Finding, FindingStatus, JobState, ScanJob, Severity, Target, User, WorkspaceScan, WorkerHeartbeat,
)
from app.schemas import (
    AIAssistOut, AIAssistRequest, AIStatusOut, AuditOut, DashboardSummary, EngineStatus, Envelope, ErrorEnvelope, FindingOut,
    HealthOut, LoginRequest, LoginResponse, Meta, RegressionOut, TargetAuthorizationRequest, TargetCreate, TargetOut, ToolCatalogItem,
    ToolRunCreate, ToolRunOut, UserOut, WorkspaceRunCreate, WorkspaceRunOut,
)
from app.scope import ScopeError, default_resolver, validate_target_url
from app.tooling.catalog import catalog as tool_catalog, get_tool

VERSION = "0.9.0"
ERR = {422: {"model": ErrorEnvelope}, 400: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope}}
def create_app(settings: Settings | None = None, resolver=default_resolver) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    database = Database(settings.database_url)
    production = settings.env.lower() == "production"
    app = FastAPI(
        title="WebGuard Security Lab API",
        version=VERSION,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
        responses=ERR,
    )
    app.state.settings, app.state.db, app.state.resolver = settings, database, resolver
    app.state.login_failures = defaultdict(deque)
    app.state.ai_requests = defaultdict(deque)
    app.state.tool_requests = defaultdict(deque)
    origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
            allow_credentials=False,
            max_age=600,
        )
    if production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[host.strip() for host in settings.allowed_hosts.split(",") if host.strip()],
        )
    errors.install(app, max_request_body_bytes=settings.max_request_body_bytes, production=production)

    def get_db(request: Request):
        yield from request.app.state.db.session()

    def paging(page: int = Query(1, ge=1), page_size: int | None = Query(None, ge=1)) -> tuple[int, int]:
        size = min(page_size or settings.default_page_size, settings.max_page_size)
        return page, size

    def paginate(db: Session, stmt, page: int, size: int):  # noqa: ANN001
        total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = db.scalars(stmt.offset((page - 1) * size).limit(size)).all()
        return rows, Meta(page=page, page_size=size, total=total)

    def target_ids_for(user: User):
        stmt = select(Target.id)
        if user.role != "admin":
            stmt = stmt.where(Target.owner_user_id == user.id)
        return stmt

    def can_access_target(target: Target, user: User) -> bool:
        return user.role == "admin" or target.owner_user_id == user.id

    def ensure_tool_rate_limit(request: Request, user: User) -> None:
        now = monotonic()
        for known_user_id, bucket in list(request.app.state.tool_requests.items()):
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if not bucket:
                request.app.state.tool_requests.pop(known_user_id, None)
        bucket = request.app.state.tool_requests[user.id]
        if len(bucket) >= settings.tool_rate_limit_requests:
            raise errors.AppError(429, "rate_limited", "Tool launch rate limit reached. Try again later.",
                                  headers={"Retry-After": "60"})
        bucket.append(now)

    def live_worker_capabilities(db: Session) -> list[dict] | None:
        # In a split API/worker deployment, only the worker knows which CLIs and
        # browser runtime are really installed. Accept a short-lived heartbeat only.
        heartbeat = db.get(WorkerHeartbeat, "primary")
        if not heartbeat or heartbeat.status != "online" or not heartbeat.capabilities:
            return None
        last_seen = heartbeat.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        if datetime.now(UTC) - last_seen > timedelta(seconds=45):
            return None
        return heartbeat.capabilities

    def effective_tool_catalog(db: Session) -> list[dict]:
        capabilities = live_worker_capabilities(db)
        if capabilities is not None:
            return capabilities
        fallback = tool_catalog(settings)
        if settings.env.lower() == "production":
            # Never advertise executable capabilities from the API image when the
            # separate worker is offline. A stale queue is operationally unsafe.
            for item in fallback:
                if item["id"] != "reports":
                    item["state"] = "unavailable"
                    item["detail"] = "Dedicated tool worker is offline or its heartbeat is stale. Start the worker and verify the database migration."
        return fallback

    def require_live_worker(db: Session) -> None:
        if settings.env.lower() == "production" and live_worker_capabilities(db) is None:
            raise errors.AppError(503, "tool_worker_offline", "The dedicated tool worker is offline or its heartbeat is stale.",
                                  headers={"Retry-After": "15"})

    def tool_catalog_item(engine: str, db: Session) -> dict | None:
        return next((item for item in effective_tool_catalog(db) if item["id"] == engine), None)

    def ensure_login_allowed(request: Request) -> tuple[str, deque[float]]:
        ip = request.client.host if request.client else "unknown"
        key = ip  # per-address cap prevents username rotation from bypassing the limiter
        now = monotonic()
        # Prune before acquiring the current bucket. Otherwise a newly created empty
        # bucket would be removed here and subsequent failures would not be counted.
        for known_key, known_attempts in list(request.app.state.login_failures.items()):
            while known_attempts and known_attempts[0] <= now - 900:
                known_attempts.popleft()
            if not known_attempts:
                request.app.state.login_failures.pop(known_key, None)
        attempts = request.app.state.login_failures[key]
        if len(request.app.state.login_failures) > 20_000:
            for oldest_key in list(request.app.state.login_failures):
                if oldest_key != key:
                    request.app.state.login_failures.pop(oldest_key, None)
                    break
        if len(attempts) >= 10:
            raise errors.AppError(
                429, "rate_limited", "Too many failed login attempts. Try again later.", headers={"Retry-After": "900"}
            )
        return key, attempts

    @app.get("/api/health", response_model=HealthOut, tags=["system"])
    def health(request: Request):
        db_ok = request.app.state.db.ping()
        return HealthOut(
            status="ok" if db_ok else "degraded", api="ok", database="ok" if db_ok else "unavailable",
            version=VERSION, time=datetime.now(UTC),
        )

    @app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
    def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
        key, attempts = ensure_login_allowed(request)
        user = db.scalar(select(User).where(User.email == body.email))
        password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
        valid = verify_password(body.password, password_hash)
        if user is None or not user.is_active or not valid:
            attempts.append(monotonic())
            raise errors.AppError(401, "invalid_credentials", "Email or password is incorrect.")
        request.app.state.login_failures.pop(key, None)
        token, ttl = create_access_token(user, settings)
        db.add(AuditEvent(entity_type="user", entity_id=user.id, event_type="auth.login",
                          payload={"method": "password"}, actor_user_id=user.id))
        db.commit()
        return LoginResponse(access_token=token, expires_in=ttl, user=UserOut.model_validate(user))

    @app.get("/api/auth/me", response_model=UserOut, tags=["auth"])
    def me(user: User = Depends(get_current_user)):
        return UserOut.model_validate(user)

    @app.get("/api/dashboard/summary", response_model=Envelope[DashboardSummary], tags=["dashboard"])
    def dashboard(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        target_ids = target_ids_for(user)
        audit_ids = select(Audit.id).where(Audit.target_id.in_(target_ids))
        audits = dict(db.execute(
            select(Audit.state, func.count()).where(Audit.target_id.in_(target_ids)).group_by(Audit.state)
        ).all())
        workspace_ids = select(WorkspaceScan.id) if user.role == "admin" else select(WorkspaceScan.id).where(WorkspaceScan.owner_user_id == user.id)
        finding_scope = or_(Finding.audit_id.in_(audit_ids), Finding.workspace_scan_id.in_(workspace_ids))
        sev = dict(db.execute(
            select(Finding.severity, func.count()).where(finding_scope).group_by(Finding.severity)
        ).all())
        recent = db.scalars(
            select(Audit).where(Audit.target_id.in_(target_ids)).order_by(Audit.created_at.desc()).limit(5)
        ).all()
        return Envelope(data=DashboardSummary(
            targets=db.scalar(select(func.count(Target.id)).where(Target.id.in_(target_ids))) or 0,
            audits_by_state={s.value: audits.get(s, 0) for s in JobState},
            findings_by_severity={s.value: sev.get(s, 0) for s in Severity},
            open_findings=db.scalar(
                select(func.count(Finding.id)).where(Finding.status == FindingStatus.open, finding_scope)
            ) or 0,
            recent_audits=[AuditOut.model_validate(a) for a in recent],
        ))

    @app.get("/api/targets", response_model=Envelope[list[TargetOut]], tags=["targets"])
    def list_targets(db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging),
                     user: User = Depends(get_current_user)):
        stmt = select(Target).order_by(Target.created_at.desc())
        if user.role != "admin":
            stmt = stmt.where(Target.owner_user_id == user.id)
        rows, meta = paginate(db, stmt, *pg)
        return Envelope(data=[TargetOut.model_validate(r) for r in rows], meta=meta)

    @app.post("/api/targets", response_model=Envelope[TargetOut], status_code=201, tags=["targets"])
    def create_target(body: TargetCreate, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_operator)):
        try:
            url, host, is_lab = validate_target_url(
                body.base_url, allow_lab=settings.allow_lab_targets, resolver=request.app.state.resolver
            )
        except ScopeError as exc:
            raise errors.AppError(400, "scope_violation", str(exc)) from exc
        target = Target(
            name=body.name, base_url=url, hostname=host, scope_rules=body.scope_rules,
            authorization_note=body.authorization_note, is_lab_target=is_lab,
            owner_user_id=user.id,  # the owner is derived from the authenticated principal, never the request body
        )
        db.add(target)
        try:
            db.flush()
            db.add(AuditEvent(entity_type="target", entity_id=target.id, event_type="target.created",
                              payload={"hostname": host, "is_lab_target": is_lab}, actor_user_id=user.id))
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise errors.AppError(409, "conflict", "a target with this URL already exists") from exc
        db.refresh(target)
        return Envelope(data=TargetOut.model_validate(target))

    @app.post("/api/targets/{target_id}/authorize", response_model=Envelope[TargetOut], tags=["targets"])
    def authorize_target(target_id: str, body: TargetAuthorizationRequest, db: Session = Depends(get_db),
                         user: User = Depends(require_operator)):
        target = db.get(Target, target_id)
        if target is None or not can_access_target(target, user):
            raise errors.AppError(404, "not_found", "Target not found in your authorized workspace.")
        if not body.confirmed:
            raise errors.AppError(422, "authorization_required", "Explicit authorization confirmation is required.")
        target.authorization_status = AuthorizationStatus.authorized
        target.authorization_note = body.note
        db.add(AuditEvent(entity_type="target", entity_id=target.id, event_type="target.authorization_granted",
                          payload={"hostname": target.hostname, "note_recorded": True}, actor_user_id=user.id))
        db.commit()
        db.refresh(target)
        return Envelope(data=TargetOut.model_validate(target))

    @app.post("/api/targets/{target_id}/revoke", response_model=Envelope[TargetOut], tags=["targets"])
    def revoke_target(target_id: str, db: Session = Depends(get_db), user: User = Depends(require_operator)):
        target = db.get(Target, target_id)
        if target is None or not can_access_target(target, user):
            raise errors.AppError(404, "not_found", "Target not found in your authorized workspace.")
        target.authorization_status = AuthorizationStatus.revoked
        audits = db.scalars(select(Audit).where(Audit.target_id == target.id)).all()
        audit_ids = [audit.id for audit in audits]
        active_jobs = db.scalars(select(ScanJob).where(ScanJob.audit_id.in_(audit_ids),
                                                        ScanJob.state.in_([JobState.queued, JobState.running]))).all() if audit_ids else []
        for job in active_jobs:
            job.state = JobState.cancelled
            job.finished_at = datetime.now(UTC)
        for audit in audits:
            if audit.state in {JobState.queued, JobState.running}:
                audit.state = JobState.cancelled
                audit.finished_at = datetime.now(UTC)
        db.add(AuditEvent(entity_type="target", entity_id=target.id, event_type="target.authorization_revoked",
                          payload={"hostname": target.hostname, "cancelled_jobs": len(active_jobs)}, actor_user_id=user.id))
        db.commit()
        db.refresh(target)
        return Envelope(data=TargetOut.model_validate(target))

    @app.get("/api/audits", response_model=Envelope[list[AuditOut]], tags=["audits"])
    def list_audits(
        db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging),
        target_id: str | None = None, state: JobState | None = None,
        user: User = Depends(get_current_user),
    ):
        owned_target_ids = target_ids_for(user)
        stmt = select(Audit).where(Audit.target_id.in_(owned_target_ids)).order_by(Audit.created_at.desc())
        if target_id:
            stmt = stmt.where(Audit.target_id == target_id)
        if state:
            stmt = stmt.where(Audit.state == state)
        rows, meta = paginate(db, stmt, *pg)
        return Envelope(data=[AuditOut.model_validate(r) for r in rows], meta=meta)

    @app.get("/api/findings", response_model=Envelope[list[FindingOut]], tags=["findings"])
    def list_findings(
        db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging),
        audit_id: str | None = None, severity: Severity | None = None, status: FindingStatus | None = None,
        user: User = Depends(get_current_user),
    ):
        owned_audit_ids = select(Audit.id).where(Audit.target_id.in_(target_ids_for(user)))
        owned_workspace_ids = select(WorkspaceScan.id) if user.role == "admin" else select(WorkspaceScan.id).where(WorkspaceScan.owner_user_id == user.id)
        stmt = select(Finding).where(or_(Finding.audit_id.in_(owned_audit_ids), Finding.workspace_scan_id.in_(owned_workspace_ids))).order_by(Finding.created_at.desc())
        if audit_id:
            stmt = stmt.where(Finding.audit_id == audit_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        rows, meta = paginate(db, stmt, *pg)
        return Envelope(data=[FindingOut.model_validate(r) for r in rows], meta=meta)


    @app.get("/api/tools/catalog", response_model=Envelope[list[ToolCatalogItem]], tags=["tools"])
    def tools_catalog(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        """Return capabilities reported by the live worker, with a safe fallback if it is offline."""
        return Envelope(data=[ToolCatalogItem.model_validate(item) for item in effective_tool_catalog(db)])

    def _target_run_out(job: ScanJob, db: Session) -> ToolRunOut:
        audit = db.get(Audit, job.audit_id)
        target = db.get(Target, audit.target_id) if audit else None
        return ToolRunOut(
            id=job.id, audit_id=job.audit_id, target_id=target.id if target else "", target_name=target.name if target else "Deleted target",
            engine=job.engine, state=job.state, progress=job.progress, profile=str((job.config or {}).get("profile", "quick")),
            results=job.results or {}, error_message=job.error_message, started_at=job.started_at,
            finished_at=job.finished_at, created_at=job.created_at,
        )

    @app.post("/api/tools/runs", response_model=Envelope[ToolRunOut], status_code=202, tags=["tools"])
    def create_tool_run(body: ToolRunCreate, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(require_operator)):
        tool = get_tool(body.engine)
        catalog_item = tool_catalog_item(body.engine, db)
        if not tool or not tool.requires_target:
            raise errors.AppError(400, "invalid_tool", "Choose a tool that tests a registered target.")
        if not settings.tool_execution_enabled:
            raise errors.AppError(503, "tool_execution_disabled", "Tool execution is disabled by server configuration.")
        require_live_worker(db)
        if not catalog_item or catalog_item["state"] != "available":
            detail = catalog_item["detail"] if catalog_item else "Tool is not registered."
            raise errors.AppError(503, "tool_unavailable", detail)
        target = db.get(Target, body.target_id)
        if target is None or not can_access_target(target, user):
            raise errors.AppError(404, "not_found", "Target not found in your authorized workspace.")
        if target.authorization_status != AuthorizationStatus.authorized:
            raise errors.AppError(409, "authorization_not_active", "Authorize the target explicitly before running tests.")
        if target.is_lab_target and not settings.allow_lab_targets:
            raise errors.AppError(409, "lab_disabled", "This target is local-lab scoped but isolated-lab mode is disabled on the server.")
        try:
            normalized, hostname, is_lab = validate_target_url(
                target.base_url, allow_lab=settings.allow_lab_targets, resolver=request.app.state.resolver
            )
        except ScopeError as exc:
            target.authorization_status = AuthorizationStatus.revoked
            db.add(AuditEvent(entity_type="target", entity_id=target.id, event_type="target.scope_revalidation_denied",
                              payload={"reason": str(exc)[:200]}, actor_user_id=user.id))
            db.commit()
            raise errors.AppError(409, "scope_revalidation_failed", "The saved target no longer passes scope validation; authorization was revoked.") from exc
        if hostname != target.hostname:
            raise errors.AppError(409, "scope_changed", "Target hostname changed; register the target again.")
        ensure_tool_rate_limit(request, user)
        owned_ids = target_ids_for(user)
        active_jobs = db.scalar(
            select(func.count(ScanJob.id)).join(Audit, ScanJob.audit_id == Audit.id)
            .where(Audit.target_id.in_(owned_ids), ScanJob.state.in_([JobState.queued, JobState.running]))
        ) or 0
        if active_jobs >= 10:
            raise errors.AppError(429, "queue_limit", "Too many queued or running jobs in this workspace.", headers={"Retry-After": "60"})
        audit = Audit(target_id=target.id, name=f"{tool.name} · {body.profile}", state=JobState.queued)
        db.add(audit)
        db.flush()
        job = ScanJob(audit_id=audit.id, engine=body.engine, state=JobState.queued, progress=0,
                      config={"profile": body.profile, "requested_by": user.id, "scope_hostname": hostname,
                              "target_url": normalized, "authorization_confirmed": body.authorization_confirmed}, results={})
        db.add(job)
        db.flush()
        db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.queued",
                          payload={"engine": body.engine, "profile": body.profile, "target_hostname": hostname}, actor_user_id=user.id))
        db.commit()
        db.refresh(job)
        return Envelope(data=_target_run_out(job, db))

    @app.get("/api/tools/runs", response_model=Envelope[list[ToolRunOut]], tags=["tools"])
    def list_tool_runs(db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging),
                       user: User = Depends(get_current_user)):
        stmt = select(ScanJob).join(Audit, ScanJob.audit_id == Audit.id).join(Target, Audit.target_id == Target.id)
        if user.role != "admin":
            stmt = stmt.where(Target.owner_user_id == user.id)
        stmt = stmt.order_by(ScanJob.created_at.desc())
        rows, meta = paginate(db, stmt, *pg)
        return Envelope(data=[_target_run_out(row, db) for row in rows], meta=meta)

    @app.get("/api/tools/runs/{run_id}", response_model=Envelope[ToolRunOut], tags=["tools"])
    def get_tool_run(run_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        job = db.get(ScanJob, run_id)
        if not job:
            raise errors.AppError(404, "not_found", "Tool run was not found.")
        audit = db.get(Audit, job.audit_id)
        target = db.get(Target, audit.target_id) if audit else None
        if not target or not can_access_target(target, user):
            raise errors.AppError(404, "not_found", "Tool run was not found in your workspace.")
        return Envelope(data=_target_run_out(job, db))

    @app.post("/api/tools/runs/{run_id}/cancel", response_model=Envelope[ToolRunOut], tags=["tools"])
    def cancel_tool_run(run_id: str, db: Session = Depends(get_db), user: User = Depends(require_operator)):
        job = db.get(ScanJob, run_id)
        if not job:
            raise errors.AppError(404, "not_found", "Tool run was not found.")
        audit = db.get(Audit, job.audit_id)
        target = db.get(Target, audit.target_id) if audit else None
        if not target or not can_access_target(target, user):
            raise errors.AppError(404, "not_found", "Tool run was not found in your workspace.")
        if job.state not in {JobState.queued, JobState.running}:
            raise errors.AppError(409, "invalid_state", "Only queued or running tool jobs can be cancelled.")
        job.state = JobState.cancelled
        job.finished_at = datetime.now(UTC)
        if audit:
            audit.state = JobState.cancelled
            audit.finished_at = datetime.now(UTC)
        db.add(AuditEvent(entity_type="scan_job", entity_id=job.id, event_type="tool.cancelled",
                          payload={"engine": job.engine}, actor_user_id=user.id))
        db.commit()
        db.refresh(job)
        return Envelope(data=_target_run_out(job, db))

    @app.post("/api/tools/workspace-runs", response_model=Envelope[WorkspaceRunOut], status_code=202, tags=["tools"])
    def create_workspace_run(body: WorkspaceRunCreate, request: Request, db: Session = Depends(get_db),
                             user: User = Depends(require_operator)):
        if user.role != "admin":
            raise errors.AppError(403, "forbidden", "Only administrators can scan the server-configured source workspace.")
        if not settings.tool_execution_enabled or not settings.external_tools_enabled or not settings.egress_policy_confirmed:
            raise errors.AppError(503, "tool_execution_disabled", "Workspace scanning requires external engines and egress controls explicitly enabled.")
        require_live_worker(db)
        catalog_item = tool_catalog_item(body.engine, db)
        if not catalog_item or catalog_item["state"] != "available":
            detail = catalog_item["detail"] if catalog_item else "Tool is not registered."
            raise errors.AppError(503, "tool_unavailable", detail)
        if not settings.workspace_scan_root:
            raise errors.AppError(503, "workspace_not_configured", "Set WEBGUARD_WORKSPACE_SCAN_ROOT on the server; client paths are not accepted.")
        # This API may run in a different, intentionally unprivileged container than
        # the worker and therefore cannot stat the worker-only read-only mount. Require
        # an absolute admin-configured path here; the worker resolves and validates the
        # actual directory before every source scan.
        from pathlib import Path
        if not Path(settings.workspace_scan_root).expanduser().is_absolute():
            raise errors.AppError(503, "workspace_not_configured", "WEBGUARD_WORKSPACE_SCAN_ROOT must be an absolute path inside the worker container.")
        ensure_tool_rate_limit(request, user)
        active = db.scalar(select(func.count(WorkspaceScan.id)).where(WorkspaceScan.owner_user_id == user.id,
                          WorkspaceScan.state.in_([JobState.queued, JobState.running]))) or 0
        if active >= 3:
            raise errors.AppError(429, "queue_limit", "Too many workspace scans are queued or running.", headers={"Retry-After": "60"})
        scan = WorkspaceScan(owner_user_id=user.id, engine=body.engine, profile=body.profile,
                             state=JobState.queued, progress=0, results={})
        db.add(scan)
        db.flush()
        db.add(AuditEvent(entity_type="workspace_scan", entity_id=scan.id, event_type="workspace_scan.queued",
                          payload={"engine": body.engine, "profile": body.profile, "workspace_configured": True}, actor_user_id=user.id))
        db.commit()
        db.refresh(scan)
        return Envelope(data=WorkspaceRunOut.model_validate(scan))

    @app.get("/api/tools/workspace-runs", response_model=Envelope[list[WorkspaceRunOut]], tags=["tools"])
    def list_workspace_runs(db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging),
                            user: User = Depends(get_current_user)):
        stmt = select(WorkspaceScan).order_by(WorkspaceScan.created_at.desc())
        if user.role != "admin":
            stmt = stmt.where(WorkspaceScan.owner_user_id == user.id)
        rows, meta = paginate(db, stmt, *pg)
        return Envelope(data=[WorkspaceRunOut.model_validate(row) for row in rows], meta=meta)

    @app.post("/api/tools/workspace-runs/{run_id}/cancel", response_model=Envelope[WorkspaceRunOut], tags=["tools"])
    def cancel_workspace_run(run_id: str, db: Session = Depends(get_db), user: User = Depends(require_operator)):
        scan = db.get(WorkspaceScan, run_id)
        if scan is None or (user.role != "admin" and scan.owner_user_id != user.id):
            raise errors.AppError(404, "not_found", "Workspace run was not found.")
        if scan.state not in {JobState.queued, JobState.running}:
            raise errors.AppError(409, "invalid_state", "Only queued or running workspace jobs can be cancelled.")
        scan.state = JobState.cancelled
        scan.finished_at = datetime.now(UTC)
        db.add(AuditEvent(entity_type="workspace_scan", entity_id=scan.id, event_type="workspace_scan.cancelled",
                          payload={"engine": scan.engine}, actor_user_id=user.id))
        db.commit()
        db.refresh(scan)
        return Envelope(data=WorkspaceRunOut.model_validate(scan))

    @app.get("/api/audits/{audit_id}/regression", response_model=Envelope[RegressionOut], tags=["reports"])
    def compare_audits(audit_id: str, baseline_audit_id: str = Query(min_length=36, max_length=36),
                       db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        current = db.get(Audit, audit_id)
        baseline = db.get(Audit, baseline_audit_id)
        current_target = db.get(Target, current.target_id) if current else None
        baseline_target = db.get(Target, baseline.target_id) if baseline else None
        if (not current or not baseline or not current_target or not baseline_target
                or not can_access_target(current_target, user) or not can_access_target(baseline_target, user)):
            raise errors.AppError(404, "not_found", "One or both audits were not found in your workspace.")
        if current.target_id != baseline.target_id:
            raise errors.AppError(400, "invalid_comparison", "Baseline and current audits must belong to the same target.")
        def collect(audit_id: str) -> dict[tuple, dict]:
            items = db.scalars(select(Finding).where(Finding.audit_id == audit_id)).all()
            out = {}
            for finding in items:
                key = (finding.title.casefold(), finding.severity.value, (urlsplit(finding.url).path if finding.url else ""))
                out[key] = {"title": finding.title, "severity": finding.severity.value, "url": finding.url,
                            "status": finding.status.value}
            return out
        old = collect(baseline.id); new = collect(current.id)
        added_keys, removed_keys = new.keys() - old.keys(), old.keys() - new.keys()
        return Envelope(data=RegressionOut(
            baseline_audit_id=baseline.id, current_audit_id=current.id,
            new_findings=[new[key] for key in sorted(added_keys)],
            resolved_findings=[old[key] for key in sorted(removed_keys)], unchanged_findings=len(new.keys() & old.keys()),
        ))

    @app.get("/api/reports/export", tags=["reports"])
    def export_report(audit_id: str | None = None, workspace_scan_id: str | None = None,
                      format: str = Query("json", pattern=r"^(json|html|pdf|sarif|cyclonedx)$"),
                      db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        if bool(audit_id) == bool(workspace_scan_id):
            raise errors.AppError(400, "invalid_report_source", "Set exactly one of audit_id or workspace_scan_id.")
        if audit_id:
            audit = db.get(Audit, audit_id)
            target = db.get(Target, audit.target_id) if audit else None
            if not audit or not target or not can_access_target(target, user):
                raise errors.AppError(404, "not_found", "Audit was not found in your workspace.")
            findings = db.scalars(select(Finding).where(Finding.audit_id == audit.id).order_by(Finding.created_at.desc())).all()
            doc = {"report_type": "webguard_audit", "audit_id": audit.id, "audit_name": audit.name,
                   "target": {"name": target.name, "hostname": target.hostname}, "state": audit.state.value,
                   "created_at": audit.created_at.isoformat(), "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings]}
            label = audit.id[:8]
        else:
            scan = db.get(WorkspaceScan, workspace_scan_id)
            if not scan or (user.role != "admin" and scan.owner_user_id != user.id):
                raise errors.AppError(404, "not_found", "Workspace scan was not found in your workspace.")
            findings = db.scalars(select(Finding).where(Finding.workspace_scan_id == scan.id).order_by(Finding.created_at.desc())).all()
            report_results = dict(scan.results or {})
            if "sbom_document" in report_results:
                report_results.pop("sbom_document", None)
                report_results["sbom_document_available"] = True
            doc = {"report_type": "webguard_workspace_scan", "scan_id": scan.id, "engine": scan.engine,
                   "state": scan.state.value, "created_at": scan.created_at.isoformat(),
                   "results": report_results, "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings]}
            label = scan.id[:8]
        if format == "cyclonedx":
            if not workspace_scan_id:
                raise errors.AppError(400, "invalid_report_format", "CycloneDX export is only available for completed SBOM workspace scans.")
            sbom_scan = db.get(WorkspaceScan, workspace_scan_id)
            if not sbom_scan or (user.role != "admin" and sbom_scan.owner_user_id != user.id):
                raise errors.AppError(404, "not_found", "Workspace scan was not found in your workspace.")
            if sbom_scan.engine != "sbom" or sbom_scan.state != JobState.completed:
                raise errors.AppError(400, "invalid_report_format", "CycloneDX export is only available for completed SBOM workspace scans.")
            sbom_document = (sbom_scan.results or {}).get("sbom_document")
            if not isinstance(sbom_document, dict) or sbom_document.get("bomFormat") != "CycloneDX":
                raise errors.AppError(409, "sbom_not_available", "The completed scan does not contain a valid CycloneDX document.")
            payload = json.dumps(sbom_document, ensure_ascii=False, indent=2)
            media = "application/vnd.cyclonedx+json"
            filename = f"webguard-sbom-{label}.cdx.json"
        elif format == "pdf":
            from app.tooling.reports import build_pdf_report
            pdf = build_pdf_report(doc)
            return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="webguard-report-{label}.pdf"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        elif format == "json":
            payload = json.dumps(doc, ensure_ascii=False, indent=2)
            media = "application/json"
            filename = f"webguard-report-{label}.json"
        elif format == "html":
            payload = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>WebGuard Report</title><style>body{font:16px system-ui;max-width:1000px;margin:3rem auto;padding:0 1rem;background:#101923;color:#e8eef5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#192633;padding:1rem;border-radius:.5rem}</style></head><body><h1>WebGuard Security Report</h1><p>Generated " + html.escape(datetime.now(UTC).isoformat()) + "</p><pre>" + html.escape(json.dumps(doc, ensure_ascii=False, indent=2)) + "</pre></body></html>"
            media = "text/html; charset=utf-8"
            filename = f"webguard-report-{label}.html"
        else:
            results = []
            for finding in doc["findings"]:
                evidence = finding.get("evidence") or {}
                rule_id = evidence.get("cve") or evidence.get("cweid") or evidence.get("rule_id") or finding["id"]
                results.append({"ruleId": str(rule_id), "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(finding["severity"], "note"),
                                "message": {"text": finding["title"] + (": " + finding.get("description", "") if finding.get("description") else "")},
                                "locations": ([{"physicalLocation": {"artifactLocation": {"uri": finding["url"]}}}] if finding.get("url") else []),
                                "properties": {"severity": finding["severity"], "status": finding["status"]}})
            sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                     "runs": [{"tool": {"driver": {"name": "WebGuard Security Lab", "informationUri": "https://owasp.org/"}}, "results": results}]}
            payload = json.dumps(sarif, ensure_ascii=False, indent=2)
            media = "application/sarif+json"
            filename = f"webguard-report-{label}.sarif.json"
        return Response(content=payload, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.get("/api/history", response_model=Envelope[list[dict]], tags=["history"])
    def history(db: Session = Depends(get_db), pg: tuple[int, int] = Depends(paging), user: User = Depends(get_current_user)):
        stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())
        if user.role != "admin":
            own_target_ids = target_ids_for(user)
            own_audit_ids = select(Audit.id).where(Audit.target_id.in_(own_target_ids))
            own_scan_ids = select(ScanJob.id).where(ScanJob.audit_id.in_(own_audit_ids))
            own_workspace_scan_ids = select(WorkspaceScan.id).where(WorkspaceScan.owner_user_id == user.id)
            stmt = stmt.where((AuditEvent.actor_user_id == user.id) |
                              ((AuditEvent.entity_type == "target") & AuditEvent.entity_id.in_(own_target_ids)) |
                              ((AuditEvent.entity_type == "audit") & AuditEvent.entity_id.in_(own_audit_ids)) |
                              ((AuditEvent.entity_type == "scan_job") & AuditEvent.entity_id.in_(own_scan_ids)) |
                              ((AuditEvent.entity_type == "workspace_scan") & AuditEvent.entity_id.in_(own_workspace_scan_ids)))
        rows, meta = paginate(db, stmt, *pg)
        data = [{"id": row.id, "entity_type": row.entity_type, "entity_id": row.entity_id,
                 "event_type": row.event_type, "payload": row.payload or {}, "created_at": row.created_at.isoformat()} for row in rows]
        return Envelope(data=data, meta=meta)

    @app.get("/api/ai/status", response_model=Envelope[AIStatusOut], tags=["ai"])
    def ai_status(user: User = Depends(get_current_user)):
        """Return safe capability status; never expose provider credentials."""
        return Envelope(data=AIStatusOut.model_validate(status_payload(settings)))

    @app.post("/api/ai/assist", response_model=Envelope[AIAssistOut], tags=["ai"])
    async def ai_assist(body: AIAssistRequest, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
        """Analyze authorized, minimized records. This endpoint cannot execute security jobs."""
        # Bound model spend / CPU by authenticated principal. Production deployments should
        # also enforce a shared limit at the edge because this in-memory guard is per process.
        now = monotonic()
        for known_user_id, known_requests in list(request.app.state.ai_requests.items()):
            while known_requests and known_requests[0] <= now - 60:
                known_requests.popleft()
            if not known_requests:
                request.app.state.ai_requests.pop(known_user_id, None)
        recent_ai_requests = request.app.state.ai_requests[user.id]
        if len(request.app.state.ai_requests) > 20_000:
            for known_user_id in list(request.app.state.ai_requests):
                if known_user_id != user.id:
                    request.app.state.ai_requests.pop(known_user_id, None)
                    break
        if len(recent_ai_requests) >= settings.ai_rate_limit_requests:
            raise errors.AppError(429, "rate_limited", "AI request limit reached. Try again later.",
                                  headers={"Retry-After": "60"})
        recent_ai_requests.append(now)

        target_ids = target_ids_for(user)
        context: dict = {}
        if body.task == "process_review":
            audit_stmt = select(Audit.state, func.count()).where(
                Audit.target_id.in_(target_ids)
            ).group_by(Audit.state)
            audits = {state.value: count for state, count in db.execute(audit_stmt).all()}
            audit_ids = select(Audit.id).where(Audit.target_id.in_(target_ids))
            severity_rows = db.execute(
                select(Finding.severity, func.count()).where(Finding.audit_id.in_(audit_ids)).group_by(Finding.severity)
            ).all()
            severities = {severity.value: count for severity, count in severity_rows}
            target_count = db.scalar(select(func.count(Target.id)).where(Target.id.in_(target_ids))) or 0
            context = {
                "target_count": target_count,
                "audits_by_state": audits,
                "findings_by_severity": severities,
                "module_readiness": {
                    "scanner": "not_implemented", "browser_bots": "not_implemented",
                    "load_tests": "not_implemented", "reports": "not_implemented",
                },
            }
        elif body.task == "audit_summary":
            stmt = select(Audit).where(Audit.target_id.in_(target_ids)).order_by(Audit.created_at.desc())
            if body.audit_id:
                stmt = stmt.where(Audit.id == body.audit_id)
            audit = db.scalars(stmt.limit(1)).first()
            if body.audit_id and audit is None:
                raise errors.AppError(404, "not_found", "Audit not found in your authorized workspace.")
            context = {"audit": ({"name": audit.name, "state": audit.state.value} if audit else None)}
            if audit:
                findings = db.scalars(
                    select(Finding).where(Finding.audit_id == audit.id).order_by(Finding.created_at.desc()).limit(50)
                ).all()
                context["findings"] = [
                    {"title": item.title[:300], "severity": item.severity.value, "status": item.status.value,
                     "description": (item.description or "")[:1000], "created_at": item.created_at.isoformat()}
                    for item in findings
                ]
            else:
                context["findings"] = []
        elif body.task in {"finding_triage", "remediation_plan"}:
            owned_audit_ids = select(Audit.id).where(Audit.target_id.in_(target_ids))
            findings = db.scalars(
                select(Finding).where(
                    Finding.audit_id.in_(owned_audit_ids), Finding.status == FindingStatus.open
                ).order_by(Finding.created_at.desc()).limit(50)
            ).all()
            # Do not send evidence blobs or URL query parameters to a model provider.
            context = {"findings": [
                {"title": item.title[:300], "severity": item.severity.value,
                 "status": item.status.value, "description": (item.description or "")[:1000],
                 "created_at": item.created_at.isoformat()}
                for item in findings
            ]}
        else:
            context = {"product": "WebGuard Security Lab", "scope": "Authorized security operations only"}

        mode = "local_rules"
        provider = "Local rule-based assistant"
        model = None
        answer = ""
        remote_configured = bool(settings.ai_api_key and settings.ai_model.strip())
        if remote_configured:
            try:
                prompt = build_remote_prompt(body.task, body.question, context)
                answer = await remote_completion(settings, system_prompt(), prompt)
                mode, provider, model = "remote_model", settings.ai_provider_name, settings.ai_model
            except AIProviderError as exc:
                # Provider outages do not break core WebGuard operations; provide a local result instead.
                logging.getLogger(__name__).warning("AI provider unavailable; falling back to local rules")
                answer = local_recommendation(body.task, body.question, context)
        else:
            answer = local_recommendation(body.task, body.question, context)

        db.add(AuditEvent(
            entity_type="ai", entity_id=user.id, event_type="ai.assist",
            payload={"task": body.task, "mode": mode, "context_items": len(context.get("findings", []))},
            actor_user_id=user.id,
        ))
        db.commit()
        return Envelope(data=AIAssistOut(
            task=body.task, answer=answer, mode=mode, provider=provider, model=model,
            generated_at=datetime.now(UTC),
            disclaimer="AI output is advisory. Verify recommendations manually; this endpoint never runs scans or changes scope.",
        ))

    @app.get("/api/engines/status", response_model=Envelope[list[EngineStatus]], tags=["engines"])
    def engines(user: User = Depends(get_current_user)):
        kind_map = {"web_security": "scanner", "api_testing": "scanner", "browser": "browser",
                    "performance": "load_test", "code_security": "scanner", "configuration": "scanner"}
        return Envelope(data=[EngineStatus(name=item["id"], kind="report" if item["id"] == "reports" else kind_map[item["category"]],
                                             state=item["state"], detail=item["detail"])
                              for item in tool_catalog(settings)])

    return app
