"""Uniform API error envelopes, request IDs, payload bounds and security headers."""
import logging
import re
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("webguard.errors")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AppError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: list[dict] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.status, self.code, self.message, self.details = status, code, message, details
        self.headers = headers or {}


def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


def _body(code: str, message: str, request: Request, details: list[dict] | None = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details, "request_id": _rid(request)}}


def install(app: FastAPI, *, max_request_body_bytes: int = 1_048_576, production: bool = False) -> None:
    @app.middleware("http")
    async def request_hardening(request: Request, call_next):  # noqa: ANN001
        supplied_id = request.headers.get("x-request-id", "")
        request.state.request_id = supplied_id if _REQUEST_ID.fullmatch(supplied_id) else str(uuid.uuid4())
        raw_length = request.headers.get("content-length")
        if raw_length:
            try:
                content_length = int(raw_length)
            except ValueError:
                content_length = max_request_body_bytes + 1
            if content_length < 0 or content_length > max_request_body_bytes:
                response = JSONResponse(
                    _body("payload_too_large", "Request body exceeds the configured limit", request),
                    status_code=413,
                )
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["x-request-id"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        if production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError):
        return JSONResponse(
            _body(exc.code, exc.message, request, exc.details), status_code=exc.status, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def validation(request: Request, exc: RequestValidationError):
        details = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        return JSONResponse(_body("validation_error", "Request validation failed", request, details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed", 413: "payload_too_large", 429: "rate_limited"}.get(exc.status_code, "http_error")
        message = str(exc.detail) if exc.status_code < 500 else "Request failed"
        return JSONResponse(_body(code, message, request), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.error("unhandled error", exc_info=exc, extra={"request_id": _rid(request), "path": request.url.path})
        return JSONResponse(_body("internal_error", "An unexpected error occurred", request), status_code=500)
