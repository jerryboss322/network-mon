"""ASGI middleware and unified exception handlers for the NetPulse FastAPI application.

Provides:
- :class:`RequestContextMiddleware`: Pure-ASGI middleware that assigns or propagates
  ``X-Request-ID``, binds async-safe structured logging context, measures request
  duration (``X-Process-Time-Ms``), and emits structured access logs.
- :class:`SecurityHeadersMiddleware`: Pure-ASGI middleware injecting modern HTTP
  security headers (XSS, frame, MIME-sniffing, referrer, permissions, and HSTS).
- :func:`register_exception_handlers`: Uniform JSON error envelope mapping for
  :class:`NetPulseError`, FastAPI :class:`RequestValidationError`, HTTP exceptions,
  SQLAlchemy :class:`IntegrityError` / :class:`OperationalError`, and unhandled errors.
- :func:`register_middleware`: One-call wiring for CORS, security headers, request
  correlation, and exception handling.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings, get_settings
from app.core.exceptions import NetPulseError, RateLimitError
from app.core.logging import (
    generate_request_id,
    get_logger,
    get_org_id,
    get_request_id,
    get_user_id,
    request_context,
)
from app.schemas.common import utcnow

logger = get_logger("netpulse.http")
access_logger = get_logger("netpulse.access")

# Paths where verbose access logs are downgraded to DEBUG to avoid log noise
_QUIET_ACCESS_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/ready",
        "/api/v1/health",
        "/api/v1/ready",
        "/favicon.ico",
    }
)

# Paths that serve interactive OpenAPI docs and require relaxed CSP
_DOCS_PATH_PREFIXES: tuple[str, ...] = ("/docs", "/redoc", "/openapi.json")

# Sensitive auth endpoints that should never be cached by browsers or proxies
_SENSITIVE_NO_STORE_PREFIXES: tuple[str, ...] = (
    "/api/v1/auth",
    "/api/v1/api-keys",
    "/api/v1/users",
    "/api/v1/credentials",
)


def _get_header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    target = name.lower()
    for k, v in headers:
        if k.lower() == target:
            try:
                return v.decode("latin-1").strip()
            except UnicodeDecodeError:
                return None
    return None


def _set_header(headers: list[tuple[bytes, bytes]], name: bytes, value: str) -> None:
    target = name.lower()
    encoded_val = value.encode("latin-1")
    for idx, (k, _) in enumerate(headers):
        if k.lower() == target:
            headers[idx] = (k, encoded_val)
            return
    headers.append((name, encoded_val))


def _has_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bool:
    target = name.lower()
    return any(k.lower() == target for k, _ in headers)


def _extract_scope_client_ip(scope: Scope) -> str | None:
    raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
    xff = _get_header(raw_headers, b"x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    real_ip = _get_header(raw_headers, b"x-real-ip")
    if real_ip:
        return real_ip
    client = scope.get("client")
    if client and len(client) >= 1:
        return str(client[0])
    return None


def _sanitize_request_id(candidate: str | None) -> str:
    if not candidate:
        return generate_request_id()
    cleaned = candidate.strip()
    # Accept safe correlation IDs up to 128 printable ASCII chars without whitespace
    if 4 <= len(cleaned) <= 128 and all(33 <= ord(ch) <= 126 for ch in cleaned):
        return cleaned
    return generate_request_id()


# ---------------------------------------------------------------------------
# RequestContextMiddleware
# ---------------------------------------------------------------------------


class RequestContextMiddleware:
    """Pure-ASGI middleware for request correlation, timing, and structured access logs.

    - Assigns or propagates ``X-Request-ID`` on every request and response.
    - Stores ``request_id`` in ``scope["state"]["request_id"]`` (accessible via
      ``request.state.request_id``) and binds it to async-safe ``contextvars``.
    - Measures end-to-end execution latency and sets ``X-Process-Time-Ms``.
    - Emits a structured access log entry with HTTP method, path, status code,
      latency, client IP, tenant ``org_id``, and ``user_id``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        incoming_req_id = _get_header(raw_headers, b"x-request-id") or _get_header(
            raw_headers, b"x-correlation-id"
        )
        req_id = _sanitize_request_id(incoming_req_id)

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", "/"))
        query_bytes: bytes = scope.get("query_string") or b""
        query_str = query_bytes.decode("latin-1", errors="replace") if query_bytes else ""
        client_ip = _extract_scope_client_ip(scope)
        user_agent = _get_header(raw_headers, b"user-agent") or ""

        state = scope.setdefault("state", {})
        state["request_id"] = req_id
        state["client_ip"] = client_ip

        start_ns = time.perf_counter_ns()
        status_code = 500
        response_bytes = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_bytes
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)
                resp_headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                _set_header(resp_headers, b"x-request-id", req_id)
                _set_header(resp_headers, b"x-process-time-ms", f"{elapsed_ms:.2f}")
                message["headers"] = resp_headers
            elif message["type"] == "http.response.body":
                body = message.get("body") or b""
                response_bytes += len(body)
            await send(message)

        with request_context(
            request_id=req_id,
            http_method=method,
            http_path=path,
            client_ip=client_ip,
        ):
            try:
                await self.app(scope, receive, send_wrapper)
            finally:
                duration_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)
                log_level = self._choose_log_level(path, status_code)
                access_logger.log(
                    log_level,
                    "%s %s -> %d (%.2fms)",
                    method,
                    path,
                    status_code,
                    duration_ms,
                    extra={
                        "http_method": method,
                        "http_path": path,
                        "query_string": query_str[:256] if query_str else None,
                        "status_code": status_code,
                        "duration_ms": duration_ms,
                        "response_bytes": response_bytes,
                        "client_ip": client_ip,
                        "user_agent": user_agent[:256] if user_agent else None,
                        "org_id": get_org_id(),
                        "user_id": get_user_id(),
                    },
                )

    @staticmethod
    def _choose_log_level(path: str, status_code: int) -> int:
        if status_code >= 500:
            return logging.ERROR
        if status_code >= 400:
            return logging.WARNING
        if path in _QUIET_ACCESS_PATHS:
            return logging.DEBUG
        return logging.INFO


# ---------------------------------------------------------------------------
# SecurityHeadersMiddleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware injecting defense-in-depth HTTP security headers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings | None = None,
        hsts_max_age: int = 31_536_000,
    ) -> None:
        self.app = app
        self.settings = settings or get_settings()
        self.hsts_max_age = hsts_max_age

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", "/"))
        scheme = str(scope.get("scheme", "http"))
        raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        forwarded_proto = (_get_header(raw_headers, b"x-forwarded-proto") or "").lower()
        is_https = scheme == "https" or forwarded_proto == "https"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                _set_header(headers, b"x-content-type-options", "nosniff")
                _set_header(headers, b"x-frame-options", "DENY")
                _set_header(headers, b"x-xss-protection", "1; mode=block")
                _set_header(headers, b"referrer-policy", "strict-origin-when-cross-origin")
                _set_header(
                    headers,
                    b"permissions-policy",
                    "geolocation=(), microphone=(), camera=(), payment=()",
                )
                _set_header(headers, b"x-permitted-cross-domain-policies", "none")

                # Strict CSP for API endpoints; relaxed CSP on OpenAPI /docs & /redoc
                if not _has_header(headers, b"content-security-policy"):
                    if any(path.startswith(prefix) for prefix in _DOCS_PATH_PREFIXES):
                        csp = (
                            "default-src 'self' https://cdn.jsdelivr.net; "
                            "img-src 'self' data: https://fastapi.tiangolo.com; "
                            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"
                        )
                    else:
                        csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
                    _set_header(headers, b"content-security-policy", csp)

                if (is_https or self.settings.environment == "production") and not _has_header(
                    headers, b"strict-transport-security"
                ):
                    _set_header(
                        headers,
                        b"strict-transport-security",
                        f"max-age={self.hsts_max_age}; includeSubDomains",
                    )

                if any(path.startswith(prefix) for prefix in _SENSITIVE_NO_STORE_PREFIXES):
                    if not _has_header(headers, b"cache-control"):
                        _set_header(headers, b"cache-control", "no-store, max-age=0")
                        _set_header(headers, b"pragma", "no-cache")

                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ---------------------------------------------------------------------------
# Uniform Error Envelope Builder & Exception Handlers
# ---------------------------------------------------------------------------


def _resolve_request_id(request: Request) -> str:
    req_id = getattr(request.state, "request_id", None) or get_request_id()
    if req_id:
        return str(req_id)
    header_id = request.headers.get("x-request-id")
    return _sanitize_request_id(header_id)


def build_error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    details: dict[str, Any] | None = None,
    field_errors: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a uniform JSON error payload matching :class:`app.schemas.common.ErrorResponse`."""
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "field_errors": field_errors or [],
        },
        "request_id": request_id,
        "timestamp": utcnow().isoformat(),
    }
    response_headers = {"X-Request-ID": request_id}
    if headers:
        response_headers.update(headers)
    return JSONResponse(status_code=status_code, content=payload, headers=response_headers)


def _format_validation_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    formatted: list[dict[str, Any]] = []
    for err in exc.errors():
        loc_parts = [str(part) for part in err.get("loc", ()) if part != "__root__"]
        field_path = ".".join(loc_parts) if loc_parts else "request"
        formatted.append(
            {
                "field": field_path,
                "message": str(err.get("msg", "Invalid value")),
                "code": str(err.get("type", "invalid_value")),
            }
        )
    return formatted


def _classify_integrity_error(exc: IntegrityError) -> tuple[str, str, dict[str, Any]]:
    raw_msg = str(getattr(exc, "orig", exc))
    lowered = raw_msg.lower()
    if "unique" in lowered or "duplicate" in lowered:
        return (
            "DUPLICATE_RESOURCE",
            "A resource with the same unique identifier already exists",
            {"constraint": "unique"},
        )
    if "foreign key" in lowered:
        return (
            "FOREIGN_KEY_VIOLATION",
            "Referenced related resource does not exist or cannot be removed while referenced",
            {"constraint": "foreign_key"},
        )
    if "not null" in lowered:
        return (
            "MISSING_REQUIRED_FIELD",
            "A required database field was missing or null",
            {"constraint": "not_null"},
        )
    if "check constraint" in lowered:
        return (
            "CONSTRAINT_VIOLATION",
            "Value violated a database integrity check constraint",
            {"constraint": "check"},
        )
    return (
        "CONFLICT",
        "Database integrity constraint violation",
        {"constraint": "integrity"},
    )


def _http_status_to_error_code(status_code: int) -> str:
    mapping: dict[int, str] = {
        400: "BAD_REQUEST",
        401: "AUTHENTICATION_FAILED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE",
        504: "GATEWAY_TIMEOUT",
    }
    return mapping.get(status_code, f"HTTP_{status_code}")


def register_exception_handlers(app: FastAPI) -> None:
    """Register unified exception handlers on the FastAPI application instance."""

    @app.exception_handler(NetPulseError)
    async def handle_netpulse_error(request: Request, exc: NetPulseError) -> JSONResponse:
        req_id = _resolve_request_id(request)
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimitError):
            retry_after = exc.details.get("retry_after_seconds")
            if retry_after is not None:
                headers["Retry-After"] = str(max(1, int(float(retry_after) + 0.999)))
        elif exc.status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"

        if exc.status_code >= 500:
            logger.error(
                "Domain error [%s]: %s",
                exc.error_code,
                exc.message,
                extra={"error_code": exc.error_code, "status_code": exc.status_code},
            )
        else:
            logger.warning(
                "Client domain error [%s]: %s",
                exc.error_code,
                exc.message,
                extra={"error_code": exc.error_code, "status_code": exc.status_code},
            )

        return build_error_response(
            status_code=exc.status_code,
            code=exc.error_code,
            message=exc.message,
            request_id=req_id,
            details=exc.details,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        req_id = _resolve_request_id(request)
        field_errors = _format_validation_errors(exc)
        logger.warning(
            "Request validation failed (%d errors)",
            len(field_errors),
            extra={"field_error_count": len(field_errors)},
        )
        return build_error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message="Request validation failed. Check field_errors for details.",
            request_id=req_id,
            details={"error_count": len(field_errors)},
            field_errors=field_errors,
        )

    @app.exception_handler(StarletteHTTPException)
    @app.exception_handler(HTTPException)
    async def handle_http_exception(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        req_id = _resolve_request_id(request)
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            payload = dict(detail)
            payload.setdefault("request_id", req_id)
            payload.setdefault("timestamp", utcnow().isoformat())
            return JSONResponse(
                status_code=exc.status_code,
                content=payload,
                headers={"X-Request-ID": req_id, **dict(exc.headers or {})},
            )
        message = detail if isinstance(detail, str) else str(detail)
        return build_error_response(
            status_code=exc.status_code,
            code=_http_status_to_error_code(exc.status_code),
            message=message,
            request_id=req_id,
            headers=dict(exc.headers or {}),
        )

    @app.exception_handler(IntegrityError)
    async def handle_integrity_error(request: Request, exc: IntegrityError) -> JSONResponse:
        req_id = _resolve_request_id(request)
        code, message, details = _classify_integrity_error(exc)
        logger.warning(
            "Database integrity violation [%s]: %s",
            code,
            message,
            extra={"constraint": details.get("constraint")},
        )
        return build_error_response(
            status_code=409,
            code=code,
            message=message,
            request_id=req_id,
            details=details,
        )

    @app.exception_handler(OperationalError)
    async def handle_operational_error(request: Request, exc: OperationalError) -> JSONResponse:
        req_id = _resolve_request_id(request)
        logger.exception("Database operational failure during request")
        settings = get_settings()
        details: dict[str, Any] = {}
        if settings.debug:
            details["exception_type"] = type(exc).__name__
        return build_error_response(
            status_code=503,
            code="DATABASE_UNAVAILABLE",
            message="The database service is temporarily unavailable. Please retry shortly.",
            request_id=req_id,
            details=details,
        )

    @app.exception_handler(ValueError)
    async def handle_value_error(request: Request, exc: ValueError) -> JSONResponse:
        req_id = _resolve_request_id(request)
        logger.warning("ValueError raised during request: %s", exc)
        return build_error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message=str(exc) or "Invalid input value",
            request_id=req_id,
        )

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        req_id = _resolve_request_id(request)
        logger.exception("Unhandled exception during request processing")
        settings = get_settings()
        details: dict[str, Any] = {}
        if settings.debug:
            details["exception_type"] = type(exc).__name__
            details["detail"] = str(exc)
        return build_error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="An unexpected internal server error occurred.",
            request_id=req_id,
            details=details,
        )


def register_middleware(app: FastAPI, settings: Settings | None = None) -> None:
    """Attach CORS, security headers, request context middleware, and error handlers.

    Starlette applies middleware in LIFO order (last added executes outermost), so
    ``RequestContextMiddleware`` is added last to wrap every response—including
    CORS preflights and error responses—with correlation IDs and timing headers.
    """
    cfg = settings or get_settings()

    allow_origins = list(cfg.security.cors_origins)
    allow_credentials = "*" not in allow_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-ID",
            "X-Process-Time-Ms",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "Content-Disposition",
        ],
    )
    app.add_middleware(SecurityHeadersMiddleware, settings=cfg)
    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)


__all__ = [
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
    "build_error_response",
    "register_exception_handlers",
    "register_middleware",
]
