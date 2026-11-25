"""NetPulse HTTP API package (dependencies, middleware, and versioned routers)."""

from __future__ import annotations

from app.api.deps import (
    AuthContext,
    ResolvedTimeRange,
    ensure_database_ready,
    get_current_auth,
    get_db_session,
    parse_pagination,
    parse_time_range,
    rate_limit_dependency,
    require_any_permission,
    require_auth,
    require_permission,
    require_role,
)
from app.api.middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    register_exception_handlers,
    register_middleware,
)

__all__ = [
    "AuthContext",
    "RequestContextMiddleware",
    "ResolvedTimeRange",
    "SecurityHeadersMiddleware",
    "ensure_database_ready",
    "get_current_auth",
    "get_db_session",
    "parse_pagination",
    "parse_time_range",
    "rate_limit_dependency",
    "register_exception_handlers",
    "register_middleware",
    "require_any_permission",
    "require_auth",
    "require_permission",
    "require_role",
]
