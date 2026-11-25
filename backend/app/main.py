"""FastAPI application factory for the NetPulse Network & Infrastructure Observability Platform.

Provides :func:`create_app` and the module-level ASGI instance :data:`app`,
configured for both persistent self-hosted deployments (Uvicorn/Gunicorn) and
ephemeral serverless runtimes (Vercel Python Functions):

- Structured JSON/console logging with automatic secret redaction.
- CORS middleware, :class:`SecurityHeadersMiddleware`, and
  :class:`RequestContextMiddleware` (correlation IDs, timing, structured access logs).
- Unified JSON error envelope handlers for domain, validation, HTTP, and database errors.
- Async lifespan hook that initializes SQLAlchemy ORM tables and idempotently seeds
  the enterprise demo dataset without launching blocking background threads.
- Mounted ``/api/v1`` router, lightweight ``/api/health`` probe, and root ``/``
  platform descriptor.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

# Import models package up-front so every SQLAlchemy table registers on Base.metadata.
import app.models  # noqa: F401
from app.api.deps import ensure_database_ready
from app.api.middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    register_exception_handlers,
    register_middleware,
)
from app.api.v1.router import OPENAPI_TAGS, api_v1_router, get_mounted_routers
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import get_engine
from app.schemas.common import utcnow

logger = get_logger("netpulse.main")

_APP_START_MONOTONIC = time.monotonic()


def _should_use_json_logs(cfg: Settings) -> bool:
    """Emit structured JSON logs in production, staging, and Vercel serverless runtimes."""
    return cfg.is_vercel or cfg.environment in {"production", "staging"}


def _build_lifespan(cfg: Settings, *, enable_seed: bool | None = None):
    """Build an async FastAPI lifespan context manager with safe DB init & demo seeding."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        startup_ts = time.perf_counter()
        logger.info(
            "Starting %s v%s (env=%s, vercel=%s, sqlite=%s)",
            cfg.app_name,
            cfg.version,
            cfg.environment,
            cfg.is_vercel,
            cfg.is_sqlite,
        )

        # Initialize database tables and idempotently seed demo data if empty.
        # Kept strictly synchronous and fast with no background threads so
        # Vercel serverless cold starts complete cleanly.
        try:
            init_status = ensure_database_ready(auto_seed=enable_seed)
            application.state.db_initialized = bool(init_status.get("initialized", True))
            application.state.demo_seeded = bool(init_status.get("seeded", False))
            elapsed_ms = round((time.perf_counter() - startup_ts) * 1000.0, 2)
            logger.info(
                "NetPulse startup complete in %.2fms (db_initialized=%s, demo_seeded=%s)",
                elapsed_ms,
                application.state.db_initialized,
                application.state.demo_seeded,
            )
        except Exception:
            application.state.db_initialized = False
            application.state.demo_seeded = False
            logger.exception("Database initialization failed during application lifespan startup")
            # Do not crash app creation in serverless environments; endpoints will retry lazily.

        yield

        logger.info("Shutting down %s v%s", cfg.app_name, cfg.version)

    return lifespan


def _check_database_connectivity() -> tuple[bool, float, str | None]:
    """Run a lightweight ``SELECT 1`` health probe against the configured engine."""
    started = time.perf_counter()
    try:
        ensure_database_ready()
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return True, latency_ms, None
    except Exception as exc:
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return False, latency_ms, f"{type(exc).__name__}: {exc}"


def create_app(
    settings: Settings | None = None,
    *,
    enable_seed: bool | None = None,
) -> FastAPI:
    """Construct and configure a production-grade NetPulse :class:`FastAPI` application.

    Args:
        settings: Optional :class:`Settings` override (defaults to :func:`get_settings`).
        enable_seed: Optional override controlling automatic idempotent demo seeding
            during lifespan startup (``None`` defers to environment configuration).

    Returns:
        A fully wired FastAPI ASGI application ready for Uvicorn or Vercel serverless.
    """
    cfg = settings or get_settings()

    configure_logging(
        level=cfg.log_level,
        json_format=_should_use_json_logs(cfg),
        service_name="netpulse",
    )

    application = FastAPI(
        title=cfg.app_name,
        version=cfg.version,
        description=(
            "Enterprise Network & Infrastructure Observability Platform providing "
            "CMDB asset inventory, physical site & rack DCIM, IPAM & CIDR/VLSM "
            "engineering, Fernet-encrypted credential vaulting, multi-tenant RBAC, "
            "telemetry ingestion, topology discovery, alerting, and automation."
        ),
        openapi_tags=OPENAPI_TAGS,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=_build_lifespan(cfg, enable_seed=enable_seed),
    )

    application.state.settings = cfg
    application.state.started_at = utcnow()
    application.state.db_initialized = False
    application.state.demo_seeded = False

    # Wire CORS, SecurityHeadersMiddleware, RequestContextMiddleware, and exception handlers.
    register_middleware(application, settings=cfg)

    # Mount master v1 API router under /api/v1 (or configured prefix).
    application.include_router(api_v1_router, prefix=cfg.api_v1_prefix)

    # ------------------------------------------------------------------
    # Top-level platform health probe (/api/health) & root descriptor (/)
    # ------------------------------------------------------------------

    @application.get(
        "/api/health",
        tags=["Health & System"],
        summary="Top-level platform liveness and database health check",
    )
    def api_health() -> JSONResponse:
        """Fast health probe suitable for load balancers, Docker, and Vercel checks."""
        db_ok, db_latency_ms, db_error = _check_database_connectivity()
        uptime_seconds = round(max(0.0, time.monotonic() - _APP_START_MONOTONIC), 2)
        payload: dict[str, Any] = {
            "status": "healthy" if db_ok else "degraded",
            "service": cfg.app_name,
            "version": cfg.version,
            "environment": cfg.environment,
            "runtime": "vercel-serverless" if cfg.is_vercel else "standard",
            "uptime_seconds": uptime_seconds,
            "timestamp": utcnow().isoformat(),
            "database": {
                "status": "up" if db_ok else "down",
                "backend": "sqlite" if cfg.is_sqlite else "postgresql",
                "latency_ms": db_latency_ms,
                **({"error": db_error} if db_error and cfg.debug else {}),
            },
        }
        code = status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=code, content=payload)

    @application.get(
        "/",
        tags=["Health & System"],
        summary="NetPulse API root descriptor",
    )
    def root_descriptor() -> dict[str, Any]:
        """Return API discovery metadata, documentation links, and mounted v1 modules."""
        return {
            "service": cfg.app_name,
            "version": cfg.version,
            "status": "operational",
            "environment": cfg.environment,
            "runtime": "vercel-serverless" if cfg.is_vercel else "standard",
            "api_v1_prefix": cfg.api_v1_prefix,
            "links": {
                "health": "/api/health",
                "v1_health": f"{cfg.api_v1_prefix}/health",
                "v1_ready": f"{cfg.api_v1_prefix}/ready",
                "v1_meta": f"{cfg.api_v1_prefix}/meta",
                "openapi": "/openapi.json",
                "docs": "/docs",
                "redoc": "/redoc",
            },
            "modules": get_mounted_routers(),
        }

    return application


# Module-level ASGI application instance for Uvicorn, Gunicorn, and Vercel
app = create_app()

__all__ = [
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
    "app",
    "create_app",
    "register_exception_handlers",
    "register_middleware",
]
