"""API v1 router registry aggregating NetPulse domain routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.users import router as users_router


def build_v1_router() -> APIRouter:
    """Create the aggregated ``/api/v1`` FastAPI router."""
    api_router = APIRouter()
    api_router.include_router(health_router)
    api_router.include_router(auth_router)
    api_router.include_router(users_router)
    return api_router


v1_router = build_v1_router()

__all__ = [
    "auth_router",
    "build_v1_router",
    "health_router",
    "users_router",
    "v1_router",
]
