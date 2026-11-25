"""Vercel Python Serverless ASGI entrypoint for NetPulse.

Exposes the FastAPI ASGI application ``app`` (and compatibility alias ``handler``)
for Vercel's Python runtime (`@vercel/python`). Adds the ``backend/`` directory
to ``sys.path`` idempotently before importing :data:`app.main.app`, ensuring clean
cold-start initialization with lazy database schema creation and idempotent
enterprise demo seeding.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Resolve repository root and prepend backend/ to sys.path for app.* imports.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_BACKEND_DIR = _REPO_ROOT / "backend"
_BACKEND_STR = str(_BACKEND_DIR)

if _BACKEND_DIR.is_dir() and _BACKEND_STR not in sys.path:
    sys.path.insert(0, _BACKEND_STR)

# Default to serverless-safe configuration when invoked directly via Vercel runtime.
os.environ.setdefault("NETMON_COLLECTORS_ENABLED", "false")
if os.getenv("VERCEL") in {"1", "true", "TRUE"}:
    os.environ.setdefault("NETMON_SIMULATE_DEMO", "true")

from app.api.deps import ensure_database_ready  # noqa: E402
from app.main import app, create_app  # noqa: E402

# Ensure ephemeral serverless SQLite (/tmp) schema & demo seed exist on cold start
# even if the host runtime dispatches HTTP requests without running ASGI lifespan.
if os.getenv("VERCEL") in {"1", "true", "TRUE"}:
    try:
        ensure_database_ready()
    except Exception:
        # Individual request dependencies will retry lazily if cold-start DB init fails.
        pass

# Vercel's Python ASGI adapter discovers ``app`` directly; ``handler`` is exported as an alias.
handler = app

__all__ = ["app", "create_app", "handler"]
