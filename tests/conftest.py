"""Shared pytest fixtures for NetPulse test suites."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app.models  # noqa: E402, F401
from app.db.seed import seed_enterprise_demo  # noqa: E402
from app.db.session import get_session_factory, init_database, reset_engine  # noqa: E402


@pytest.fixture()
def db_session():
    """Provide an isolated in-memory SQLite session with schema created."""
    reset_engine("sqlite:///:memory:")
    init_database()
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def seeded_db(db_session):
    """Provide an in-memory session pre-populated with enterprise demo data."""
    summary = seed_enterprise_demo(db_session, commit=True)
    return db_session, summary
