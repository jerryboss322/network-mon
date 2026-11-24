"""Database engine, session factory, and transaction context managers."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.db.base import Base


def build_engine(settings: Settings | None = None, database_url: str | None = None) -> Engine:
    """Create a configured SQLAlchemy engine for SQLite or PostgreSQL."""
    cfg = settings or get_settings()
    url = database_url or cfg.database_url

    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        kwargs: dict = {"connect_args": connect_args, "echo": cfg.db_echo}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        return engine

    return create_engine(
        url,
        echo=cfg.db_echo,
        pool_size=cfg.db_pool_size,
        max_overflow=cfg.db_max_overflow,
        pool_pre_ping=True,
    )


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _session_factory


def reset_engine(database_url: str | None = None) -> Engine:
    """Reset the singleton engine (useful in tests and serverless restarts)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = build_engine(database_url=database_url)
    _session_factory = sessionmaker(
        bind=_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    return _engine


def init_database(engine: Engine | None = None) -> None:
    """Create all ORM tables on the given or default engine."""
    target = engine or get_engine()
    Base.metadata.create_all(bind=target)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped SQLAlchemy session."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope(factory: sessionmaker[Session] | None = None) -> Generator[Session, None, None]:
    """Transactional context manager that commits on success and rolls back on error."""
    sf = factory or get_session_factory()
    session = sf()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
