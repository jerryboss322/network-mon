"""SQLAlchemy 2.0 declarative base and shared ORM mixins."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, JSON, MetaData, String, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Return canonical lowercase UUID4 string."""
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        dict[str, Any]: JSON,
    }


class UUIDPrimaryKeyMixin:
    """Adds a string UUID4 primary key column."""

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)


class TimestampMixin:
    """Adds UTC created_at and updated_at columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class SoftDeleteMixin:
    """Adds soft-deletion tracking for auditable entities."""

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def mark_deleted(self) -> None:
        self.is_deleted = True
        self.deleted_at = utcnow()


class TenantScopedMixin:
    """Marks entities belonging to a specific organization tenant."""

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
