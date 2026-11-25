"""Identity, multi-tenancy, authentication, RBAC, and audit ORM models.

Defines the core security and tenant boundary tables for NetPulse:
- :class:`Organization`: Multi-tenant isolation boundary, plan quotas, and settings.
- :class:`User`: Tenant-scoped operator accounts with MFA and lockout protection.
- :class:`UserSession`: Refresh-token-backed login sessions with revocation tracking.
- :class:`ApiKey`: Scoped machine-to-machine API credentials with CIDR allow-lists.
- :class:`AuditLog`: Append-only security and configuration change trail.
- :class:`OrgWebhookEndpoint`: Organization-level outbound event webhook subscriptions.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    utcnow,
)
from app.models.enums import AuditAction, UserRole

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,118}[a-z0-9])?$")
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def _as_utc(dt: datetime | None) -> datetime | None:
    """Normalize naive datetimes (e.g. from SQLite) to timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Multi-tenant organization entity owning inventory, telemetry, and users."""

    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint("max_devices > 0", name="max_devices_positive"),
        CheckConstraint("max_users > 0", name="max_users_positive"),
        CheckConstraint("retention_days > 0", name="retention_days_positive"),
        Index("ix_organizations_active_plan", "is_active", "plan_tier"),
    )

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    plan_tier: Mapped[str] = mapped_column(String(32), default="enterprise", nullable=False)
    max_devices: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    max_users: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    api_keys: Mapped[list[ApiKey]] = relationship(
        "ApiKey",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    webhook_endpoints: Mapped[list[OrgWebhookEndpoint]] = relationship(
        "OrgWebhookEndpoint",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("slug")
    def _validate_slug(self, _key: str, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned or not _SLUG_RE.match(cleaned):
            raise ValueError(
                f"Invalid organization slug {value!r}: must contain lowercase "
                "alphanumeric characters and hyphens only"
            )
        return cleaned

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Organization name must not be empty")
        return cleaned

    @validates("max_devices", "max_users", "retention_days")
    def _validate_positive_quota(self, key: str, value: int) -> int:
        if value <= 0:
            raise ValueError(f"Organization {key} must be strictly positive, got {value}")
        return value

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Retrieve a typed or nested setting value from ``settings_json``."""
        if not isinstance(self.settings_json, dict):
            return default
        return self.settings_json.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        """Update a setting key using copy-on-write so SQLAlchemy tracks dirtiness."""
        updated = dict(self.settings_json or {})
        updated[key] = value
        self.settings_json = updated

    def can_add_device(self, current_device_count: int) -> bool:
        """Return ``True`` when the tenant has remaining device license capacity."""
        active = True if self.is_active is None else self.is_active
        limit = self.max_devices if self.max_devices is not None else 1000
        return active and not bool(self.is_deleted) and current_device_count < limit

    def can_add_user(self, current_user_count: int) -> bool:
        """Return ``True`` when the tenant has remaining user seat capacity."""
        active = True if self.is_active is None else self.is_active
        limit = self.max_users if self.max_users is not None else 100
        return active and not bool(self.is_deleted) and current_user_count < limit

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a safe, JSON-serializable summary of this organization."""
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "plan_tier": self.plan_tier,
            "max_devices": self.max_devices,
            "max_users": self.max_users,
            "retention_days": self.retention_days,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Organization id={self.id!r} slug={self.slug!r} "
            f"plan_tier={self.plan_tier!r} active={self.is_active}>"
        )


class User(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Organization-scoped platform user with RBAC, MFA, and brute-force lockout."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
        UniqueConstraint("org_id", "username", name="uq_users_org_username"),
        CheckConstraint(
            "failed_login_attempts >= 0",
            name="failed_login_attempts_non_negative",
        ),
        Index("ix_users_org_role", "org_id", "role"),
        Index("ix_users_org_active", "org_id", "is_active"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32),
        default=UserRole.VIEWER.value,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    preferences_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="users",
    )
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    created_api_keys: Mapped[list[ApiKey]] = relationship(
        "ApiKey",
        back_populates="created_by_user",
        foreign_keys="[ApiKey.created_by_user_id]",
    )

    @validates("email")
    def _validate_email(self, _key: str, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
            raise ValueError(f"Invalid email address: {value!r}")
        return cleaned

    @validates("username")
    def _validate_username(self, _key: str, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Username must be at least 2 characters long")
        return cleaned

    @validates("role")
    def _validate_role(self, _key: str, value: str | UserRole) -> str:
        if isinstance(value, UserRole):
            return value.value
        return UserRole(value.strip().lower()).value

    @property
    def role_enum(self) -> UserRole:
        """Return the user's RBAC role as a :class:`UserRole` enum."""
        return UserRole(self.role or UserRole.VIEWER.value)

    def has_role(self, required: UserRole | str) -> bool:
        """Return ``True`` if this user's role satisfies *required* privilege."""
        return self.role_enum.has_at_least(required)

    def is_locked(self, now: datetime | None = None) -> bool:
        """Return ``True`` if the account is currently in a brute-force lockout window."""
        locked_until = _as_utc(self.locked_until)
        if locked_until is None:
            return False
        reference = _as_utc(now) or utcnow()
        return locked_until > reference

    def can_authenticate(self, now: datetime | None = None) -> bool:
        """Return ``True`` if the user is active, not soft-deleted, and not locked."""
        active = True if self.is_active is None else self.is_active
        return active and not bool(self.is_deleted) and not self.is_locked(now=now)

    def record_failed_login(
        self,
        *,
        max_attempts: int = 5,
        lockout_minutes: int = 15,
        now: datetime | None = None,
    ) -> bool:
        """Increment failed login attempts and lock account if threshold is reached.

        Returns ``True`` if this attempt triggered or extended an account lockout.
        """
        reference = _as_utc(now) or utcnow()
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = reference + timedelta(minutes=lockout_minutes)
            return True
        return False

    def record_successful_login(
        self,
        *,
        ip_address: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Reset failure counters and stamp last-login metadata."""
        reference = _as_utc(now) or utcnow()
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = reference
        if ip_address is not None:
            self.last_login_ip = ip_address

    def unlock(self) -> None:
        """Administratively clear lockout state and reset failed login counter."""
        self.failed_login_attempts = 0
        self.locked_until = None

    def get_preference(self, key: str, default: Any = None) -> Any:
        """Read a user UI/notification preference from ``preferences_json``."""
        if not isinstance(self.preferences_json, dict):
            return default
        return self.preferences_json.get(key, default)

    def set_preference(self, key: str, value: Any) -> None:
        """Persist a single preference key using copy-on-write mutation."""
        prefs = dict(self.preferences_json or {})
        prefs[key] = value
        self.preferences_json = prefs

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize safe user profile fields without secrets or password hashes."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "mfa_enabled": self.mfa_enabled,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} org_id={self.org_id!r} "
            f"email={self.email!r} role={self.role!r}>"
        )


class UserSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stateful refresh-token session enabling instant logout and token rotation."""

    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_active", "user_id", "revoked_at", "expires_at"),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    refresh_token_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="sessions")

    @property
    def is_revoked(self) -> bool:
        """Return ``True`` if this session has been explicitly revoked."""
        return self.revoked_at is not None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return ``True`` if the refresh token expiration timestamp has passed."""
        expires = _as_utc(self.expires_at)
        if expires is None:
            return True
        reference = _as_utc(now) or utcnow()
        return expires <= reference

    def is_valid(self, now: datetime | None = None) -> bool:
        """Return ``True`` if the session is neither revoked nor expired."""
        return not self.is_revoked and not self.is_expired(now=now)

    def revoke(self, now: datetime | None = None) -> None:
        """Revoke the session idempotently."""
        if self.revoked_at is None:
            self.revoked_at = _as_utc(now) or utcnow()

    def extend(self, new_expires_at: datetime) -> None:
        """Extend expiration for a non-revoked session."""
        if self.is_revoked:
            raise ValueError("Cannot extend a revoked user session")
        self.expires_at = _as_utc(new_expires_at) or new_expires_at

    def __repr__(self) -> str:
        return (
            f"<UserSession id={self.id!r} user_id={self.user_id!r} "
            f"revoked={self.is_revoked}>"
        )


class ApiKey(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Scoped programmatic API key with optional CIDR allow-list and expiry."""

    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_api_keys_org_name"),
        Index("ix_api_keys_org_active", "org_id", "is_active"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    scopes_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_cidrs_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="api_keys",
    )
    created_by_user: Mapped[User | None] = relationship(
        "User",
        back_populates="created_api_keys",
        foreign_keys="[ApiKey.created_by_user_id]",
    )

    @validates("allowed_cidrs_json")
    def _validate_cidrs(self, _key: str, value: list[str] | None) -> list[str]:
        if not value:
            return []
        normalized: list[str] = []
        for raw_cidr in value:
            network = ipaddress.ip_network(raw_cidr.strip(), strict=False)
            normalized.append(str(network))
        return normalized

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return ``True`` if an expiration time is set and has elapsed."""
        expires = _as_utc(self.expires_at)
        if expires is None:
            return False
        reference = _as_utc(now) or utcnow()
        return expires <= reference

    def is_valid(self, now: datetime | None = None) -> bool:
        """Return ``True`` if the key is active and unexpired."""
        active = True if self.is_active is None else self.is_active
        return active and not self.is_expired(now=now)

    def has_scope(self, required_scope: str) -> bool:
        """Check whether *required_scope* is granted by ``scopes_json``.

        Supports exact matches, global wildcard ``"*"``, and namespace wildcards
        such as ``"inventory:*"`` or ``"alerts:read"``.
        """
        scopes = self.scopes_json or []
        for granted in scopes:
            if granted == "*" or granted == required_scope:
                return True
            if "*" in granted and fnmatch.fnmatchcase(required_scope, granted):
                return True
        return False

    def is_ip_allowed(self, client_ip: str) -> bool:
        """Verify *client_ip* against ``allowed_cidrs_json``.

        An empty allow-list permits access from any source IP address.
        """
        cidrs = self.allowed_cidrs_json or []
        if not cidrs:
            return True
        try:
            addr = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def mark_used(self, now: datetime | None = None) -> None:
        """Update the ``last_used_at`` audit timestamp."""
        self.last_used_at = _as_utc(now) or utcnow()

    def revoke(self) -> None:
        """Deactivate this API key immediately."""
        self.is_active = False

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize non-secret metadata for API responses (excludes ``key_hash``)."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": list(self.scopes_json or []),
            "allowed_cidrs": list(self.allowed_cidrs_json or []),
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<ApiKey id={self.id!r} org_id={self.org_id!r} "
            f"prefix={self.key_prefix!r} active={self.is_active}>"
        )


class AuditLog(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable, append-only compliance and security audit log record."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_org_created", "org_id", "created_at"),
        Index("ix_audit_logs_org_resource", "org_id", "resource_type", "resource_id"),
        Index("ix_audit_logs_org_action", "org_id", "action", "created_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="audit_logs",
    )
    actor_user: Mapped[User | None] = relationship(
        "User",
        foreign_keys="[AuditLog.actor_user_id]",
    )

    @validates("action")
    def _validate_action(self, _key: str, value: str | AuditAction) -> str:
        if isinstance(value, AuditAction):
            return value.value
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("AuditLog action must not be empty")
        return cleaned

    def changed_fields(self) -> dict[str, dict[str, Any]]:
        """Compute a field-level diff between ``before_state`` and ``after_state``."""
        before = self.before_state if isinstance(self.before_state, dict) else {}
        after = self.after_state if isinstance(self.after_state, dict) else {}
        diff: dict[str, dict[str, Any]] = {}
        for key in sorted(set(before.keys()) | set(after.keys())):
            old_val = before.get(key)
            new_val = after.get(key)
            if old_val != new_val:
                diff[key] = {"before": old_val, "after": new_val}
        return diff

    def to_event_dict(self) -> dict[str, Any]:
        """Serialize the audit event for SIEM export or API responses."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "actor_user_id": self.actor_user_id,
            "actor_email": self.actor_email,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "summary": self.summary,
            "changed_fields": self.changed_fields(),
            "ip_address": self.ip_address,
            "request_id": self.request_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id!r} org_id={self.org_id!r} "
            f"action={self.action!r} resource={self.resource_type!r}:{self.resource_id!r}>"
        )


class OrgWebhookEndpoint(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Tenant-level outbound webhook subscription with HMAC secret and circuit-breaker."""

    __tablename__ = "org_webhook_endpoints"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_org_webhook_endpoints_org_name"),
        CheckConstraint("failure_count >= 0", name="failure_count_non_negative"),
        Index("ix_org_webhooks_org_active", "org_id", "is_active"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_patterns_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="webhook_endpoints",
    )

    @validates("url")
    def _validate_url(self, _key: str, value: str) -> str:
        cleaned = value.strip()
        if not _URL_SCHEME_RE.match(cleaned):
            raise ValueError(f"Webhook URL must use http:// or https:// scheme: {value!r}")
        return cleaned

    def matches_event(self, event_name: str) -> bool:
        """Return ``True`` if this active endpoint subscribes to *event_name*."""
        active = True if self.is_active is None else self.is_active
        if not active:
            return False
        patterns = self.event_patterns_json or []
        if not patterns:
            return False
        return any(fnmatch.fnmatchcase(event_name, pat) for pat in patterns)

    def record_success(self, now: datetime | None = None) -> None:
        """Reset consecutive failure count and update ``last_triggered_at``."""
        self.failure_count = 0
        self.last_triggered_at = _as_utc(now) or utcnow()

    def record_failure(
        self,
        *,
        max_failures: int = 10,
        auto_disable: bool = True,
        now: datetime | None = None,
    ) -> bool:
        """Record a delivery failure and optionally trip the circuit breaker.

        Returns ``True`` if the endpoint was auto-disabled by this failure.
        """
        self.failure_count = (self.failure_count or 0) + 1
        self.last_triggered_at = _as_utc(now) or utcnow()
        if auto_disable and self.failure_count >= max_failures:
            self.is_active = False
            return True
        return False

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize webhook configuration without exposing ``secret_encrypted``."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "url": self.url,
            "has_secret": bool(self.secret_encrypted),
            "event_patterns": list(self.event_patterns_json or []),
            "is_active": self.is_active,
            "failure_count": self.failure_count,
            "last_triggered_at": (
                self.last_triggered_at.isoformat() if self.last_triggered_at else None
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<OrgWebhookEndpoint id={self.id!r} org_id={self.org_id!r} "
            f"name={self.name!r} active={self.is_active}>"
        )


__all__ = [
    "ApiKey",
    "AuditLog",
    "OrgWebhookEndpoint",
    "Organization",
    "User",
    "UserSession",
]
