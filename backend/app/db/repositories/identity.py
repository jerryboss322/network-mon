"""Data-access repositories for identity, authentication, RBAC, audit, and webhook entities."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, func, or_, select, update as sa_update
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.db.base import utcnow
from app.db.repositories.base import BaseRepository, PageResult

if TYPE_CHECKING:
    from app.models.identity import (
        ApiKey,
        AuditLog,
        Organization,
        OrgWebhookEndpoint,
        User,
        UserSession,
    )


class OrganizationRepository(BaseRepository["Organization"]):
    """Repository for multi-tenant :class:`Organization` records."""

    _model_spec = ("app.models.identity", "Organization")
    default_order_by = ("name",)

    def get_by_slug(self, slug: str, *, include_deleted: bool | None = None) -> Any | None:
        """Fetch an organization by its unique URL slug (case-insensitive)."""
        normalized = slug.strip().lower()
        col = self._resolve_column("slug")
        stmt = self._base_query(include_deleted=include_deleted).where(func.lower(col) == normalized)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_slug_or_raise(self, slug: str) -> Any:
        """Fetch an organization by slug or raise :class:`NotFoundError`."""
        org = self.get_by_slug(slug)
        if org is None:
            raise NotFoundError(
                f"Organization '{slug}' was not found",
                details={"entity": "Organization", "slug": slug},
            )
        return org

    def slug_exists(self, slug: str, *, exclude_id: str | None = None) -> bool:
        """Return ``True`` if another organization already claims ``slug``."""
        normalized = slug.strip().lower()
        col = self._resolve_column("slug")
        stmt = self._base_query(include_deleted=True).where(func.lower(col) == normalized)
        if exclude_id is not None:
            stmt = stmt.where(self._get_column("id") != exclude_id)
        return self.session.execute(select(stmt.limit(1).exists())).scalar_one()

    def list_active(self, *, limit: int | None = None, offset: int | None = None) -> list[Any]:
        """List all active (non-suspended, non-deleted) organizations."""
        filters: dict[str, Any] = {}
        if self._has_column("is_active"):
            filters["is_active"] = True
        elif self._has_column("status"):
            filters["status"] = "active"
        return self.list(filters=filters, limit=limit, offset=offset)

    def get_by_domain(self, domain: str) -> Any | None:
        """Lookup an organization by SSO/email domain if configured."""
        col = self._optional_column("domain", "sso_domain", "primary_domain")
        if col is None:
            return None
        stmt = self._base_query().where(func.lower(col) == domain.strip().lower())
        return self.session.execute(stmt).scalar_one_or_none()

    def update_plan(
        self,
        org_id: str,
        plan: str,
        *,
        max_devices: int | None = None,
        max_users: int | None = None,
        flush: bool = True,
    ) -> Any:
        """Update an organization's subscription tier and optional resource quotas."""
        patch: dict[str, Any] = {}
        if self._has_column("plan_tier"):
            patch["plan_tier"] = plan
        elif self._has_column("plan"):
            patch["plan"] = plan
        elif self._has_column("tier"):
            patch["tier"] = plan
        if max_devices is not None and self._has_column("max_devices"):
            patch["max_devices"] = max_devices
        if max_users is not None and self._has_column("max_users"):
            patch["max_users"] = max_users
        return self.update(org_id, patch, flush=flush)

    def update_settings(
        self,
        org_id: str,
        patch: Mapping[str, Any],
        *,
        flush: bool = True,
    ) -> Any:
        """Merge keys into the organization's JSON settings payload."""
        org = self.get_by_id_or_raise(org_id)
        settings_col = self._optional_column("settings_json", "settings", "metadata_json", "config")
        if settings_col is None:
            return org
        attr_name = settings_col.key
        current = dict(getattr(org, attr_name) or {})
        current.update(patch)
        return self.update(org, {attr_name: current}, flush=flush)


class UserRepository(BaseRepository["User"]):
    """Repository for platform :class:`User` accounts, RBAC roles, and lockout tracking."""

    _model_spec = ("app.models.identity", "User")
    default_order_by = ("email",)

    def get_by_email(
        self,
        email: str,
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> Any | None:
        """Lookup a user by case-insensitive email address."""
        normalized = email.strip().lower()
        email_col = self._resolve_column("email")
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted).where(
            func.lower(email_col) == normalized
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_email_or_raise(self, email: str, *, org_id: str | None = None) -> Any:
        """Fetch a user by email or raise :class:`NotFoundError`."""
        user = self.get_by_email(email, org_id=org_id)
        if user is None:
            raise NotFoundError(
                f"User with email '{email}' was not found",
                details={"entity": "User", "email": email},
            )
        return user

    def get_by_username(self, username: str, *, org_id: str | None = None) -> Any | None:
        """Lookup a user by username if the model exposes a username column."""
        col = self._optional_column("username")
        if col is None:
            return None
        stmt = self._base_query(org_id=org_id).where(func.lower(col) == username.strip().lower())
        return self.session.execute(stmt).scalar_one_or_none()

    def list_by_role(
        self,
        role: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[Any]:
        """Return all users assigned a given RBAC role."""
        filters: dict[str, Any] = {"role": role}
        if active_only and self._has_column("is_active"):
            filters["is_active"] = True
        return self.list(filters=filters, org_id=org_id)

    def search(
        self,
        *,
        query: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        org_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Any]:
        """Search users by email, full name, or username with optional role/activity filters."""
        stmt = self._base_query(org_id=org_id)
        if role is not None and self._has_column("role"):
            stmt = stmt.where(self._get_column("role") == role)
        if is_active is not None and self._has_column("is_active"):
            stmt = stmt.where(self._get_column("is_active").is_(is_active))
        if query:
            pattern = f"%{query.strip()}%"
            predicates = [self._get_column("email").ilike(pattern)]
            for candidate in ("full_name", "display_name", "username"):
                if self._has_column(candidate):
                    predicates.append(self._get_column(candidate).ilike(pattern))
            stmt = stmt.where(or_(*predicates))

        total = int(self.session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        ordered = self._apply_ordering(stmt, None).offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.execute(ordered).scalars().all())
        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def record_login_success(
        self,
        user_id: str,
        *,
        ip_address: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Reset failed login counters and update last-login metadata."""
        patch: dict[str, Any] = {}
        now = utcnow()
        if self._has_column("last_login_at"):
            patch["last_login_at"] = now
        if self._has_column("failed_login_attempts"):
            patch["failed_login_attempts"] = 0
        if self._has_column("locked_until"):
            patch["locked_until"] = None
        if ip_address is not None and self._has_column("last_login_ip"):
            patch["last_login_ip"] = ip_address
        return self.update(user_id, patch, flush=flush)

    def record_login_failure(
        self,
        user_id: str,
        *,
        max_attempts: int = 5,
        lockout_minutes: int = 15,
        flush: bool = True,
    ) -> Any:
        """Increment failed login attempts and enforce temporary account lockout if threshold reached."""
        user = self.get_by_id_or_raise(user_id)
        patch: dict[str, Any] = {}
        if self._has_column("failed_login_attempts"):
            attempts = int(getattr(user, "failed_login_attempts", 0) or 0) + 1
            patch["failed_login_attempts"] = attempts
            if attempts >= max_attempts and self._has_column("locked_until"):
                patch["locked_until"] = utcnow() + timedelta(minutes=lockout_minutes)
        return self.update(user, patch, flush=flush)

    def is_locked_out(self, user: Any) -> bool:
        """Return ``True`` if the user is currently locked out due to failed login attempts."""
        locked_until: datetime | None = getattr(user, "locked_until", None)
        if locked_until is None:
            return False
        now = utcnow()
        if locked_until.tzinfo is None:
            now = now.replace(tzinfo=None)
        return locked_until > now

    def unlock_account(self, user_id: str, *, flush: bool = True) -> Any:
        """Manually clear lockout timestamp and failed attempt counter."""
        patch: dict[str, Any] = {}
        if self._has_column("failed_login_attempts"):
            patch["failed_login_attempts"] = 0
        if self._has_column("locked_until"):
            patch["locked_until"] = None
        return self.update(user_id, patch, flush=flush)

    def update_password_hash(self, user_id: str, password_hash: str, *, flush: bool = True) -> Any:
        """Persist a new hashed password for a user."""
        col = self._resolve_column("password_hash", "hashed_password")
        patch: dict[str, Any] = {col.key: password_hash}
        if self._has_column("password_changed_at"):
            patch["password_changed_at"] = utcnow()
        return self.update(user_id, patch, flush=flush)

    def count_by_role(self, *, org_id: str | None = None) -> dict[str, int]:
        """Return user counts grouped by RBAC role."""
        role_col = self._resolve_column("role")
        base = self._base_query(org_id=org_id).subquery()
        stmt = select(base.c[role_col.key], func.count()).group_by(base.c[role_col.key])
        return {str(role): int(cnt) for role, cnt in self.session.execute(stmt).all()}


class UserSessionRepository(BaseRepository["UserSession"]):
    """Repository for active refresh/access :class:`UserSession` records."""

    _model_spec = ("app.models.identity", "UserSession")
    default_order_by = ("-created_at",)

    def get_by_token_hash(self, token_hash: str) -> Any | None:
        """Find a session by its hashed refresh or session token."""
        col = self._resolve_column("refresh_token_hash", "token_hash")
        stmt = self._base_query().where(col == token_hash)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_active_by_token_hash(self, token_hash: str) -> Any | None:
        """Return a session only if it has not been revoked and has not expired."""
        col = self._resolve_column("refresh_token_hash", "token_hash")
        stmt = self._base_query().where(col == token_hash)
        if self._has_column("is_revoked"):
            stmt = stmt.where(self._get_column("is_revoked").is_(False))
        elif self._has_column("revoked_at"):
            stmt = stmt.where(self._get_column("revoked_at").is_(None))
        if self._has_column("expires_at"):
            stmt = stmt.where(self._get_column("expires_at") > utcnow())
        return self.session.execute(stmt).scalar_one_or_none()

    def list_active_for_user(self, user_id: str) -> list[Any]:
        """List all non-revoked, non-expired sessions for a user."""
        stmt = self._base_query().where(self._get_column("user_id") == user_id)
        if self._has_column("is_revoked"):
            stmt = stmt.where(self._get_column("is_revoked").is_(False))
        elif self._has_column("revoked_at"):
            stmt = stmt.where(self._get_column("revoked_at").is_(None))
        if self._has_column("expires_at"):
            stmt = stmt.where(self._get_column("expires_at") > utcnow())
        stmt = self._apply_ordering(stmt, None)
        return list(self.session.execute(stmt).scalars().all())

    def revoke_session(self, session_id: str, *, flush: bool = True) -> Any:
        """Mark a single user session as revoked."""
        patch: dict[str, Any] = {}
        if self._has_column("is_revoked"):
            patch["is_revoked"] = True
        if self._has_column("revoked_at"):
            patch["revoked_at"] = utcnow()
        return self.update(session_id, patch, flush=flush)

    def revoke_all_for_user(
        self,
        user_id: str,
        *,
        exclude_session_id: str | None = None,
        flush: bool = True,
    ) -> int:
        """Revoke all active sessions belonging to ``user_id``."""
        values: dict[str, Any] = {}
        if self._has_column("is_revoked"):
            values["is_revoked"] = True
        if self._has_column("revoked_at"):
            values["revoked_at"] = utcnow()
        if not values:
            return 0

        conditions = [self._get_column("user_id") == user_id]
        if exclude_session_id is not None:
            conditions.append(self._get_column("id") != exclude_session_id)
        if self._has_column("is_revoked"):
            conditions.append(self._get_column("is_revoked").is_(False))

        stmt = sa_update(self.model_cls).where(and_(*conditions)).values(**values)
        result = self.session.execute(stmt)
        if flush:
            self.session.flush()
        return int(result.rowcount or 0)

    def touch_activity(self, session_id: str, *, flush: bool = True) -> Any:
        """Update the last-seen activity timestamp for a session."""
        col = self._optional_column("last_used_at", "last_active_at", "updated_at")
        if col is None:
            return self.get_by_id_or_raise(session_id)
        return self.update(session_id, {col.key: utcnow()}, flush=flush)

    def purge_expired(self, *, before: datetime | None = None, flush: bool = True) -> int:
        """Remove expired sessions prior to ``before`` (defaults to now)."""
        if not self._has_column("expires_at"):
            return 0
        cutoff = before or utcnow()
        return self.delete_where(filters={"expires_at__lt": cutoff}, flush=flush)


class ApiKeyRepository(BaseRepository["ApiKey"]):
    """Repository for scoped programmatic :class:`ApiKey` credentials."""

    _model_spec = ("app.models.identity", "ApiKey")
    default_order_by = ("-created_at",)

    def get_by_prefix(self, key_prefix: str, *, org_id: str | None = None) -> Any | None:
        """Lookup an API key by its short display/lookup prefix (e.g. ``npm_xxxx``)."""
        col = self._resolve_column("key_prefix", "prefix")
        stmt = self._base_query(org_id=org_id).where(col == key_prefix)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_key_hash(self, key_hash: str) -> Any | None:
        """Lookup an API key by its cryptographic hash."""
        col = self._resolve_column("key_hash", "hashed_key")
        stmt = self._base_query().where(col == key_hash)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_valid_by_hash(self, key_hash: str) -> Any | None:
        """Return an API key only if it is active, non-revoked, and unexpired."""
        col = self._resolve_column("key_hash", "hashed_key")
        stmt = self._base_query().where(col == key_hash)
        if self._has_column("is_active"):
            stmt = stmt.where(self._get_column("is_active").is_(True))
        if self._has_column("revoked_at"):
            stmt = stmt.where(self._get_column("revoked_at").is_(None))
        if self._has_column("expires_at"):
            exp_col = self._get_column("expires_at")
            stmt = stmt.where(or_(exp_col.is_(None), exp_col > utcnow()))
        return self.session.execute(stmt).scalar_one_or_none()

    def list_for_user(
        self,
        user_id: str,
        *,
        active_only: bool = True,
        org_id: str | None = None,
    ) -> list[Any]:
        """List API keys created by or belonging to a specific user."""
        user_col = self._resolve_column("created_by_user_id", "user_id", "created_by_id", "owner_id")
        filters: dict[str, Any] = {user_col.key: user_id}
        if active_only and self._has_column("is_active"):
            filters["is_active"] = True
        return self.list(filters=filters, org_id=org_id)

    def list_expiring_soon(
        self,
        *,
        within_days: int = 14,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return active API keys expiring within ``within_days`` days."""
        if not self._has_column("expires_at"):
            return []
        now = utcnow()
        horizon = now + timedelta(days=within_days)
        stmt = self._base_query(org_id=org_id).where(
            and_(
                self._get_column("expires_at").is_not(None),
                self._get_column("expires_at") > now,
                self._get_column("expires_at") <= horizon,
            )
        )
        if self._has_column("is_active"):
            stmt = stmt.where(self._get_column("is_active").is_(True))
        return list(self.session.execute(stmt.order_by(self._get_column("expires_at"))).scalars().all())

    def record_usage(
        self,
        api_key_id: str,
        *,
        ip_address: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Update last-used timestamp and optional usage counter on an API key."""
        entity = self.get_by_id_or_raise(api_key_id)
        patch: dict[str, Any] = {}
        if self._has_column("last_used_at"):
            patch["last_used_at"] = utcnow()
        if ip_address is not None and self._has_column("last_used_ip"):
            patch["last_used_ip"] = ip_address
        if self._has_column("usage_count"):
            patch["usage_count"] = int(getattr(entity, "usage_count", 0) or 0) + 1
        return self.update(entity, patch, flush=flush)

    def revoke(self, api_key_id: str, *, org_id: str | None = None, flush: bool = True) -> Any:
        """Immediately revoke an API key."""
        patch: dict[str, Any] = {}
        if self._has_column("is_active"):
            patch["is_active"] = False
        if self._has_column("revoked_at"):
            patch["revoked_at"] = utcnow()
        return self.update(api_key_id, patch, org_id=org_id, flush=flush)


class AuditLogRepository(BaseRepository["AuditLog"]):
    """Append-oriented repository for immutable compliance :class:`AuditLog` entries."""

    _model_spec = ("app.models.identity", "AuditLog")
    default_order_by = ("-created_at",)

    def record(
        self,
        *,
        action: str,
        resource_type: str,
        org_id: str | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        resource_id: str | None = None,
        summary: str | None = None,
        status: str = "success",
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        before_state: Mapping[str, Any] | None = None,
        after_state: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        flush: bool = True,
    ) -> Any:
        """Insert a structured audit trail entry, mapping fields to existing ORM columns."""
        cols = self._column_names()
        resolved_summary = summary or f"{action} on {resource_type}" + (f" ({resource_id})" if resource_id else "")
        candidates: dict[str, Any] = {
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "summary": resolved_summary,
            "status": status,
            "outcome": status,
            "actor_user_id": actor_user_id,
            "user_id": actor_user_id,
            "actor_email": actor_email,
            "ip_address": ip_address,
            "source_ip": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "before_state": dict(before_state) if before_state is not None else None,
            "after_state": dict(after_state) if after_state is not None else (dict(details) if details is not None else None),
            "details": dict(details) if details is not None else {},
            "metadata_json": dict(details) if details is not None else {},
        }
        payload = {k: v for k, v in candidates.items() if k in cols and v is not None}
        if "details" in cols and "details" not in payload:
            payload["details"] = {}
        return self.create(payload, org_id=org_id, flush=flush)

    def search(
        self,
        *,
        org_id: str | None = None,
        actor_user_id: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Any]:
        """Query audit logs with actor, action, resource, time window, and text filters."""
        stmt = self._base_query(org_id=org_id)
        if actor_user_id is not None:
            actor_col = self._optional_column("actor_user_id", "user_id")
            if actor_col is not None:
                stmt = stmt.where(actor_col == actor_user_id)
        if action is not None and self._has_column("action"):
            stmt = stmt.where(self._get_column("action") == action)
        if resource_type is not None and self._has_column("resource_type"):
            stmt = stmt.where(self._get_column("resource_type") == resource_type)
        if resource_id is not None and self._has_column("resource_id"):
            stmt = stmt.where(self._get_column("resource_id") == resource_id)

        ts_col = self._resolve_column("timestamp", "created_at")
        if since is not None:
            stmt = stmt.where(ts_col >= since)
        if until is not None:
            stmt = stmt.where(ts_col <= until)
        if query:
            pattern = f"%{query.strip()}%"
            or_clauses = [self._get_column("action").ilike(pattern)]
            for candidate in ("resource_type", "resource_id", "actor_email", "ip_address"):
                if self._has_column(candidate):
                    or_clauses.append(self._get_column(candidate).ilike(pattern))
            stmt = stmt.where(or_(*or_clauses))

        total = int(self.session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        ordered = stmt.order_by(ts_col.desc()).offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.execute(ordered).scalars().all())
        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def list_for_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 50,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return recent audit events associated with a specific entity."""
        return self.list(
            filters={"resource_type": resource_type, "resource_id": resource_id},
            limit=limit,
            org_id=org_id,
        )

    def count_by_action(
        self,
        *,
        since: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Aggregate audit log counts grouped by action name."""
        stmt = self._base_query(org_id=org_id)
        if since is not None:
            ts_col = self._resolve_column("timestamp", "created_at")
            stmt = stmt.where(ts_col >= since)
        sub = stmt.subquery()
        agg = select(sub.c.action, func.count()).group_by(sub.c.action)
        return {str(act): int(cnt) for act, cnt in self.session.execute(agg).all()}

    def purge_older_than(self, cutoff: datetime, *, org_id: str | None = None, flush: bool = True) -> int:
        """Delete audit logs older than ``cutoff`` according to retention policy."""
        ts_col = self._resolve_column("timestamp", "created_at")
        return self.delete_where(filters={f"{ts_col.key}__lt": cutoff}, org_id=org_id, flush=flush)


class WebhookEndpointRepository(BaseRepository["OrgWebhookEndpoint"]):
    """Repository for outbound organization :class:`OrgWebhookEndpoint` subscriptions."""

    _model_spec = ("app.models.identity", "OrgWebhookEndpoint")
    default_order_by = ("name",)

    def list_enabled(self, *, org_id: str | None = None) -> list[Any]:
        """Return all enabled webhook endpoints for an organization."""
        filters: dict[str, Any] = {}
        if self._has_column("is_active"):
            filters["is_active"] = True
        elif self._has_column("is_enabled"):
            filters["is_enabled"] = True
        elif self._has_column("enabled"):
            filters["enabled"] = True
        return self.list(filters=filters, org_id=org_id)

    def list_active_for_event(self, event_type: str, *, org_id: str | None = None) -> list[Any]:
        """Return enabled webhook endpoints subscribed to ``event_type`` (or ``"*"`` wildcard)."""
        enabled = self.list_enabled(org_id=org_id)
        matched: list[Any] = []
        for endpoint in enabled:
            events = (
                getattr(endpoint, "event_patterns_json", None)
                or getattr(endpoint, "events", None)
                or getattr(endpoint, "event_types", None)
                or []
            )
            if isinstance(events, str):
                event_list = [e.strip() for e in events.split(",") if e.strip()]
            else:
                event_list = list(events)
            if not event_list or "*" in event_list or event_type in event_list:
                matched.append(endpoint)
        return matched

    def record_delivery_result(
        self,
        endpoint_id: str,
        *,
        success: bool,
        status_code: int | None = None,
        error_message: str | None = None,
        disable_after_failures: int = 10,
        flush: bool = True,
    ) -> Any:
        """Update webhook health counters and auto-disable after consecutive failures."""
        endpoint = self.get_by_id_or_raise(endpoint_id)
        patch: dict[str, Any] = {}
        now = utcnow()
        if self._has_column("last_triggered_at"):
            patch["last_triggered_at"] = now
        if self._has_column("last_delivery_at"):
            patch["last_delivery_at"] = now
        if status_code is not None and self._has_column("last_status_code"):
            patch["last_status_code"] = status_code

        fail_col = self._optional_column("consecutive_failures", "failure_count")
        if success:
            if fail_col is not None:
                patch[fail_col.key] = 0
            if self._has_column("last_error"):
                patch["last_error"] = None
        else:
            if self._has_column("last_error") and error_message is not None:
                patch["last_error"] = error_message[:1000]
            if fail_col is not None:
                failures = int(getattr(endpoint, fail_col.key, 0) or 0) + 1
                patch[fail_col.key] = failures
                if failures >= disable_after_failures:
                    for flag in ("is_active", "is_enabled", "enabled"):
                        if self._has_column(flag):
                            patch[flag] = False
                            break

        return self.update(endpoint, patch, flush=flush)

    def reset_failures(self, endpoint_id: str, *, reenable: bool = True, flush: bool = True) -> Any:
        """Reset failure counter and optionally re-enable a circuit-broken webhook."""
        patch: dict[str, Any] = {}
        fail_col = self._optional_column("consecutive_failures", "failure_count")
        if fail_col is not None:
            patch[fail_col.key] = 0
        if self._has_column("last_error"):
            patch["last_error"] = None
        if reenable:
            for flag in ("is_active", "is_enabled", "enabled"):
                if self._has_column(flag):
                    patch[flag] = True
                    break
        return self.update(endpoint_id, patch, flush=flush)


__all__ = [
    "ApiKeyRepository",
    "AuditLogRepository",
    "OrganizationRepository",
    "UserRepository",
    "UserSessionRepository",
    "WebhookEndpointRepository",
]
