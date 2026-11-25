"""Immutable compliance audit logging, field-level diffing, export, and analytics service.

Provides :class:`AuditService` for recording, querying, exporting, and analyzing
security and configuration change trails across NetPulse tenant organizations:

- Recursive secret redaction stripping sensitive keys (passwords, tokens, secrets,
  API keys, SNMP communities, private keys, MFA seeds) and inline credential patterns
  prior to persistence.
- Structured field-level diffing between ``before_state`` and ``after_state`` snapshots.
- Flexible multi-criteria search & pagination by actor, action/prefix, resource,
  source IP, time window, and free-text query.
- Compliant CSV (RFC 4180 with spreadsheet formula-injection neutralization) and
  JSONL (newline-delimited JSON) SIEM export helpers.
- Activity summary analytics covering action breakdowns, resource distributions,
  top actors, daily event volume series, and security highlights.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_request_id
from app.db.base import utcnow
from app.db.repositories.base import PageResult
from app.db.repositories.identity import AuditLogRepository
from app.models.enums import AuditAction
from app.models.identity import AuditLog
from app.schemas.common import SortOrder
from app.schemas.identity import AuditLogQuery

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive key & value redaction constants
# ---------------------------------------------------------------------------

REDACTED_VALUE = "[REDACTED]"

#: Exact lowercase key names or substrings indicating sensitive credential fields.
SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "community",
    "passphrase",
    "credential",
    "private_key",
    "authorization",
    "cookie",
    "auth_pass",
    "priv_pass",
    "snmp_auth",
    "snmp_priv",
    "hmac",
    "mfa_secret",
    "totp",
    "bearer",
    "jwt",
    "pin",
)

#: Safe non-secret keys that happen to contain substrings such as "key" or "token".
SAFE_KEY_ALLOWLIST: frozenset[str] = frozenset(
    {
        "key_prefix",
        "key_id",
        "api_key_id",
        "api_key_name",
        "has_secret",
        "has_signing_secret",
        "token_type",
        "token_count",
        "primary_key",
        "foreign_key",
        "sort_key",
        "secret_hint",
        "public_key_fingerprint",
        "ssh_key_fingerprint",
        "key_algorithm",
        "key_length",
        "key_bits",
    }
)

_INLINE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9_\-=]+\$[A-Za-z0-9_\-=]+"),
    re.compile(r"\bnpm_[A-Za-z0-9]{4,}_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{16,}\b"),
)

#: Action identifiers classified as authentication / security-sensitive events.
AUTH_AUDIT_ACTIONS: frozenset[str] = frozenset(
    {
        AuditAction.LOGIN.value,
        AuditAction.LOGOUT.value,
        AuditAction.LOGIN_FAILED.value,
        AuditAction.TOKEN_REFRESH.value,
        AuditAction.SESSION_REVOKE.value,
        AuditAction.PASSWORD_CHANGE.value,
        AuditAction.MFA_ENABLE.value,
        AuditAction.MFA_DISABLE.value,
        AuditAction.API_KEY_CREATE.value,
        AuditAction.API_KEY_REVOKE.value,
        AuditAction.PERMISSION_CHANGE.value,
    }
)

MUTATION_AUDIT_ACTIONS: frozenset[str] = frozenset(
    {
        AuditAction.CREATE.value,
        AuditAction.UPDATE.value,
        AuditAction.DELETE.value,
        AuditAction.RESTORE.value,
        AuditAction.SETTINGS_UPDATE.value,
        AuditAction.PERMISSION_CHANGE.value,
        AuditAction.CREDENTIAL_ROTATE.value,
        AuditAction.CONFIG_RESTORE.value,
    }
)

CSV_EXPORT_COLUMNS: tuple[str, ...] = (
    "id",
    "created_at",
    "org_id",
    "actor_user_id",
    "actor_email",
    "action",
    "resource_type",
    "resource_id",
    "summary",
    "ip_address",
    "user_agent",
    "request_id",
    "changed_fields",
)

_CSV_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------------------
# Pure redaction, normalization, and diffing helpers
# ---------------------------------------------------------------------------


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` if *key* represents a sensitive credential or secret field."""
    normalized = key.strip().lower()
    if not normalized or normalized in SAFE_KEY_ALLOWLIST:
        return False
    return any(token in normalized for token in SENSITIVE_KEY_TOKENS)


def _normalize_scalar(value: Any) -> Any:
    """Convert non-JSON-native scalar objects into deterministic JSON-safe values."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        return redact_inline_secrets(value)
    return str(value)


def redact_inline_secrets(text: str) -> str:
    """Mask embedded hashes, JWTs, API keys, and bearer strings inside plain text."""
    result = text
    for pattern in _INLINE_SECRET_PATTERNS:
        result = pattern.sub(REDACTED_VALUE, result)
    return result


def redact_state(
    data: Any,
    *,
    max_depth: int = 10,
    _depth: int = 0,
) -> Any:
    """Recursively sanitize a state snapshot by redacting sensitive keys and tokens.

    Args:
        data: Arbitrary mapping, sequence, or scalar representing entity state.
        max_depth: Maximum nesting depth to prevent pathological recursion.

    Returns:
        JSON-serializable copy of *data* with all sensitive values replaced by
        :data:`REDACTED_VALUE`.
    """
    if data is None:
        return None
    if _depth >= max_depth:
        return "<max_depth_reached>"

    if isinstance(data, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_key, raw_val in data.items():
            key_str = str(raw_key)
            if is_sensitive_key(key_str):
                sanitized[key_str] = REDACTED_VALUE if raw_val is not None else None
            else:
                sanitized[key_str] = redact_state(raw_val, max_depth=max_depth, _depth=_depth + 1)
        return sanitized

    if isinstance(data, (list, tuple, set, frozenset)):
        return [redact_state(item, max_depth=max_depth, _depth=_depth + 1) for item in data]

    return _normalize_scalar(data)


def compute_state_diff(
    before_state: Mapping[str, Any] | None,
    after_state: Mapping[str, Any] | None,
    *,
    redact: bool = True,
    flatten_nested: bool = False,
) -> dict[str, dict[str, Any]]:
    """Compute a structured field-level diff between *before_state* and *after_state*.

    Args:
        before_state: Snapshot prior to the mutation (or ``None`` on creation).
        after_state: Snapshot after the mutation (or ``None`` on deletion).
        redact: When ``True`` (default), recursively redact sensitive keys first.
        flatten_nested: When ``True``, emit dot-delimited paths for changed nested
            dictionary keys (e.g. ``"settings.timezone"``).

    Returns:
        Dictionary keyed by changed field name containing ``{"before", "after", "change_type"}``.
    """
    before_clean: dict[str, Any] = (
        redact_state(before_state) if (redact and before_state is not None) else dict(before_state or {})
    )
    after_clean: dict[str, Any] = (
        redact_state(after_state) if (redact and after_state is not None) else dict(after_state or {})
    )

    if flatten_nested:
        return _compute_nested_diff(before_clean, after_clean, prefix="")

    diff: dict[str, dict[str, Any]] = {}
    all_keys = sorted(set(before_clean.keys()) | set(after_clean.keys()))
    for key in all_keys:
        in_before = key in before_clean
        in_after = key in after_clean
        old_val = before_clean.get(key)
        new_val = after_clean.get(key)

        if not in_before and in_after:
            diff[key] = {"before": None, "after": new_val, "change_type": "added"}
        elif in_before and not in_after:
            diff[key] = {"before": old_val, "after": None, "change_type": "removed"}
        elif old_val != new_val:
            diff[key] = {"before": old_val, "after": new_val, "change_type": "modified"}
    return diff


def _compute_nested_diff(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    prefix: str,
) -> dict[str, dict[str, Any]]:
    diff: dict[str, dict[str, Any]] = {}
    all_keys = sorted(set(before.keys()) | set(after.keys()))
    for key in all_keys:
        path = f"{prefix}.{key}" if prefix else key
        in_before = key in before
        in_after = key in after
        old_val = before.get(key)
        new_val = after.get(key)

        if in_before and in_after and isinstance(old_val, Mapping) and isinstance(new_val, Mapping):
            diff.update(_compute_nested_diff(old_val, new_val, prefix=path))
        elif not in_before and in_after:
            diff[path] = {"before": None, "after": new_val, "change_type": "added"}
        elif in_before and not in_after:
            diff[path] = {"before": old_val, "after": None, "change_type": "removed"}
        elif old_val != new_val:
            diff[path] = {"before": old_val, "after": new_val, "change_type": "modified"}
    return diff


def _sanitize_csv_cell(value: Any) -> str:
    """Convert *value* to a CSV-safe string, neutralizing spreadsheet formula prefixes."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return f"'{text}"
    return text


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Structured result containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditRecordResult:
    """Bundle pairing the persisted :class:`AuditLog` row with its computed diff."""

    audit_log: AuditLog
    changed_fields: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = self.audit_log.to_event_dict()
        payload["changed_fields"] = self.changed_fields
        return payload


@dataclass(frozen=True, slots=True)
class ActorActivityStat:
    """Aggregated audit volume and recency statistics for a single actor."""

    actor_user_id: str | None
    actor_email: str
    event_count: int
    distinct_actions: int
    last_activity_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_user_id": self.actor_user_id,
            "actor_email": self.actor_email,
            "event_count": self.event_count,
            "distinct_actions": self.distinct_actions,
            "last_activity_at": (
                self.last_activity_at.isoformat() if self.last_activity_at else None
            ),
        }


@dataclass(frozen=True, slots=True)
class DailyAuditVolume:
    """Daily event count breakdown for audit trend visualizations."""

    date: str
    total: int
    auth_events: int
    mutation_events: int
    other_events: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "date": self.date,
            "total": self.total,
            "auth_events": self.auth_events,
            "mutation_events": self.mutation_events,
            "other_events": self.other_events,
        }


@dataclass(frozen=True, slots=True)
class AuditActivitySummary:
    """Organization-wide audit analytics summary over a bounded time window."""

    org_id: str
    window_start: datetime
    window_end: datetime
    total_events: int
    unique_actors: int
    unique_ips: int
    actions_by_type: dict[str, int]
    resources_by_type: dict[str, int]
    top_actors: list[ActorActivityStat]
    daily_volume: list[DailyAuditVolume]
    security_highlights: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "total_events": self.total_events,
            "unique_actors": self.unique_actors,
            "unique_ips": self.unique_ips,
            "actions_by_type": dict(self.actions_by_type),
            "resources_by_type": dict(self.resources_by_type),
            "top_actors": [actor.to_dict() for actor in self.top_actors],
            "daily_volume": [day.to_dict() for day in self.daily_volume],
            "security_highlights": dict(self.security_highlights),
        }


# ---------------------------------------------------------------------------
# AuditService
# ---------------------------------------------------------------------------


class AuditService:
    """Business-logic service for compliance audit recording, search, export, and analytics."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repo = AuditLogRepository(db)

    # ── Recording ────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        org_id: str,
        action: AuditAction | str,
        resource_type: str,
        resource_id: str | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        summary: str | None = None,
        before_state: Mapping[str, Any] | None = None,
        after_state: Mapping[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        flush: bool = True,
        commit: bool = False,
    ) -> AuditLog:
        """Persist a redacted, diff-enriched immutable :class:`AuditLog` entry.

        Sensitive keys (passwords, secrets, tokens, API keys, SNMP communities) in
        ``before_state`` and ``after_state`` are recursively masked prior to storage.
        When ``summary`` is omitted, a descriptive summary referencing changed fields
        is automatically generated.
        """
        action_str = action.value if isinstance(action, AuditAction) else str(action).strip().lower()
        if not action_str:
            raise ValidationError("Audit action must not be empty")
        resource_str = resource_type.strip().lower()
        if not resource_str:
            raise ValidationError("Audit resource_type must not be empty")

        sanitized_before: dict[str, Any] | None = (
            redact_state(before_state) if before_state is not None else None
        )
        sanitized_after: dict[str, Any] | None = (
            redact_state(after_state) if after_state is not None else None
        )

        diff = compute_state_diff(sanitized_before, sanitized_after, redact=False)
        resolved_summary = self._build_summary(
            summary=summary,
            action=action_str,
            resource_type=resource_str,
            resource_id=resource_id,
            diff=diff,
        )
        resolved_request_id = request_id or get_request_id()

        entry = self.repo.record(
            org_id=org_id,
            action=action_str,
            resource_type=resource_str,
            resource_id=resource_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email.strip().lower() if actor_email else None,
            summary=resolved_summary,
            before_state=sanitized_before,
            after_state=sanitized_after,
            ip_address=ip_address.strip() if ip_address else None,
            user_agent=user_agent[:512] if user_agent else None,
            request_id=resolved_request_id[:64] if resolved_request_id else None,
            flush=flush or commit,
        )
        if commit:
            self.db.commit()

        logger.debug(
            "Recorded audit event action=%s resource=%s:%s org_id=%s changed_fields=%d",
            action_str,
            resource_str,
            resource_id or "-",
            org_id,
            len(diff),
        )
        return entry

    def record_with_diff(
        self,
        *,
        org_id: str,
        action: AuditAction | str,
        resource_type: str,
        resource_id: str | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        summary: str | None = None,
        before_state: Mapping[str, Any] | None = None,
        after_state: Mapping[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        flatten_nested: bool = False,
        flush: bool = True,
        commit: bool = False,
    ) -> AuditRecordResult:
        """Record an audit log and return both the ORM row and computed field diff."""
        entry = self.record(
            org_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            summary=summary,
            before_state=before_state,
            after_state=after_state,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            flush=flush,
            commit=commit,
        )
        diff = compute_state_diff(
            entry.before_state,
            entry.after_state,
            redact=False,
            flatten_nested=flatten_nested,
        )
        return AuditRecordResult(audit_log=entry, changed_fields=diff)

    @staticmethod
    def _build_summary(
        *,
        summary: str | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        diff: Mapping[str, Any],
    ) -> str:
        if summary and summary.strip():
            return redact_inline_secrets(summary.strip())
        base = f"{action} on {resource_type}"
        if resource_id:
            base = f"{base} ({resource_id})"
        if diff:
            changed_keys = ", ".join(list(diff.keys())[:8])
            suffix = f" (+{len(diff) - 8} more)" if len(diff) > 8 else ""
            return f"{base}: changed [{changed_keys}{suffix}]"
        return base

    # ── Querying & Filtering ─────────────────────────────────────────────────

    def get_by_id(self, audit_id: str, *, org_id: str) -> AuditLog:
        """Fetch a single tenant-scoped audit log entry or raise :class:`NotFoundError`."""
        entry = self.repo.get_by_id(audit_id, org_id=org_id)
        if entry is None:
            raise NotFoundError(
                f"Audit log '{audit_id}' was not found",
                details={"entity": "AuditLog", "id": audit_id, "org_id": org_id},
            )
        return entry

    def _build_filtered_stmt(
        self,
        *,
        org_id: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        actions: Sequence[str] | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
    ) -> Any:
        since_utc = _as_utc(since)
        until_utc = _as_utc(until)
        if since_utc is not None and until_utc is not None and since_utc > until_utc:
            raise ValidationError(
                "'since' timestamp must be earlier than or equal to 'until'",
                details={"since": since_utc.isoformat(), "until": until_utc.isoformat()},
            )

        stmt = select(AuditLog).where(AuditLog.org_id == org_id)

        if actor_user_id:
            stmt = stmt.where(AuditLog.actor_user_id == actor_user_id)
        if actor_email:
            stmt = stmt.where(func.lower(AuditLog.actor_email) == actor_email.strip().lower())
        if action:
            stmt = stmt.where(AuditLog.action == action.strip().lower())
        if action_prefix:
            stmt = stmt.where(AuditLog.action.ilike(f"{action_prefix.strip().lower()}%"))
        if actions:
            normalized_actions = [a.strip().lower() for a in actions if a and a.strip()]
            if normalized_actions:
                stmt = stmt.where(AuditLog.action.in_(normalized_actions))
        if resource_type:
            stmt = stmt.where(AuditLog.resource_type == resource_type.strip().lower())
        if resource_id:
            stmt = stmt.where(AuditLog.resource_id == resource_id)
        if ip_address:
            stmt = stmt.where(AuditLog.ip_address == ip_address.strip())
        if request_id:
            stmt = stmt.where(AuditLog.request_id == request_id.strip())
        if since_utc is not None:
            stmt = stmt.where(AuditLog.created_at >= since_utc)
        if until_utc is not None:
            stmt = stmt.where(AuditLog.created_at <= until_utc)
        if search and search.strip():
            pattern = f"%{search.strip()}%"
            stmt = stmt.where(
                or_(
                    AuditLog.action.ilike(pattern),
                    AuditLog.resource_type.ilike(pattern),
                    AuditLog.resource_id.ilike(pattern),
                    AuditLog.actor_email.ilike(pattern),
                    AuditLog.summary.ilike(pattern),
                    AuditLog.ip_address.ilike(pattern),
                    AuditLog.request_id.ilike(pattern),
                )
            )
        return stmt

    def query_logs(
        self,
        *,
        org_id: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        actions: Sequence[str] | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
        sort_order: SortOrder | str = SortOrder.DESC,
    ) -> PageResult[AuditLog]:
        """Search, filter, sort, and paginate organization audit logs."""
        if page < 1:
            raise ValidationError("page must be >= 1", details={"page": page})
        if page_size < 1 or page_size > 500:
            raise ValidationError(
                "page_size must be between 1 and 500",
                details={"page_size": page_size},
            )

        stmt = self._build_filtered_stmt(
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            action_prefix=action_prefix,
            actions=actions,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            request_id=request_id,
            since=since,
            until=until,
            search=search,
        )

        total = int(
            self.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        )
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0

        order_val = sort_order.value if isinstance(sort_order, SortOrder) else str(sort_order).lower()
        order_col = AuditLog.created_at.asc() if order_val == "asc" else AuditLog.created_at.desc()
        ordered = stmt.order_by(order_col, AuditLog.id.desc())
        paginated = ordered.offset((page - 1) * page_size).limit(page_size)
        items = list(self.db.execute(paginated).scalars().all())

        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def query_from_schema(self, org_id: str, query: AuditLogQuery) -> PageResult[AuditLog]:
        """Execute an audit log query directly from an :class:`AuditLogQuery` Pydantic model."""
        return self.query_logs(
            org_id=org_id,
            actor_user_id=query.actor_user_id,
            action=query.action,
            action_prefix=query.action_prefix,
            resource_type=query.resource_type,
            resource_id=query.resource_id,
            ip_address=query.source_ip,
            since=query.start,
            until=query.end,
            search=query.search,
            page=query.page,
            page_size=query.page_size,
            sort_order=query.sort_order,
        )

    def get_resource_history(
        self,
        *,
        org_id: str,
        resource_type: str,
        resource_id: str,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Return chronological audit history (most recent first) for a single entity."""
        clamped_limit = max(1, min(limit, 500))
        return self.repo.list_for_resource(
            resource_type.strip().lower(),
            resource_id,
            limit=clamped_limit,
            org_id=org_id,
        )

    def get_actor_history(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Return recent audit events performed by a specific user."""
        clamped_limit = max(1, min(limit, 500))
        page = self.query_logs(
            org_id=org_id,
            actor_user_id=actor_user_id,
            page=1,
            page_size=clamped_limit,
        )
        return page.items

    # ── Export (CSV & JSONL) ─────────────────────────────────────────────────

    def _fetch_for_export(
        self,
        *,
        org_id: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        max_rows: int = 10_000,
        sort_order: SortOrder | str = SortOrder.DESC,
    ) -> list[AuditLog]:
        if max_rows < 1 or max_rows > 100_000:
            raise ValidationError(
                "max_rows must be between 1 and 100000",
                details={"max_rows": max_rows},
            )
        stmt = self._build_filtered_stmt(
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            action_prefix=action_prefix,
            resource_type=resource_type,
            resource_id=resource_id,
            since=since,
            until=until,
            search=search,
        )
        order_val = sort_order.value if isinstance(sort_order, SortOrder) else str(sort_order).lower()
        order_col = AuditLog.created_at.asc() if order_val == "asc" else AuditLog.created_at.desc()
        stmt = stmt.order_by(order_col, AuditLog.id.desc()).limit(max_rows)
        return list(self.db.execute(stmt).scalars().all())

    def export_csv(
        self,
        *,
        org_id: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        max_rows: int = 10_000,
        sort_order: SortOrder | str = SortOrder.DESC,
    ) -> str:
        """Export matching audit log entries as an RFC-4180 CSV string."""
        rows = self._fetch_for_export(
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            action_prefix=action_prefix,
            resource_type=resource_type,
            resource_id=resource_id,
            since=since,
            until=until,
            search=search,
            max_rows=max_rows,
            sort_order=sort_order,
        )
        return self.serialize_logs_to_csv(rows)

    def serialize_logs_to_csv(self, logs: Iterable[AuditLog]) -> str:
        """Serialize an iterable of :class:`AuditLog` rows into a CSV document."""
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=list(CSV_EXPORT_COLUMNS),
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writeheader()
        for entry in logs:
            diff = compute_state_diff(entry.before_state, entry.after_state, redact=True)
            writer.writerow(
                {
                    "id": _sanitize_csv_cell(entry.id),
                    "created_at": (
                        entry.created_at.isoformat() if entry.created_at else ""
                    ),
                    "org_id": _sanitize_csv_cell(entry.org_id),
                    "actor_user_id": _sanitize_csv_cell(entry.actor_user_id),
                    "actor_email": _sanitize_csv_cell(entry.actor_email),
                    "action": _sanitize_csv_cell(entry.action),
                    "resource_type": _sanitize_csv_cell(entry.resource_type),
                    "resource_id": _sanitize_csv_cell(entry.resource_id),
                    "summary": _sanitize_csv_cell(entry.summary),
                    "ip_address": _sanitize_csv_cell(entry.ip_address),
                    "user_agent": _sanitize_csv_cell(entry.user_agent),
                    "request_id": _sanitize_csv_cell(entry.request_id),
                    "changed_fields": json.dumps(diff, sort_keys=True, default=str),
                }
            )
        return buffer.getvalue()

    def export_jsonl(
        self,
        *,
        org_id: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        max_rows: int = 10_000,
        sort_order: SortOrder | str = SortOrder.DESC,
        include_states: bool = True,
    ) -> str:
        """Export matching audit log entries as newline-delimited JSON (JSONL)."""
        rows = self._fetch_for_export(
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            action_prefix=action_prefix,
            resource_type=resource_type,
            resource_id=resource_id,
            since=since,
            until=until,
            search=search,
            max_rows=max_rows,
            sort_order=sort_order,
        )
        return "\n".join(self.iter_serialize_jsonl(rows, include_states=include_states))

    def iter_serialize_jsonl(
        self,
        logs: Iterable[AuditLog],
        *,
        include_states: bool = True,
    ) -> Iterator[str]:
        """Yield one compact JSON line per :class:`AuditLog` record for SIEM streaming."""
        for entry in logs:
            before_safe = redact_state(entry.before_state) if entry.before_state is not None else None
            after_safe = redact_state(entry.after_state) if entry.after_state is not None else None
            record: dict[str, Any] = {
                "id": entry.id,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
                "org_id": entry.org_id,
                "actor_user_id": entry.actor_user_id,
                "actor_email": entry.actor_email,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "summary": entry.summary,
                "changed_fields": compute_state_diff(before_safe, after_safe, redact=False),
                "ip_address": entry.ip_address,
                "user_agent": entry.user_agent,
                "request_id": entry.request_id,
            }
            if include_states:
                record["before_state"] = before_safe
                record["after_state"] = after_safe
            yield json.dumps(record, separators=(",", ":"), sort_keys=True, default=str)

    # ── Activity Summary Analytics ───────────────────────────────────────────

    def get_activity_summary(
        self,
        *,
        org_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        days: int = 30,
        top_actors_limit: int = 10,
    ) -> AuditActivitySummary:
        """Compute activity summary analytics: actions by type, top actors, and daily volume."""
        if days < 1 or days > 365:
            raise ValidationError("days must be between 1 and 365", details={"days": days})
        if top_actors_limit < 1 or top_actors_limit > 100:
            raise ValidationError(
                "top_actors_limit must be between 1 and 100",
                details={"top_actors_limit": top_actors_limit},
            )

        now = utcnow()
        window_end = _as_utc(until) or now
        window_start = _as_utc(since) or (window_end - timedelta(days=days))
        if window_start > window_end:
            raise ValidationError(
                "'since' must be earlier than or equal to 'until'",
                details={
                    "since": window_start.isoformat(),
                    "until": window_end.isoformat(),
                },
            )

        stmt = (
            select(
                AuditLog.action,
                AuditLog.resource_type,
                AuditLog.actor_user_id,
                AuditLog.actor_email,
                AuditLog.ip_address,
                AuditLog.created_at,
            )
            .where(
                and_(
                    AuditLog.org_id == org_id,
                    AuditLog.created_at >= window_start,
                    AuditLog.created_at <= window_end,
                )
            )
        )
        rows = self.db.execute(stmt).all()

        action_counts: Counter[str] = Counter()
        resource_counts: Counter[str] = Counter()
        unique_ips: set[str] = set()
        actor_counts: Counter[tuple[str | None, str]] = Counter()
        actor_actions: dict[tuple[str | None, str], set[str]] = defaultdict(set)
        actor_last_seen: dict[tuple[str | None, str], datetime] = {}

        # Daily bucket tracking: date_str -> [total, auth, mutation, other]
        daily_buckets: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])

        security_highlights: dict[str, int] = {
            "login_success": 0,
            "login_failed": 0,
            "password_changes": 0,
            "permission_changes": 0,
            "api_key_events": 0,
            "session_revocations": 0,
        }

        for act, res_type, actor_uid, actor_email, ip_addr, created_at in rows:
            act_str = str(act)
            res_str = str(res_type)
            action_counts[act_str] += 1
            resource_counts[res_str] += 1

            if ip_addr:
                unique_ips.add(str(ip_addr))

            actor_label = actor_email or (f"user:{actor_uid}" if actor_uid else "system")
            actor_key = (actor_uid, actor_label)
            actor_counts[actor_key] += 1
            actor_actions[actor_key].add(act_str)

            ts = _as_utc(created_at)
            if ts is not None:
                prev = actor_last_seen.get(actor_key)
                if prev is None or ts > prev:
                    actor_last_seen[actor_key] = ts
                day_str = ts.date().isoformat()
                bucket = daily_buckets[day_str]
                bucket[0] += 1
                if act_str in AUTH_AUDIT_ACTIONS:
                    bucket[1] += 1
                elif act_str in MUTATION_AUDIT_ACTIONS:
                    bucket[2] += 1
                else:
                    bucket[3] += 1

            if act_str == AuditAction.LOGIN.value:
                security_highlights["login_success"] += 1
            elif act_str == AuditAction.LOGIN_FAILED.value:
                security_highlights["login_failed"] += 1
            elif act_str == AuditAction.PASSWORD_CHANGE.value:
                security_highlights["password_changes"] += 1
            elif act_str == AuditAction.PERMISSION_CHANGE.value:
                security_highlights["permission_changes"] += 1
            elif act_str in {AuditAction.API_KEY_CREATE.value, AuditAction.API_KEY_REVOKE.value}:
                security_highlights["api_key_events"] += 1
            elif act_str == AuditAction.SESSION_REVOKE.value:
                security_highlights["session_revocations"] += 1

        # Build sorted top actors list
        top_actors: list[ActorActivityStat] = []
        for actor_key, count in actor_counts.most_common(top_actors_limit):
            actor_uid, actor_label = actor_key
            top_actors.append(
                ActorActivityStat(
                    actor_user_id=actor_uid,
                    actor_email=actor_label,
                    event_count=count,
                    distinct_actions=len(actor_actions[actor_key]),
                    last_activity_at=actor_last_seen.get(actor_key),
                )
            )

        # Build contiguous daily series across the full date window (capped at 366 days)
        start_day = window_start.date()
        end_day = window_end.date()
        span_days = min(366, max(0, (end_day - start_day).days) + 1)
        daily_volume: list[DailyAuditVolume] = []
        for offset in range(span_days):
            day = start_day + timedelta(days=offset)
            day_str = day.isoformat()
            counts = daily_buckets.get(day_str, [0, 0, 0, 0])
            daily_volume.append(
                DailyAuditVolume(
                    date=day_str,
                    total=counts[0],
                    auth_events=counts[1],
                    mutation_events=counts[2],
                    other_events=counts[3],
                )
            )

        sorted_actions = dict(sorted(action_counts.items(), key=lambda kv: (-kv[1], kv[0])))
        sorted_resources = dict(sorted(resource_counts.items(), key=lambda kv: (-kv[1], kv[0])))

        return AuditActivitySummary(
            org_id=org_id,
            window_start=window_start,
            window_end=window_end,
            total_events=len(rows),
            unique_actors=len(actor_counts),
            unique_ips=len(unique_ips),
            actions_by_type=sorted_actions,
            resources_by_type=sorted_resources,
            top_actors=top_actors,
            daily_volume=daily_volume,
            security_highlights=security_highlights,
        )

    # ── Retention & Housekeeping ─────────────────────────────────────────────

    def purge_expired_logs(
        self,
        *,
        org_id: str,
        retention_days: int | None = None,
        commit: bool = True,
    ) -> int:
        """Delete audit entries older than the organization or platform retention window."""
        effective_days = (
            retention_days
            if retention_days is not None
            else get_settings().retention.audit_log_days
        )
        if effective_days < 1:
            raise ValidationError(
                "retention_days must be at least 1",
                details={"retention_days": effective_days},
            )
        cutoff = utcnow() - timedelta(days=effective_days)
        deleted = self.repo.purge_older_than(cutoff, org_id=org_id, flush=True)
        if commit:
            self.db.commit()
        return deleted


__all__ = [
    "AUTH_AUDIT_ACTIONS",
    "ActorActivityStat",
    "AuditActivitySummary",
    "AuditRecordResult",
    "AuditService",
    "CSV_EXPORT_COLUMNS",
    "DailyAuditVolume",
    "MUTATION_AUDIT_ACTIONS",
    "REDACTED_VALUE",
    "SAFE_KEY_ALLOWLIST",
    "SENSITIVE_KEY_TOKENS",
    "compute_state_diff",
    "is_sensitive_key",
    "redact_inline_secrets",
    "redact_state",
]
