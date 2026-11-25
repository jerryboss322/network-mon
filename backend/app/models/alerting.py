"""Alerting, incident management, on-call, notifications, maintenance, and SLO ORM models.

Implements the operational reliability and incident response schema for NetPulse:
- ``EscalationPolicy``: Multi-step escalation tiers with repeat counts.
- ``AlertRule``: Threshold, anomaly, composite, and SLO-burn alert rule definitions.
- ``MaintenanceWindow``: Time-bounded maintenance schedules with device/site/tag alert suppression.
- ``Incident`` & ``IncidentTimelineEntry``: Full incident lifecycle tracking with MTTA/MTTR and audit log.
- ``AlertEvent``: Deduplicated firing/acknowledged/suppressed/resolved alert instances.
- ``OnCallSchedule``: Timezone-aware rotation schedules with deterministic on-call resolution.
- ``NotificationChannel`` & ``NotificationDelivery``: Encrypted outbound connectors and delivery audit log.
- ``SloDefinition``: Service Level Objectives with automated SLI, error-budget, and burn-rate calculations.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    utcnow,
)

# ---------------------------------------------------------------------------
# Alerting & Incident Domain Constants
# ---------------------------------------------------------------------------

VALID_RULE_TYPES: frozenset[str] = frozenset(
    {"threshold", "anomaly", "composite", "availability", "syslog", "bgp", "slo_burn"}
)

VALID_OPERATORS: frozenset[str] = frozenset({"gt", "gte", "lt", "lte", "eq", "neq"})

VALID_SEVERITIES: frozenset[str] = frozenset({"info", "warning", "critical", "emergency"})

SEVERITY_RANK: dict[str, int] = {
    "info": 1,
    "warning": 2,
    "critical": 3,
    "emergency": 4,
}

VALID_ALERT_STATUSES: frozenset[str] = frozenset(
    {"firing", "acknowledged", "suppressed", "resolved"}
)

VALID_INCIDENT_STATUSES: frozenset[str] = frozenset(
    {"open", "investigating", "identified", "monitoring", "resolved", "closed"}
)

VALID_INCIDENT_PRIORITIES: frozenset[str] = frozenset({"P1", "P2", "P3", "P4"})

VALID_CHANNEL_TYPES: frozenset[str] = frozenset(
    {"email", "slack", "webhook", "pagerduty", "teams", "opsgenie", "sms", "discord"}
)

VALID_DELIVERY_STATUSES: frozenset[str] = frozenset(
    {"pending", "sent", "failed", "retrying", "suppressed"}
)

VALID_ROTATION_TYPES: frozenset[str] = frozenset({"daily", "weekly", "biweekly", "monthly", "custom"})

ROTATION_PERIOD_DAYS: dict[str, int] = {
    "daily": 1,
    "weekly": 7,
    "biweekly": 14,
    "monthly": 30,
    "custom": 7,
}

VALID_SLO_STATUSES: frozenset[str] = frozenset({"healthy", "at_risk", "breached", "no_data"})


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_json_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("Expected JSON object.")
    raise ValueError(f"Unsupported type {type(value).__name__} for JSON object.")


def _coerce_json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        raise ValueError("Expected JSON array.")
    raise ValueError(f"Unsupported type {type(value).__name__} for JSON array.")


def _compare_threshold(operator: str, value: float, threshold: float) -> bool:
    if operator == "gt":
        return value > threshold
    if operator == "gte":
        return value >= threshold
    if operator == "lt":
        return value < threshold
    if operator == "lte":
        return value <= threshold
    if operator == "eq":
        return value == threshold
    if operator == "neq":
        return value != threshold
    raise ValueError(f"Unsupported operator '{operator}'.")


# ---------------------------------------------------------------------------
# Escalation Policies
# ---------------------------------------------------------------------------


class EscalationPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Multi-tier escalation routing policy for unacknowledged alerts and incidents."""

    __tablename__ = "escalation_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_escalation_policy_org_name"),
        CheckConstraint("repeat_count >= 0", name="escalation_repeat_non_negative"),
        Index("ix_escalation_policies_org_default", "org_id", "is_default"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    repeat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    steps_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    @validates("steps_json")
    def _validate_steps(self, _key: str, value: Any) -> list[dict[str, Any]]:
        items = _coerce_json_list(value)
        return [dict(item) if isinstance(item, dict) else {"target": item} for item in items]

    @property
    def step_count(self) -> int:
        return len(self.steps_json or [])

    def get_step(self, level: int) -> dict[str, Any] | None:
        """Retrieve a zero-indexed escalation step, returning None if out of bounds."""
        steps = self.steps_json or []
        if 0 <= level < len(steps):
            return steps[level]
        return None

    def total_escalation_minutes(self) -> int:
        """Sum delay_minutes across all steps for one escalation cycle."""
        return sum(int(step.get("delay_minutes", 0)) for step in (self.steps_json or []))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "repeat_count": self.repeat_count,
            "steps_json": self.steps_json or [],
            "step_count": self.step_count,
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<EscalationPolicy id={self.id!r} name={self.name!r} steps={self.step_count}>"


# ---------------------------------------------------------------------------
# Alert Rules
# ---------------------------------------------------------------------------


class AlertRule(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Metric, anomaly, or composite rule that generates AlertEvents when breached."""

    __tablename__ = "alert_rules"
    __table_args__ = (
        CheckConstraint("evaluation_window_seconds >= 10", name="eval_window_min_10s"),
        CheckConstraint("consecutive_breaches >= 1", name="consecutive_breaches_min_1"),
        CheckConstraint("cooldown_seconds >= 0", name="cooldown_non_negative"),
        Index("ix_alert_rules_org_enabled", "org_id", "enabled"),
        Index("ix_alert_rules_org_metric", "org_id", "metric_name"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False, default="threshold", index=True)
    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    scope_filter_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    operator: Mapped[str] = mapped_column(String(20), nullable=False, default="gt")
    warning_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    critical_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    evaluation_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    consecutive_breaches: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    anomaly_sensitivity: Mapped[float | None] = mapped_column(Float, nullable=True)
    composite_expression: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="warning", index=True)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    auto_resolve: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    runbook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    escalation_policy_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("escalation_policies.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    escalation_policy: Mapped[EscalationPolicy | None] = relationship("EscalationPolicy")
    events: Mapped[list[AlertEvent]] = relationship(
        "AlertEvent",
        back_populates="rule",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("rule_type")
    def _validate_rule_type(self, _key: str, value: str) -> str:
        normalized = (value or "threshold").strip().lower()
        if normalized not in VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type '{value}'. Expected one of {sorted(VALID_RULE_TYPES)}.")
        return normalized

    @validates("operator")
    def _validate_operator(self, _key: str, value: str) -> str:
        normalized = (value or "gt").strip().lower()
        if normalized not in VALID_OPERATORS:
            raise ValueError(f"Invalid operator '{value}'. Expected one of {sorted(VALID_OPERATORS)}.")
        return normalized

    @validates("severity")
    def _validate_severity(self, _key: str, value: str) -> str:
        normalized = (value or "warning").strip().lower()
        if normalized not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{value}'. Expected one of {sorted(VALID_SEVERITIES)}.")
        return normalized

    @validates("scope_filter_json")
    def _validate_scope_filter(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @validates("tags_json")
    def _validate_tags(self, _key: str, value: Any) -> list[str]:
        return [str(t) for t in _coerce_json_list(value)]

    def evaluate_value(self, observed_value: float) -> tuple[str | None, float | None]:
        """Evaluate an observed metric against critical and warning thresholds.

        Returns ``(triggered_severity, threshold_crossed)`` or ``(None, None)`` when healthy.
        """
        op = self.operator or "gt"
        if self.critical_threshold is not None and _compare_threshold(
            op, observed_value, self.critical_threshold
        ):
            sev = "emergency" if self.severity == "emergency" else "critical"
            return sev, self.critical_threshold
        if self.warning_threshold is not None and _compare_threshold(
            op, observed_value, self.warning_threshold
        ):
            return "warning", self.warning_threshold
        return None, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type,
            "metric_name": self.metric_name,
            "scope_filter_json": self.scope_filter_json or {},
            "operator": self.operator,
            "warning_threshold": self.warning_threshold,
            "critical_threshold": self.critical_threshold,
            "evaluation_window_seconds": self.evaluation_window_seconds,
            "consecutive_breaches": self.consecutive_breaches,
            "anomaly_sensitivity": self.anomaly_sensitivity,
            "composite_expression": self.composite_expression,
            "severity": self.severity,
            "cooldown_seconds": self.cooldown_seconds,
            "auto_resolve": self.auto_resolve,
            "enabled": self.enabled,
            "tags_json": self.tags_json or [],
            "runbook_url": self.runbook_url,
            "escalation_policy_id": self.escalation_policy_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<AlertRule id={self.id!r} name={self.name!r} "
            f"metric={self.metric_name!r} enabled={self.enabled}>"
        )


# ---------------------------------------------------------------------------
# Maintenance Windows
# ---------------------------------------------------------------------------


class MaintenanceWindow(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Planned maintenance schedule used to suppress alert noise for scoped assets."""

    __tablename__ = "maintenance_windows"
    __table_args__ = (
        CheckConstraint("ends_at > starts_at", name="maintenance_ends_after_starts"),
        Index("ix_maintenance_org_active_window", "org_id", "is_active", "starts_at", "ends_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_device_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope_site_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope_tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    suppress_alerts: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    @validates("scope_device_ids_json", "scope_site_ids_json", "scope_tags_json")
    def _validate_scope_lists(self, _key: str, value: Any) -> list[str]:
        return [str(v) for v in _coerce_json_list(value)]

    @property
    def duration_minutes(self) -> float:
        start = _ensure_utc(self.starts_at)
        end = _ensure_utc(self.ends_at)
        if start is None or end is None:
            return 0.0
        return round(max(0.0, (end - start).total_seconds() / 60.0), 2)

    def is_in_effect(self, *, at: datetime | None = None) -> bool:
        """Return True when this maintenance window is active at ``at`` (default: now)."""
        if self.is_active is False:
            return False
        ref = _ensure_utc(at) or utcnow()
        start = _ensure_utc(self.starts_at)
        end = _ensure_utc(self.ends_at)
        if start is None or end is None:
            return False
        return start <= ref <= end

    def covers_target(
        self,
        *,
        device_id: str | None = None,
        site_id: str | None = None,
        tags: list[str] | set[str] | None = None,
    ) -> bool:
        """Check whether this window applies to a target device, site, or tag set.

        An empty scope across all three selectors is treated as an organization-wide window.
        """
        dev_scope = set(self.scope_device_ids_json or [])
        site_scope = set(self.scope_site_ids_json or [])
        tag_scope = set(self.scope_tags_json or [])

        if not dev_scope and not site_scope and not tag_scope:
            return True
        if device_id and device_id in dev_scope:
            return True
        if site_id and site_id in site_scope:
            return True
        if tags and (set(tags) & tag_scope):
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "scope_device_ids_json": self.scope_device_ids_json or [],
            "scope_site_ids_json": self.scope_site_ids_json or [],
            "scope_tags_json": self.scope_tags_json or [],
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "duration_minutes": self.duration_minutes,
            "suppress_alerts": self.suppress_alerts,
            "created_by_user_id": self.created_by_user_id,
            "is_active": self.is_active,
            "is_in_effect": self.is_in_effect(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<MaintenanceWindow id={self.id!r} name={self.name!r} "
            f"active={self.is_active} suppress={self.suppress_alerts}>"
        )


# ---------------------------------------------------------------------------
# Incidents & Timelines
# ---------------------------------------------------------------------------


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Correlated operational incident grouping one or more related AlertEvents."""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("org_id", "incident_number", name="uq_incidents_org_number"),
        Index("ix_incidents_org_status_priority", "org_id", "status", "priority"),
        Index("ix_incidents_org_started", "org_id", "started_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_number: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open", index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="P2", index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="critical", index=True)
    root_cause_device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assigned_to_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    escalation_policy_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("escalation_policies.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    affected_device_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mttr_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    postmortem_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    escalation_policy: Mapped[EscalationPolicy | None] = relationship("EscalationPolicy")
    timeline_entries: Mapped[list[IncidentTimelineEntry]] = relationship(
        "IncidentTimelineEntry",
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentTimelineEntry.created_at",
    )
    alerts: Mapped[list[AlertEvent]] = relationship("AlertEvent", back_populates="incident")

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "open").strip().lower()
        if normalized not in VALID_INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid Incident status '{value}'. Expected one of {sorted(VALID_INCIDENT_STATUSES)}."
            )
        return normalized

    @validates("priority")
    def _validate_priority(self, _key: str, value: str) -> str:
        normalized = (value or "P2").strip().upper()
        if normalized not in VALID_INCIDENT_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{value}'. Expected one of {sorted(VALID_INCIDENT_PRIORITIES)}."
            )
        return normalized

    @validates("affected_device_ids_json", "tags_json")
    def _validate_lists(self, _key: str, value: Any) -> list[str]:
        return [str(item) for item in _coerce_json_list(value)]

    @property
    def is_open(self) -> bool:
        return self.status not in {"resolved", "closed"}

    @property
    def mtta_seconds(self) -> int | None:
        """Mean Time To Acknowledge in seconds."""
        start = _ensure_utc(self.started_at)
        ack = _ensure_utc(self.acknowledged_at)
        if start is None or ack is None:
            return None
        return max(0, int((ack - start).total_seconds()))

    def acknowledge(self, *, user_id: str | None = None, at: datetime | None = None) -> None:
        now = at or utcnow()
        if self.acknowledged_at is None:
            self.acknowledged_at = now
        if self.status == "open":
            self.status = "investigating"
        if user_id and not self.assigned_to_user_id:
            self.assigned_to_user_id = user_id

    def resolve(self, *, at: datetime | None = None) -> None:
        now = at or utcnow()
        self.status = "resolved"
        self.resolved_at = now
        if self.started_at is None:
            self.started_at = now
        start = _ensure_utc(self.started_at)
        end = _ensure_utc(now)
        if start is not None and end is not None:
            self.mttr_seconds = max(0, int((end - start).total_seconds()))

    def reopen(self) -> None:
        self.status = "open"
        self.resolved_at = None
        self.mttr_seconds = None

    def add_affected_device(self, device_id: str) -> None:
        current = list(self.affected_device_ids_json or [])
        if device_id not in current:
            current.append(device_id)
            self.affected_device_ids_json = current

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "incident_number": self.incident_number,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "severity": self.severity,
            "root_cause_device_id": self.root_cause_device_id,
            "assigned_to_user_id": self.assigned_to_user_id,
            "escalation_policy_id": self.escalation_policy_id,
            "affected_device_ids_json": self.affected_device_ids_json or [],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "mtta_seconds": self.mtta_seconds,
            "mttr_seconds": self.mttr_seconds,
            "postmortem_markdown": self.postmortem_markdown,
            "tags_json": self.tags_json or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id!r} number={self.incident_number!r} "
            f"status={self.status!r} priority={self.priority!r}>"
        )


class IncidentTimelineEntry(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Immutable audit/activity entry attached to an incident timeline."""

    __tablename__ = "incident_timeline_entries"
    __table_args__ = (
        Index("ix_incident_timeline_incident_created", "incident_id", "created_at"),
        Index("ix_incident_timeline_org_type", "org_id", "entry_type"),
    )

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    entry_type: Mapped[str] = mapped_column(String(50), nullable=False, default="comment")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    incident: Mapped[Incident] = relationship("Incident", back_populates="timeline_entries")

    @validates("metadata_json")
    def _validate_metadata(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "org_id": self.org_id,
            "author_user_id": self.author_user_id,
            "entry_type": self.entry_type,
            "content": self.content,
            "metadata_json": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<IncidentTimelineEntry id={self.id!r} incident_id={self.incident_id!r} "
            f"type={self.entry_type!r}>"
        )


# ---------------------------------------------------------------------------
# Alert Events
# ---------------------------------------------------------------------------


class AlertEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Stateful alert instance fired by an AlertRule against a device or service."""

    __tablename__ = "alert_events"
    __table_args__ = (
        Index("ix_alert_events_org_status_sev", "org_id", "status", "severity"),
        Index("ix_alert_events_org_fp_status", "org_id", "fingerprint", "status"),
        Index("ix_alert_events_org_device_ts", "org_id", "device_id", "triggered_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("alert_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="firing", index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="warning", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metric_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    metric_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    threshold_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    labels_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppressed_by_maintenance_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    rule: Mapped[AlertRule] = relationship("AlertRule", back_populates="events")
    incident: Mapped[Incident | None] = relationship("Incident", back_populates="alerts")
    maintenance_window: Mapped[MaintenanceWindow | None] = relationship("MaintenanceWindow")

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "firing").strip().lower()
        if normalized not in VALID_ALERT_STATUSES:
            raise ValueError(
                f"Invalid AlertEvent status '{value}'. Expected one of {sorted(VALID_ALERT_STATUSES)}."
            )
        return normalized

    @validates("labels_json")
    def _validate_labels(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @property
    def is_active(self) -> bool:
        return self.status in {"firing", "acknowledged"}

    @property
    def duration_seconds(self) -> float:
        start = _ensure_utc(self.triggered_at)
        if start is None:
            return 0.0
        end = _ensure_utc(self.resolved_at) or utcnow()
        return round(max(0.0, (end - start).total_seconds()), 2)

    @staticmethod
    def build_fingerprint(
        org_id: str,
        rule_id: str,
        device_id: str | None = None,
        labels: dict[str, Any] | None = None,
    ) -> str:
        """Deterministic deduplication fingerprint for alert grouping."""
        sorted_labels = json.dumps(labels or {}, sort_keys=True, separators=(",", ":"))
        raw = f"{org_id}|{rule_id}|{device_id or 'global'}|{sorted_labels}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]

    def acknowledge(self, actor: str, *, at: datetime | None = None) -> None:
        self.status = "acknowledged"
        self.acknowledged_by = actor
        self.acknowledged_at = at or utcnow()

    def resolve(self, *, at: datetime | None = None) -> None:
        self.status = "resolved"
        self.resolved_at = at or utcnow()

    def suppress(self, maintenance_window_id: str) -> None:
        self.status = "suppressed"
        self.suppressed_by_maintenance_id = maintenance_window_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "rule_id": self.rule_id,
            "device_id": self.device_id,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold_value": self.threshold_value,
            "labels_json": self.labels_json or {},
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "duration_seconds": self.duration_seconds,
            "suppressed_by_maintenance_id": self.suppressed_by_maintenance_id,
            "incident_id": self.incident_id,
        }

    def __repr__(self) -> str:
        return (
            f"<AlertEvent id={self.id!r} severity={self.severity!r} "
            f"status={self.status!r} title={self.title!r}>"
        )


# ---------------------------------------------------------------------------
# On-Call Schedules
# ---------------------------------------------------------------------------


class OnCallSchedule(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Recurring responder rotation schedule for incident paging and escalations."""

    __tablename__ = "oncall_schedules"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_oncall_schedule_org_name"),
        CheckConstraint("handoff_hour_utc >= 0 AND handoff_hour_utc <= 23", name="handoff_hour_range"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    rotation_type: Mapped[str] = mapped_column(String(50), nullable=False, default="weekly")
    participants_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    handoff_hour_utc: Mapped[int] = mapped_column(Integer, nullable=False, default=9)
    current_oncall_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    @validates("rotation_type")
    def _validate_rotation_type(self, _key: str, value: str) -> str:
        normalized = (value or "weekly").strip().lower()
        if normalized not in VALID_ROTATION_TYPES:
            raise ValueError(
                f"Invalid rotation_type '{value}'. Expected one of {sorted(VALID_ROTATION_TYPES)}."
            )
        return normalized

    @validates("participants_json")
    def _validate_participants(self, _key: str, value: Any) -> list[str]:
        return [str(p) for p in _coerce_json_list(value)]

    def rotate_next(self) -> str | None:
        """Advance ``current_oncall_user_id`` to the next participant in round-robin order."""
        participants = self.participants_json or []
        if not participants:
            self.current_oncall_user_id = None
            return None
        if self.current_oncall_user_id not in participants:
            self.current_oncall_user_id = participants[0]
        else:
            idx = participants.index(self.current_oncall_user_id)
            self.current_oncall_user_id = participants[(idx + 1) % len(participants)]
        return self.current_oncall_user_id

    def resolve_oncall_for_timestamp(self, *, at: datetime | None = None) -> str | None:
        """Deterministically compute the scheduled responder for a given UTC timestamp."""
        participants = self.participants_json or []
        if not participants:
            return None
        ref = _ensure_utc(at) or utcnow()
        handoff_hour = 9 if self.handoff_hour_utc is None else self.handoff_hour_utc
        epoch = datetime(2024, 1, 1, handoff_hour, 0, 0, tzinfo=timezone.utc)
        period_seconds = ROTATION_PERIOD_DAYS.get(self.rotation_type or "weekly", 7) * 86400
        elapsed = (ref - epoch).total_seconds()
        slot = int(elapsed // period_seconds) % len(participants)
        return participants[slot]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "timezone": self.timezone,
            "rotation_type": self.rotation_type,
            "participants_json": self.participants_json or [],
            "handoff_hour_utc": self.handoff_hour_utc,
            "current_oncall_user_id": self.current_oncall_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<OnCallSchedule id={self.id!r} name={self.name!r} "
            f"rotation={self.rotation_type!r} current={self.current_oncall_user_id!r}>"
        )


# ---------------------------------------------------------------------------
# Notification Channels & Delivery Logs
# ---------------------------------------------------------------------------


class NotificationChannel(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Outbound notification integration (Slack, Email, Webhook, PagerDuty, Teams, etc.)."""

    __tablename__ = "notification_channels"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_notification_channel_org_name"),
        Index("ix_notification_channels_org_enabled", "org_id", "enabled"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    encrypted_config: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity_filter_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(50), nullable=True)

    deliveries: Mapped[list[NotificationDelivery]] = relationship(
        "NotificationDelivery",
        back_populates="channel",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("channel_type")
    def _validate_channel_type(self, _key: str, value: str) -> str:
        normalized = (value or "webhook").strip().lower()
        if normalized not in VALID_CHANNEL_TYPES:
            raise ValueError(
                f"Invalid channel_type '{value}'. Expected one of {sorted(VALID_CHANNEL_TYPES)}."
            )
        return normalized

    @validates("severity_filter_json")
    def _validate_severity_filter(self, _key: str, value: Any) -> list[str]:
        return [str(s).strip().lower() for s in _coerce_json_list(value)]

    def accepts_severity(self, severity: str) -> bool:
        """Return True when this enabled channel routes alerts of ``severity``."""
        if self.enabled is False:
            return False
        allowed = self.severity_filter_json or []
        if not allowed:
            return True
        return severity.strip().lower() in {s.lower() for s in allowed}

    def record_test_result(self, *, ok: bool, status_label: str | None = None) -> None:
        self.last_tested_at = utcnow()
        self.last_status = status_label or ("ok" if ok else "failed")

    def to_dict(self, *, include_encrypted: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "channel_type": self.channel_type,
            "severity_filter_json": self.severity_filter_json or [],
            "enabled": self.enabled,
            "last_tested_at": self.last_tested_at.isoformat() if self.last_tested_at else None,
            "last_status": self.last_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_encrypted:
            payload["encrypted_config"] = self.encrypted_config
        return payload

    def __repr__(self) -> str:
        return (
            f"<NotificationChannel id={self.id!r} name={self.name!r} "
            f"type={self.channel_type!r} enabled={self.enabled}>"
        )


class NotificationDelivery(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Delivery audit attempt for an outbound alert or incident notification."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        CheckConstraint("attempts >= 0", name="delivery_attempts_non_negative"),
        Index("ix_notification_deliveries_org_status", "org_id", "status", "created_at"),
        Index("ix_notification_deliveries_channel_ts", "channel_id", "created_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    channel_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_event_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("alert_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    channel: Mapped[NotificationChannel] = relationship(
        "NotificationChannel", back_populates="deliveries"
    )

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "pending").strip().lower()
        if normalized not in VALID_DELIVERY_STATUSES:
            raise ValueError(
                f"Invalid delivery status '{value}'. Expected one of {sorted(VALID_DELIVERY_STATUSES)}."
            )
        return normalized

    def mark_sent(self, *, response_code: int = 200, at: datetime | None = None) -> None:
        self.attempts = (self.attempts or 0) + 1
        self.status = "sent"
        self.response_code = response_code
        self.error_message = None
        self.sent_at = at or utcnow()

    def mark_failed(
        self,
        error_message: str,
        *,
        response_code: int | None = None,
        retry: bool = False,
    ) -> None:
        self.attempts = (self.attempts or 0) + 1
        self.status = "retrying" if retry else "failed"
        self.response_code = response_code
        self.error_message = error_message

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "channel_id": self.channel_id,
            "alert_event_id": self.alert_event_id,
            "incident_id": self.incident_id,
            "status": self.status,
            "attempts": self.attempts,
            "response_code": self.response_code,
            "error_message": self.error_message,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<NotificationDelivery id={self.id!r} channel_id={self.channel_id!r} "
            f"status={self.status!r} attempts={self.attempts}>"
        )


# ---------------------------------------------------------------------------
# Service Level Objectives (SLOs)
# ---------------------------------------------------------------------------


class SloDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Service Level Objective definition with live SLI, error budget, and burn rate."""

    __tablename__ = "slo_definitions"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_slo_definitions_org_name"),
        CheckConstraint("target_pct > 0.0 AND target_pct <= 100.0", name="slo_target_pct_range"),
        CheckConstraint("window_days >= 1", name="slo_window_days_positive"),
        Index("ix_slo_definitions_org_status", "org_id", "status"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False, default="availability")
    target_pct: Mapped[float] = mapped_column(Float, nullable=False, default=99.9)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    scope_filter_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metric_query: Mapped[str] = mapped_column(Text, nullable=False)
    current_sli_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_budget_remaining_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    burn_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="healthy", index=True)

    @validates("scope_filter_json")
    def _validate_scope_filter(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "healthy").strip().lower()
        if normalized not in VALID_SLO_STATUSES:
            raise ValueError(
                f"Invalid SLO status '{value}'. Expected one of {sorted(VALID_SLO_STATUSES)}."
            )
        return normalized

    @property
    def error_budget_minutes(self) -> float:
        """Total allowable downtime/error minutes over the rolling SLO window."""
        window_days = self.window_days if self.window_days is not None else 30
        target_pct = self.target_pct if self.target_pct is not None else 99.9
        total_minutes = window_days * 1440.0
        allowed_error_fraction = max(0.0, (100.0 - target_pct) / 100.0)
        return round(total_minutes * allowed_error_fraction, 2)

    def update_sli(self, sli_pct: float | None) -> str:
        """Recompute error budget remaining, burn rate, and SLO health from an SLI reading."""
        if sli_pct is None:
            self.current_sli_pct = None
            self.error_budget_remaining_pct = None
            self.burn_rate = None
            self.status = "no_data"
            return self.status

        clamped_sli = max(0.0, min(100.0, float(sli_pct)))
        self.current_sli_pct = round(clamped_sli, 4)

        target_pct = self.target_pct if self.target_pct is not None else 99.9
        allowed_error = max(1e-9, 100.0 - target_pct)
        observed_error = max(0.0, 100.0 - clamped_sli)
        consumed_ratio = observed_error / allowed_error

        self.burn_rate = round(consumed_ratio, 3)
        remaining_pct = (1.0 - consumed_ratio) * 100.0
        self.error_budget_remaining_pct = round(max(-100.0, min(100.0, remaining_pct)), 2)

        if self.error_budget_remaining_pct <= 0.0:
            self.status = "breached"
        elif self.error_budget_remaining_pct <= 25.0 or self.burn_rate >= 2.0:
            self.status = "at_risk"
        else:
            self.status = "healthy"
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "target_type": self.target_type,
            "target_pct": self.target_pct,
            "window_days": self.window_days,
            "error_budget_minutes": self.error_budget_minutes,
            "scope_filter_json": self.scope_filter_json or {},
            "metric_query": self.metric_query,
            "current_sli_pct": self.current_sli_pct,
            "error_budget_remaining_pct": self.error_budget_remaining_pct,
            "burn_rate": self.burn_rate,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<SloDefinition id={self.id!r} name={self.name!r} "
            f"target={self.target_pct}% status={self.status!r}>"
        )


__all__ = [
    "EscalationPolicy",
    "AlertRule",
    "MaintenanceWindow",
    "Incident",
    "IncidentTimelineEntry",
    "AlertEvent",
    "OnCallSchedule",
    "NotificationChannel",
    "NotificationDelivery",
    "SloDefinition",
    "VALID_RULE_TYPES",
    "VALID_OPERATORS",
    "VALID_SEVERITIES",
    "SEVERITY_RANK",
    "VALID_ALERT_STATUSES",
    "VALID_INCIDENT_STATUSES",
    "VALID_INCIDENT_PRIORITIES",
    "VALID_CHANNEL_TYPES",
    "VALID_DELIVERY_STATUSES",
    "VALID_ROTATION_TYPES",
    "VALID_SLO_STATUSES",
]
