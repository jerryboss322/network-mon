"""Alerting, incident management, escalations, on-call, notifications, maintenance, and SLOs.

Provides strongly typed Pydantic v2 contracts for:
- Alert rules: `AlertRuleCreate/Update/Read` (static thresholds, hysteresis,
  multi-window evaluation, anomaly detection, auto-remediation links)
- Alert events & lifecycle: `AlertEventRead`, `AlertEventAck`, `AlertEventResolve`,
  `AlertEventQuery`
- Incident management: `IncidentCreate/Update/Read`, `IncidentTimelineEntryCreate/Read`,
  `IncidentPostmortemUpdate`
- Escalation policies: `EscalationPolicyCreate/Update/Read`
- On-call rotations & schedules: `OnCallScheduleCreate/Update/Read`
- Notification channels (with redacted secrets on read):
  `NotificationChannelCreate/Update/Read`, `NotificationChannelTestResult`
- Maintenance windows: `MaintenanceWindowCreate/Update/Read`
- Service Level Objectives & error-budget burn rates:
  `SloDefinitionCreate/Update/Read`, `SloBurnRateReport`
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Self

from pydantic import Field, computed_field, model_validator

from app.schemas.common import (
    AggregationFunction,
    BaseSchema,
    CronExpressionStr,
    HttpUrlStr,
    KeyValueFilter,
    MetadataDict,
    SortOrder,
    TagMap,
    TenantEntityReadSchema,
    UTCDatetime,
    utcnow,
)

# ---------------------------------------------------------------------------
# Alerting & SRE Enums
# ---------------------------------------------------------------------------


class AlertSeverity(str, Enum):
    """Alert severity classification."""

    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class AlertState(str, Enum):
    """Finite state machine states for an alert event."""

    PENDING = "pending"
    FIRING = "firing"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class AlertConditionOperator(str, Enum):
    """Comparison operators for alert rule threshold evaluation."""

    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EQ = "eq"
    NEQ = "neq"
    ABSENT = "absent"
    ANOMALY_ZSCORE = "anomaly_zscore"
    PCT_CHANGE = "pct_change"


class EvaluationMode(str, Enum):
    """Strategy for evaluating an alert rule."""

    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    COMPOSITE = "composite"
    HEARTBEAT = "heartbeat"
    SLO_BURN_RATE = "slo_burn_rate"


class IncidentStatus(str, Enum):
    """Lifecycle states of an operational incident."""

    TRIGGERED = "triggered"
    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MITIGATING = "mitigating"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentPriority(str, Enum):
    """Operational response priority tiers."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class TimelineEntryType(str, Enum):
    """Event classifications recorded on an incident timeline."""

    COMMENT = "comment"
    STATUS_CHANGE = "status_change"
    SEVERITY_CHANGE = "severity_change"
    ASSIGNMENT = "assignment"
    ALERT_LINKED = "alert_linked"
    PLAYBOOK_RUN = "playbook_run"
    COMMUNICATION = "communication"
    MITIGATION = "mitigation"
    POSTMORTEM = "postmortem"


class EscalationTargetType(str, Enum):
    """Recipient target types within an escalation policy step."""

    USER = "user"
    ON_CALL_SCHEDULE = "on_call_schedule"
    NOTIFICATION_CHANNEL = "notification_channel"
    WEBHOOK = "webhook"


class RotationType(str, Enum):
    """Cadence of an on-call shift rotation."""

    DAILY = "daily"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    CUSTOM = "custom"


class NotificationChannelType(str, Enum):
    """Supported outbound alert notification transports."""

    WEBHOOK = "webhook"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    TEAMS = "teams"
    OPSGENIE = "opsgenie"
    DISCORD = "discord"
    SMS = "sms"


class MaintenanceState(str, Enum):
    """Computed or persisted lifecycle state of a maintenance window."""

    SCHEDULED = "scheduled"
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class SloIndicatorType(str, Enum):
    """Underlying Service Level Indicator (SLI) category."""

    AVAILABILITY = "availability"
    LATENCY = "latency"
    PACKET_LOSS = "packet_loss"
    SYNTHETIC_SUCCESS = "synthetic_success"
    ERROR_RATIO = "error_ratio"
    THROUGHPUT = "throughput"


class SloStatus(str, Enum):
    """Health classification of an SLO relative to its error budget."""

    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    INSUFFICIENT_DATA = "insufficient_data"


# ---------------------------------------------------------------------------
# Alert Rule Schemas
# ---------------------------------------------------------------------------


class AlertRuleCreate(BaseSchema):
    """Create a declarative metric, heartbeat, anomaly, or composite alert rule."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    is_enabled: bool = Field(default=True)
    evaluation_mode: EvaluationMode = Field(default=EvaluationMode.THRESHOLD)
    severity: AlertSeverity = Field(default=AlertSeverity.WARNING)
    metric_name: str = Field(
        ..., min_length=1, max_length=160, description="Metric key (e.g. 'icmp.rtt_avg_ms')."
    )
    query_dsl: str | None = Field(default=None, max_length=2000)
    aggregation: AggregationFunction = Field(default=AggregationFunction.AVG)
    operator: AlertConditionOperator = Field(default=AlertConditionOperator.GT)
    threshold_value: float | None = Field(default=None)
    warning_threshold: float | None = Field(default=None)
    critical_threshold: float | None = Field(default=None)
    recovery_threshold: float | None = Field(
        default=None, description="Optional hysteresis threshold required to auto-resolve."
    )
    anomaly_zscore: float | None = Field(default=None, ge=1.0, le=10.0)
    evaluation_window_seconds: int = Field(default=300, ge=15, le=86400)
    evaluation_interval_seconds: int = Field(default=60, ge=10, le=3600)
    for_duration_seconds: int = Field(
        default=120, ge=0, le=86400, description="Condition must hold this long before firing."
    )
    no_data_behavior: Literal["ignore", "keep_last", "fire_warning", "fire_critical"] = Field(
        default="ignore"
    )
    scope_device_ids: list[str] = Field(default_factory=list)
    scope_site_ids: list[str] = Field(default_factory=list)
    scope_group_ids: list[str] = Field(default_factory=list)
    scope_filters: list[KeyValueFilter] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=lambda: ["device_id"])
    notification_channel_ids: list[str] = Field(default_factory=list)
    escalation_policy_id: str | None = None
    auto_create_incident: bool = Field(default=False)
    auto_remediate_playbook_id: str | None = None
    runbook_url: HttpUrlStr | None = None
    labels: TagMap = Field(default_factory=dict)
    annotations: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_rule_thresholds(self) -> Self:
        if self.evaluation_mode == EvaluationMode.THRESHOLD and self.operator != AlertConditionOperator.ABSENT:
            if (
                self.threshold_value is None
                and self.warning_threshold is None
                and self.critical_threshold is None
            ):
                raise ValueError(
                    "Threshold rules require 'threshold_value', 'warning_threshold', or 'critical_threshold'."
                )
        if self.evaluation_mode == EvaluationMode.ANOMALY and self.anomaly_zscore is None:
            self.anomaly_zscore = 3.0
        return self


class AlertRuleUpdate(BaseSchema):
    """Partial update payload for an existing alert rule."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    is_enabled: bool | None = None
    severity: AlertSeverity | None = None
    metric_name: str | None = Field(default=None, min_length=1, max_length=160)
    query_dsl: str | None = Field(default=None, max_length=2000)
    aggregation: AggregationFunction | None = None
    operator: AlertConditionOperator | None = None
    threshold_value: float | None = None
    warning_threshold: float | None = None
    critical_threshold: float | None = None
    recovery_threshold: float | None = None
    anomaly_zscore: float | None = Field(default=None, ge=1.0, le=10.0)
    evaluation_window_seconds: int | None = Field(default=None, ge=15, le=86400)
    evaluation_interval_seconds: int | None = Field(default=None, ge=10, le=3600)
    for_duration_seconds: int | None = Field(default=None, ge=0, le=86400)
    no_data_behavior: Literal["ignore", "keep_last", "fire_warning", "fire_critical"] | None = None
    scope_device_ids: list[str] | None = None
    scope_site_ids: list[str] | None = None
    scope_group_ids: list[str] | None = None
    scope_filters: list[KeyValueFilter] | None = None
    group_by: list[str] | None = None
    notification_channel_ids: list[str] | None = None
    escalation_policy_id: str | None = None
    auto_create_incident: bool | None = None
    auto_remediate_playbook_id: str | None = None
    runbook_url: HttpUrlStr | None = None
    labels: TagMap | None = None
    annotations: TagMap | None = None


class AlertRuleRead(TenantEntityReadSchema):
    """Full representation of an alert rule with evaluation telemetry."""

    name: str
    description: str | None = None
    is_enabled: bool = True
    evaluation_mode: EvaluationMode = EvaluationMode.THRESHOLD
    severity: AlertSeverity = AlertSeverity.WARNING
    metric_name: str
    query_dsl: str | None = None
    aggregation: AggregationFunction = AggregationFunction.AVG
    operator: AlertConditionOperator = AlertConditionOperator.GT
    threshold_value: float | None = None
    warning_threshold: float | None = None
    critical_threshold: float | None = None
    recovery_threshold: float | None = None
    anomaly_zscore: float | None = None
    evaluation_window_seconds: int = 300
    evaluation_interval_seconds: int = 60
    for_duration_seconds: int = 120
    no_data_behavior: str = "ignore"
    scope_device_ids: list[str] = Field(default_factory=list)
    scope_site_ids: list[str] = Field(default_factory=list)
    scope_group_ids: list[str] = Field(default_factory=list)
    scope_filters: list[KeyValueFilter] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=list)
    notification_channel_ids: list[str] = Field(default_factory=list)
    escalation_policy_id: str | None = None
    auto_create_incident: bool = False
    auto_remediate_playbook_id: str | None = None
    runbook_url: str | None = None
    last_evaluated_at: UTCDatetime | None = None
    firing_count: int = Field(default=0, ge=0)
    labels: TagMap = Field(default_factory=dict)
    annotations: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Alert Event Schemas
# ---------------------------------------------------------------------------


class AlertEventRead(TenantEntityReadSchema):
    """Materialized firing, acknowledged, suppressed, or resolved alert event."""

    rule_id: str
    rule_name: str | None = None
    fingerprint: str = Field(..., description="Deterministic deduplication hash for this alert.")
    state: AlertState = AlertState.FIRING
    severity: AlertSeverity = AlertSeverity.WARNING
    title: str
    message: str
    device_id: str | None = None
    device_name: str | None = None
    site_id: str | None = None
    interface_name: str | None = None
    metric_name: str | None = None
    trigger_value: float | None = None
    threshold_value: float | None = None
    incident_id: str | None = None
    maintenance_window_id: str | None = None
    fired_at: UTCDatetime
    last_seen_at: UTCDatetime | None = None
    acknowledged_at: UTCDatetime | None = None
    acknowledged_by_user_id: str | None = None
    ack_note: str | None = None
    resolved_at: UTCDatetime | None = None
    resolved_by_user_id: str | None = None
    resolution_note: str | None = None
    escalation_level: int = Field(default=0, ge=0)
    notification_count: int = Field(default=0, ge=0)
    labels: TagMap = Field(default_factory=dict)
    annotations: TagMap = Field(default_factory=dict)


class AlertEventAck(BaseSchema):
    """Payload to acknowledge an active alert event."""

    note: str | None = Field(default=None, max_length=1000)
    suppress_notifications_minutes: int | None = Field(default=None, ge=1, le=10_080)
    assign_to_user_id: str | None = None


class AlertEventResolve(BaseSchema):
    """Payload to manually resolve an alert event."""

    resolution_note: str | None = Field(default=None, max_length=1000)
    root_cause_category: str | None = Field(default=None, max_length=80)
    close_linked_incident: bool = Field(default=False)


class AlertEventQuery(BaseSchema):
    """Filter parameters for listing alert events."""

    state: AlertState | None = None
    severity: AlertSeverity | None = None
    rule_id: str | None = None
    device_id: str | None = None
    site_id: str | None = None
    incident_id: str | None = None
    search: str | None = Field(default=None, max_length=200)
    only_active: bool = Field(default=False)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_order: SortOrder = SortOrder.DESC


# ---------------------------------------------------------------------------
# Incident Management & Postmortem Schemas
# ---------------------------------------------------------------------------


class IncidentActionItem(BaseSchema):
    """Follow-up corrective action item tracked inside an incident postmortem."""

    title: str = Field(..., min_length=2, max_length=200)
    owner_user_id: str | None = None
    due_date: UTCDatetime | None = None
    status: Literal["open", "in_progress", "done", "wont_fix"] = Field(default="open")
    ticket_url: HttpUrlStr | None = None


class IncidentCreate(BaseSchema):
    """Create a new operational incident manually or from correlated alerts."""

    title: str = Field(..., min_length=3, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    severity: AlertSeverity = Field(default=AlertSeverity.HIGH)
    priority: IncidentPriority = Field(default=IncidentPriority.P2)
    commander_user_id: str | None = None
    assignee_user_id: str | None = None
    escalation_policy_id: str | None = None
    alert_event_ids: list[str] = Field(default_factory=list)
    impacted_device_ids: list[str] = Field(default_factory=list)
    impacted_site_ids: list[str] = Field(default_factory=list)
    impacted_services: list[str] = Field(default_factory=list)
    customer_impact: str | None = Field(default=None, max_length=1000)
    tags: TagMap = Field(default_factory=dict)


class IncidentUpdate(BaseSchema):
    """Partial update for an active or resolved incident."""

    title: str | None = Field(default=None, min_length=3, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    status: IncidentStatus | None = None
    severity: AlertSeverity | None = None
    priority: IncidentPriority | None = None
    commander_user_id: str | None = None
    assignee_user_id: str | None = None
    impacted_device_ids: list[str] | None = None
    impacted_services: list[str] | None = None
    customer_impact: str | None = Field(default=None, max_length=1000)
    tags: TagMap | None = None


class IncidentTimelineEntryCreate(BaseSchema):
    """Append an entry to an incident's chronological activity log."""

    entry_type: TimelineEntryType = Field(default=TimelineEntryType.COMMENT)
    message: str = Field(..., min_length=1, max_length=4000)
    is_public: bool = Field(
        default=False, description="Whether this update is visible on external status pages."
    )
    metadata: MetadataDict = Field(default_factory=dict)


class IncidentTimelineEntryRead(TenantEntityReadSchema):
    """Single chronological event on an incident timeline."""

    incident_id: str
    entry_type: TimelineEntryType
    author_user_id: str | None = None
    author_name: str | None = None
    message: str
    is_public: bool = False
    metadata: MetadataDict = Field(default_factory=dict)


class IncidentPostmortemUpdate(BaseSchema):
    """Structured blameless postmortem report attached to a resolved incident."""

    root_cause: str = Field(..., min_length=5, max_length=8000)
    contributing_factors: list[str] = Field(default_factory=list)
    detection_summary: str | None = Field(default=None, max_length=4000)
    mitigation_summary: str | None = Field(default=None, max_length=4000)
    lessons_learned: list[str] = Field(default_factory=list)
    what_went_well: list[str] = Field(default_factory=list)
    action_items: list[IncidentActionItem] = Field(default_factory=list)
    is_published: bool = Field(default=False)


class IncidentRead(TenantEntityReadSchema):
    """Full representation of an incident with MTTA/MTTR metrics and postmortem."""

    incident_number: int = Field(default=0, ge=0)
    title: str
    summary: str | None = None
    status: IncidentStatus = IncidentStatus.TRIGGERED
    severity: AlertSeverity = AlertSeverity.HIGH
    priority: IncidentPriority = IncidentPriority.P2
    commander_user_id: str | None = None
    assignee_user_id: str | None = None
    escalation_policy_id: str | None = None
    alert_event_ids: list[str] = Field(default_factory=list)
    impacted_device_ids: list[str] = Field(default_factory=list)
    impacted_site_ids: list[str] = Field(default_factory=list)
    impacted_services: list[str] = Field(default_factory=list)
    customer_impact: str | None = None
    triggered_at: UTCDatetime
    acknowledged_at: UTCDatetime | None = None
    mitigated_at: UTCDatetime | None = None
    resolved_at: UTCDatetime | None = None
    mtta_seconds: int | None = Field(default=None, ge=0)
    mttr_seconds: int | None = Field(default=None, ge=0)
    postmortem: IncidentPostmortemUpdate | None = None
    timeline: list[IncidentTimelineEntryRead] = Field(default_factory=list)
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Escalation Policy & On-Call Schedule Schemas
# ---------------------------------------------------------------------------


class EscalationTarget(BaseSchema):
    """Single notification target inside an escalation step."""

    target_type: EscalationTargetType
    target_id: str = Field(..., min_length=1, max_length=128)
    label: str | None = None


class EscalationStep(BaseSchema):
    """Ordered escalation tier with delay before escalating further."""

    step_order: int = Field(..., ge=1, le=20)
    delay_minutes: int = Field(default=15, ge=0, le=1440)
    targets: list[EscalationTarget] = Field(..., min_length=1, max_length=20)


class EscalationPolicyCreate(BaseSchema):
    """Create a multi-tier alert escalation policy."""

    name: str = Field(..., min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    repeat_count: int = Field(default=2, ge=0, le=10)
    steps: list[EscalationStep] = Field(..., min_length=1, max_length=20)
    is_default: bool = Field(default=False)

    @model_validator(mode="after")
    def _validate_step_ordering(self) -> Self:
        orders = [step.step_order for step in self.steps]
        if len(orders) != len(set(orders)):
            raise ValueError("Escalation steps must have unique 'step_order' values.")
        return self


class EscalationPolicyUpdate(BaseSchema):
    """Partial update for an escalation policy."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    repeat_count: int | None = Field(default=None, ge=0, le=10)
    steps: list[EscalationStep] | None = Field(default=None, min_length=1, max_length=20)
    is_default: bool | None = None


class EscalationPolicyRead(TenantEntityReadSchema):
    """Persisted escalation policy."""

    name: str
    description: str | None = None
    repeat_count: int = 2
    steps: list[EscalationStep] = Field(default_factory=list)
    is_default: bool = False
    attached_rule_count: int = Field(default=0, ge=0)


class OnCallOverride(BaseSchema):
    """Temporary shift override replacing the scheduled responder."""

    user_id: str
    starts_at: UTCDatetime
    ends_at: UTCDatetime
    reason: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _validate_bounds(self) -> Self:
        if self.starts_at >= self.ends_at:
            raise ValueError("On-call override 'starts_at' must be earlier than 'ends_at'.")
        return self


class OnCallScheduleCreate(BaseSchema):
    """Create a recurring on-call rotation schedule."""

    name: str = Field(..., min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    timezone_name: str = Field(default="UTC", max_length=64)
    rotation_type: RotationType = Field(default=RotationType.WEEKLY)
    rotation_interval_hours: int = Field(default=168, ge=1, le=8760)
    handoff_hour_utc: int = Field(default=9, ge=0, le=23)
    handoff_day_of_week: int = Field(default=0, ge=0, le=6, description="0=Monday .. 6=Sunday.")
    participant_user_ids: list[str] = Field(..., min_length=1, max_length=100)
    overrides: list[OnCallOverride] = Field(default_factory=list)
    starts_at: UTCDatetime = Field(default_factory=utcnow)


class OnCallScheduleUpdate(BaseSchema):
    """Partial update for an on-call schedule."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    timezone_name: str | None = Field(default=None, max_length=64)
    rotation_type: RotationType | None = None
    rotation_interval_hours: int | None = Field(default=None, ge=1, le=8760)
    handoff_hour_utc: int | None = Field(default=None, ge=0, le=23)
    handoff_day_of_week: int | None = Field(default=None, ge=0, le=6)
    participant_user_ids: list[str] | None = Field(default=None, min_length=1, max_length=100)
    overrides: list[OnCallOverride] | None = None


class OnCallScheduleRead(TenantEntityReadSchema):
    """Full on-call schedule including currently active responder."""

    name: str
    description: str | None = None
    timezone_name: str = "UTC"
    rotation_type: RotationType = RotationType.WEEKLY
    rotation_interval_hours: int = 168
    handoff_hour_utc: int = 9
    handoff_day_of_week: int = 0
    participant_user_ids: list[str] = Field(default_factory=list)
    overrides: list[OnCallOverride] = Field(default_factory=list)
    starts_at: UTCDatetime
    current_on_call_user_id: str | None = None
    next_handoff_at: UTCDatetime | None = None


# ---------------------------------------------------------------------------
# Notification Channel Schemas (Redacted secrets on Read)
# ---------------------------------------------------------------------------


class NotificationChannelCreate(BaseSchema):
    """Configure an outbound alert notification destination."""

    name: str = Field(..., min_length=2, max_length=120)
    channel_type: NotificationChannelType
    is_enabled: bool = Field(default=True)
    min_severity: AlertSeverity = Field(default=AlertSeverity.WARNING)
    send_resolved: bool = Field(default=True)
    config: MetadataDict = Field(
        default_factory=dict,
        description="Channel-specific parameters (url, channel, recipients, routing_key, etc.).",
    )
    rate_limit_per_minute: int = Field(default=30, ge=1, le=1000)
    tags: TagMap = Field(default_factory=dict)


class NotificationChannelUpdate(BaseSchema):
    """Partial update for a notification channel."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    is_enabled: bool | None = None
    min_severity: AlertSeverity | None = None
    send_resolved: bool | None = None
    config: MetadataDict | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=1000)
    tags: TagMap | None = None


class NotificationChannelRead(TenantEntityReadSchema):
    """Safe representation of a notification channel (redacts tokens/keys/passwords)."""

    name: str
    channel_type: NotificationChannelType
    is_enabled: bool = True
    min_severity: AlertSeverity = AlertSeverity.WARNING
    send_resolved: bool = True
    redacted_config: MetadataDict = Field(
        default_factory=dict,
        description="Channel configuration with sensitive keys masked.",
    )
    rate_limit_per_minute: int = 30
    last_sent_at: UTCDatetime | None = None
    last_error: str | None = None
    total_sent_count: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)


class NotificationChannelTestResult(BaseSchema):
    """Outcome of dispatching a synthetic test notification to a channel."""

    channel_id: str
    channel_type: NotificationChannelType
    success: bool
    http_status_code: int | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    message: str
    tested_at: UTCDatetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Maintenance Window Schemas
# ---------------------------------------------------------------------------


class MaintenanceWindowCreate(BaseSchema):
    """Schedule a planned maintenance window suppressing alerts or notifications."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    starts_at: UTCDatetime
    ends_at: UTCDatetime
    recurrence_cron: CronExpressionStr | None = Field(
        default=None, description="Optional recurring 5-field cron schedule."
    )
    timezone_name: str = Field(default="UTC", max_length=64)
    device_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    tag_filters: list[KeyValueFilter] = Field(default_factory=list)
    suppress_notifications: bool = Field(default=True)
    suppress_alert_evaluation: bool = Field(default=False)
    change_ticket_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _validate_window_bounds(self) -> Self:
        if self.starts_at >= self.ends_at:
            raise ValueError("Maintenance window 'starts_at' must be earlier than 'ends_at'.")
        return self


class MaintenanceWindowUpdate(BaseSchema):
    """Partial update for a scheduled maintenance window."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    starts_at: UTCDatetime | None = None
    ends_at: UTCDatetime | None = None
    recurrence_cron: CronExpressionStr | None = None
    device_ids: list[str] | None = None
    site_ids: list[str] | None = None
    group_ids: list[str] | None = None
    tag_filters: list[KeyValueFilter] | None = None
    suppress_notifications: bool | None = None
    suppress_alert_evaluation: bool | None = None
    state: MaintenanceState | None = None
    change_ticket_id: str | None = Field(default=None, max_length=64)


class MaintenanceWindowRead(TenantEntityReadSchema):
    """Persisted maintenance window record."""

    name: str
    description: str | None = None
    state: MaintenanceState = MaintenanceState.SCHEDULED
    starts_at: UTCDatetime
    ends_at: UTCDatetime
    recurrence_cron: str | None = None
    timezone_name: str = "UTC"
    device_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    tag_filters: list[KeyValueFilter] = Field(default_factory=list)
    suppress_notifications: bool = True
    suppress_alert_evaluation: bool = False
    change_ticket_id: str | None = None
    created_by_user_id: str | None = None


# ---------------------------------------------------------------------------
# SLO Definition & Multi-Window Burn Rate Report Schemas
# ---------------------------------------------------------------------------


class SloDefinitionCreate(BaseSchema):
    """Define a Service Level Objective with rolling error budget tracking."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    service_name: str = Field(..., min_length=1, max_length=120)
    indicator_type: SloIndicatorType = Field(default=SloIndicatorType.AVAILABILITY)
    target_pct: float = Field(
        ..., gt=0.0, lt=100.0, description="Reliability target percentage (e.g. 99.9 or 99.95)."
    )
    window_days: int = Field(default=30, ge=1, le=365, description="Rolling compliance window.")
    threshold_ms: float | None = Field(
        default=None, ge=1.0, description="Latency threshold for latency-based SLIs."
    )
    device_ids: list[str] = Field(default_factory=list)
    probe_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    good_events_query: str | None = Field(default=None, max_length=1000)
    total_events_query: str | None = Field(default=None, max_length=1000)
    fast_burn_threshold: float = Field(default=14.4, gt=0.0)
    slow_burn_threshold: float = Field(default=6.0, gt=0.0)
    notification_channel_ids: list[str] = Field(default_factory=list)
    is_enabled: bool = Field(default=True)
    tags: TagMap = Field(default_factory=dict)


class SloDefinitionUpdate(BaseSchema):
    """Partial update for an SLO definition."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    service_name: str | None = Field(default=None, min_length=1, max_length=120)
    target_pct: float | None = Field(default=None, gt=0.0, lt=100.0)
    window_days: int | None = Field(default=None, ge=1, le=365)
    threshold_ms: float | None = Field(default=None, ge=1.0)
    device_ids: list[str] | None = None
    probe_ids: list[str] | None = None
    site_ids: list[str] | None = None
    fast_burn_threshold: float | None = Field(default=None, gt=0.0)
    slow_burn_threshold: float | None = Field(default=None, gt=0.0)
    notification_channel_ids: list[str] | None = None
    is_enabled: bool | None = None
    tags: TagMap | None = None


class SloDefinitionRead(TenantEntityReadSchema):
    """Full SLO definition with live compliance and error budget summary."""

    name: str
    description: str | None = None
    service_name: str
    indicator_type: SloIndicatorType
    target_pct: float
    window_days: int = 30
    threshold_ms: float | None = None
    device_ids: list[str] = Field(default_factory=list)
    probe_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    fast_burn_threshold: float = 14.4
    slow_burn_threshold: float = 6.0
    notification_channel_ids: list[str] = Field(default_factory=list)
    is_enabled: bool = True
    status: SloStatus = SloStatus.HEALTHY
    current_sli_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    error_budget_remaining_pct: float | None = None
    tags: TagMap = Field(default_factory=dict)

    @computed_field
    @property
    def error_budget_minutes(self) -> float:
        """Total allowed downtime minutes over the rolling window."""
        total_minutes = self.window_days * 24 * 60
        return round(total_minutes * ((100.0 - self.target_pct) / 100.0), 2)


class BurnRateWindow(BaseSchema):
    """Error-budget burn rate calculated over a specific lookback window."""

    window_label: str = Field(..., description="Window label such as '1h', '6h', '24h', '72h'.")
    window_minutes: int = Field(..., ge=1)
    good_events: int = Field(default=0, ge=0)
    total_events: int = Field(default=0, ge=0)
    achieved_sli_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    burn_rate: float = Field(default=0.0, ge=0.0)
    budget_consumed_pct: float = Field(default=0.0, ge=0.0)
    is_alerting: bool = Field(default=False)


class SloBurnRateReport(BaseSchema):
    """Multi-window SRE error-budget burn-rate analysis for an SLO."""

    slo_id: str
    slo_name: str
    service_name: str
    target_pct: float
    window_days: int
    status: SloStatus
    current_sli_pct: float = Field(..., ge=0.0, le=100.0)
    error_budget_total_minutes: float = Field(..., ge=0.0)
    error_budget_consumed_minutes: float = Field(..., ge=0.0)
    error_budget_remaining_minutes: float
    error_budget_remaining_pct: float
    projected_exhaustion_at: UTCDatetime | None = None
    windows: list[BurnRateWindow] = Field(default_factory=list)
    generated_at: UTCDatetime = Field(default_factory=utcnow)
