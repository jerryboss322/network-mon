"""Configuration management, compliance, playbooks, scheduled reports, and plugins.

Provides strongly typed Pydantic v2 contracts for:
- Device configuration backups & drift diffs: `ConfigSnapshotCreate/Read`,
  `ConfigDiffRequest/Read`
- Policy-as-code compliance auditing: `CompliancePolicyCreate/Update/Read`,
  `ComplianceEvaluationRequest/Read`
- Automated remediation & runbook playbooks: `PlaybookCreate/Update/Read`,
  `PlaybookExecuteRequest`, `PlaybookRunRead`
- Scheduled & on-demand reporting: `ScheduledReportCreate/Update/Read`,
  `GeneratedReportRead`
- Extensible platform plugins: `PluginRegister`, `PluginUpdate`, `PluginRead`
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Literal, Self

from pydantic import Field, computed_field, field_validator, model_validator

from app.schemas.common import (
    BaseSchema,
    CronExpressionStr,
    EmailAddress,
    HttpUrlStr,
    MetadataDict,
    SemVerStr,
    SeverityLevel,
    SlugStr,
    TagMap,
    TenantEntityReadSchema,
    UTCDatetime,
    utcnow,
)

# ---------------------------------------------------------------------------
# Automation & Governance Enums
# ---------------------------------------------------------------------------


class ConfigType(str, Enum):
    """Class of device configuration captured in a snapshot."""

    RUNNING = "running"
    STARTUP = "startup"
    CANDIDATE = "candidate"
    VLAN_DATABASE = "vlan_database"
    ROUTING_TABLE = "routing_table"
    FIREWALL_POLICY = "firewall_policy"
    SYSTEM_STATE = "system_state"


class ConfigCaptureMethod(str, Enum):
    """Protocol used to retrieve a device configuration snapshot."""

    SSH = "ssh"
    NETCONF = "netconf"
    RESTCONF = "restconf"
    SNMP = "snmp"
    API = "api"
    MANUAL_UPLOAD = "manual_upload"


class ComplianceRuleType(str, Enum):
    """Evaluation primitive used by a compliance rule."""

    REGEX_REQUIRED = "regex_required"
    REGEX_FORBIDDEN = "regex_forbidden"
    BLOCK_CONTAINS = "block_contains"
    EXACT_LINE = "exact_line"
    MIN_LINE_COUNT = "min_line_count"
    JSON_PATH = "json_path"


class ComplianceStatus(str, Enum):
    """Outcome of evaluating a compliance rule or policy."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


class PlaybookTriggerType(str, Enum):
    """How a remediation or operational playbook is invoked."""

    MANUAL = "manual"
    ALERT_RULE = "alert_rule"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"
    COMPLIANCE_DRIFT = "compliance_drift"


class PlaybookStepType(str, Enum):
    """Execution action type for a single playbook step."""

    SSH_COMMAND = "ssh_command"
    NETCONF_RPC = "netconf_rpc"
    HTTP_REQUEST = "http_request"
    SNMP_POLL = "snmp_poll"
    CONFIG_BACKUP = "config_backup"
    CONFIG_ROLLBACK = "config_rollback"
    NOTIFY = "notify"
    APPROVAL_GATE = "approval_gate"
    WAIT = "wait"
    CONDITION = "condition"
    PYTHON_SANDBOX = "python_sandbox"


class PlaybookRunStatus(str, Enum):
    """Execution status of a playbook run or individual step."""

    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ReportFormat(str, Enum):
    """Output rendering format for scheduled and generated reports."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


class ReportType(str, Enum):
    """Analytical domain of a scheduled report."""

    EXECUTIVE_SUMMARY = "executive_summary"
    AVAILABILITY_SLA = "availability_sla"
    CAPACITY_UTILIZATION = "capacity_utilization"
    ALERT_INCIDENT_REVIEW = "alert_incident_review"
    COMPLIANCE_AUDIT = "compliance_audit"
    INVENTORY_ASSET_LEDGER = "inventory_asset_ledger"
    TOP_TALKERS_FLOW = "top_talkers_flow"


class ReportStatus(str, Enum):
    """Generation lifecycle state of an output report artifact."""

    QUEUED = "queued"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"


class PluginCategory(str, Enum):
    """Extension hook category for a registered platform plugin."""

    COLLECTOR = "collector"
    NOTIFIER = "notifier"
    REMEDIATOR = "remediator"
    ENRICHER = "enricher"
    EXPORTER = "exporter"
    DISCOVERY = "discovery"
    COMPLIANCE = "compliance"


class PluginStatus(str, Enum):
    """Lifecycle and health state of a registered plugin."""

    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
    PENDING_VERIFICATION = "pending_verification"


# ---------------------------------------------------------------------------
# Configuration Snapshot & Diff Schemas
# ---------------------------------------------------------------------------


class ConfigSnapshotCreate(BaseSchema):
    """Store a newly captured or uploaded device configuration snapshot."""

    device_id: str
    config_type: ConfigType = Field(default=ConfigType.RUNNING)
    capture_method: ConfigCaptureMethod = Field(default=ConfigCaptureMethod.SSH)
    content: str = Field(..., min_length=1, max_length=5_000_000)
    is_baseline: bool = Field(default=False)
    label: str | None = Field(default=None, max_length=120)
    captured_at: UTCDatetime = Field(default_factory=utcnow)
    metadata: MetadataDict = Field(default_factory=dict)

    @computed_field
    @property
    def sha256_hash(self) -> str:
        """Compute deterministic SHA-256 digest of the configuration text."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @computed_field
    @property
    def byte_size(self) -> int:
        """UTF-8 byte size of the configuration text."""
        return len(self.content.encode("utf-8"))

    @computed_field
    @property
    def line_count(self) -> int:
        """Total number of lines in the snapshot."""
        return len(self.content.splitlines())


class ConfigSnapshotRead(TenantEntityReadSchema):
    """Persisted device configuration snapshot."""

    device_id: str
    device_name: str | None = None
    version_number: int = Field(default=1, ge=1)
    config_type: ConfigType = ConfigType.RUNNING
    capture_method: ConfigCaptureMethod = ConfigCaptureMethod.SSH
    sha256_hash: str
    byte_size: int = Field(default=0, ge=0)
    line_count: int = Field(default=0, ge=0)
    is_baseline: bool = False
    has_drift_from_baseline: bool = False
    label: str | None = None
    captured_at: UTCDatetime
    captured_by_user_id: str | None = None
    content: str | None = Field(
        default=None, description="Full configuration text (may be omitted in compact list views)."
    )
    metadata: MetadataDict = Field(default_factory=dict)


class ConfigDiffRequest(BaseSchema):
    """Request a line-by-line unified diff between two configuration snapshots."""

    source_snapshot_id: str = Field(..., description="Older / baseline snapshot UUID.")
    target_snapshot_id: str = Field(..., description="Newer / candidate snapshot UUID.")
    context_lines: int = Field(default=3, ge=0, le=20)
    ignore_whitespace: bool = Field(default=False)
    ignore_comments: bool = Field(default=False)

    @model_validator(mode="after")
    def _distinct_snapshots(self) -> Self:
        if self.source_snapshot_id == self.target_snapshot_id:
            raise ValueError("'source_snapshot_id' and 'target_snapshot_id' must differ.")
        return self


class DiffHunk(BaseSchema):
    """Structured diff hunk for syntax-highlighted side-by-side rendering."""

    old_start: int = Field(..., ge=0)
    old_lines: int = Field(..., ge=0)
    new_start: int = Field(..., ge=0)
    new_lines: int = Field(..., ge=0)
    header: str
    lines: list[str] = Field(default_factory=list)


class ConfigDiffRead(BaseSchema):
    """Computed unified diff and change statistics between two config snapshots."""

    device_id: str
    source_snapshot_id: str
    target_snapshot_id: str
    source_version: int | None = None
    target_version: int | None = None
    has_changes: bool
    lines_added: int = Field(default=0, ge=0)
    lines_removed: int = Field(default=0, ge=0)
    unified_diff: str = Field(default="")
    hunks: list[DiffHunk] = Field(default_factory=list)
    drift_summary: str | None = None
    computed_at: UTCDatetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Compliance Policy & Evaluation Schemas
# ---------------------------------------------------------------------------


class ComplianceRuleSpec(BaseSchema):
    """Single atomic check inside a compliance policy."""

    rule_id: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=500)
    rule_type: ComplianceRuleType = Field(default=ComplianceRuleType.REGEX_REQUIRED)
    pattern: str = Field(..., min_length=1, max_length=1000)
    block_selector: str | None = Field(
        default=None,
        max_length=256,
        description="Optional parent section regex (e.g. '^interface GigabitEthernet').",
    )
    severity: SeverityLevel = Field(default=SeverityLevel.HIGH)
    control_ref: str | None = Field(
        default=None, max_length=64, description="Benchmark reference (e.g. 'CIS-IOS-2.1.3')."
    )
    remediation_hint: str | None = Field(default=None, max_length=1000)
    weight: float = Field(default=1.0, gt=0.0, le=100.0)

    @model_validator(mode="after")
    def _validate_regex_patterns(self) -> Self:
        if self.rule_type in {
            ComplianceRuleType.REGEX_REQUIRED,
            ComplianceRuleType.REGEX_FORBIDDEN,
            ComplianceRuleType.BLOCK_CONTAINS,
        }:
            try:
                re.compile(self.pattern, re.MULTILINE)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern in rule '{self.rule_id}': {exc}") from exc
        if self.block_selector is not None:
            try:
                re.compile(self.block_selector, re.MULTILINE)
            except re.error as exc:
                raise ValueError(
                    f"Invalid block_selector regex in rule '{self.rule_id}': {exc}"
                ) from exc
        return self


class CompliancePolicyCreate(BaseSchema):
    """Create a declarative configuration compliance benchmark policy."""

    name: str = Field(..., min_length=2, max_length=160)
    slug: SlugStr
    description: str | None = Field(default=None, max_length=1000)
    framework: str | None = Field(
        default=None, max_length=64, description="Standard name (CIS, NIST-800-53, PCI-DSS, SOC2)."
    )
    target_vendors: list[str] = Field(default_factory=list)
    target_device_types: list[str] = Field(default_factory=list)
    target_tags: TagMap = Field(default_factory=dict)
    rules: list[ComplianceRuleSpec] = Field(..., min_length=1, max_length=200)
    is_enabled: bool = Field(default=True)
    auto_evaluate_on_backup: bool = Field(default=True)
    remediation_playbook_id: str | None = None

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Self:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                raise ValueError(f"Duplicate compliance rule_id: {rule.rule_id!r}")
            seen.add(rule.rule_id)
        return self


class CompliancePolicyUpdate(BaseSchema):
    """Partial update for a compliance policy."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    framework: str | None = Field(default=None, max_length=64)
    target_vendors: list[str] | None = None
    target_device_types: list[str] | None = None
    target_tags: TagMap | None = None
    rules: list[ComplianceRuleSpec] | None = Field(default=None, min_length=1, max_length=200)
    is_enabled: bool | None = None
    auto_evaluate_on_backup: bool | None = None
    remediation_playbook_id: str | None = None


class CompliancePolicyRead(TenantEntityReadSchema):
    """Full representation of a compliance policy."""

    name: str
    slug: str
    description: str | None = None
    framework: str | None = None
    target_vendors: list[str] = Field(default_factory=list)
    target_device_types: list[str] = Field(default_factory=list)
    target_tags: TagMap = Field(default_factory=dict)
    rules: list[ComplianceRuleSpec] = Field(default_factory=list)
    is_enabled: bool = True
    auto_evaluate_on_backup: bool = True
    remediation_playbook_id: str | None = None
    last_evaluated_at: UTCDatetime | None = None
    avg_score_pct: float | None = Field(default=None, ge=0.0, le=100.0)


class ComplianceEvaluationRequest(BaseSchema):
    """Trigger compliance evaluation of a policy against one or more devices/snapshots."""

    policy_id: str
    device_ids: list[str] = Field(default_factory=list, max_length=200)
    snapshot_id: str | None = None
    site_id: str | None = None
    group_id: str | None = None


class ComplianceRuleResult(BaseSchema):
    """Per-rule pass/fail finding within a compliance evaluation."""

    rule_id: str
    title: str
    severity: SeverityLevel
    status: ComplianceStatus
    control_ref: str | None = None
    matched_lines: list[str] = Field(default_factory=list)
    message: str | None = None
    remediation_hint: str | None = None


class ComplianceEvaluationRead(TenantEntityReadSchema):
    """Persisted compliance audit result for a device against a policy."""

    policy_id: str
    policy_name: str | None = None
    device_id: str
    device_name: str | None = None
    snapshot_id: str | None = None
    status: ComplianceStatus
    score_pct: float = Field(..., ge=0.0, le=100.0)
    total_rules: int = Field(..., ge=0)
    passed_rules: int = Field(..., ge=0)
    failed_rules: int = Field(..., ge=0)
    warning_rules: int = Field(default=0, ge=0)
    rule_results: list[ComplianceRuleResult] = Field(default_factory=list)
    evaluated_at: UTCDatetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Automation Playbook & Run Schemas
# ---------------------------------------------------------------------------


class PlaybookStepSpec(BaseSchema):
    """Declarative step inside an automation/remediation playbook."""

    step_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=160)
    step_type: PlaybookStepType
    depends_on: list[str] = Field(default_factory=list)
    config: MetadataDict = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    retry_count: int = Field(default=0, ge=0, le=5)
    on_failure: Literal["abort", "continue", "rollback"] = Field(default="abort")
    requires_approval: bool = Field(default=False)


class PlaybookCreate(BaseSchema):
    """Create a reusable operational or self-healing remediation playbook."""

    name: str = Field(..., min_length=2, max_length=160)
    slug: SlugStr
    description: str | None = Field(default=None, max_length=1000)
    trigger_type: PlaybookTriggerType = Field(default=PlaybookTriggerType.MANUAL)
    schedule_cron: CronExpressionStr | None = None
    is_enabled: bool = Field(default=True)
    supports_dry_run: bool = Field(default=True)
    require_approval: bool = Field(default=False)
    max_concurrency: int = Field(default=10, ge=1, le=100)
    timeout_seconds: int = Field(default=600, ge=10, le=14_400)
    parameters_schema: MetadataDict = Field(
        default_factory=dict, description="JSON Schema describing runtime input parameters."
    )
    steps: list[PlaybookStepSpec] = Field(..., min_length=1, max_length=100)
    tags: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_step_dag(self) -> Self:
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("Playbook steps must have unique 'step_id' values.")
        id_set = set(step_ids)
        adj: dict[str, list[str]] = {}
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in id_set:
                    raise ValueError(
                        f"Step '{step.step_id}' depends on unknown step_id '{dep}'."
                    )
                if dep == step.step_id:
                    raise ValueError(f"Step '{step.step_id}' cannot depend on itself.")
            adj[step.step_id] = list(step.depends_on)
        # Detect dependency cycles via DFS three-color marking
        state: dict[str, int] = {}

        def _has_cycle(node: str) -> bool:
            state[node] = 1
            for nxt in adj.get(node, ()):
                nxt_state = state.get(nxt, 0)
                if nxt_state == 1 or (nxt_state == 0 and _has_cycle(nxt)):
                    return True
            state[node] = 2
            return False

        for sid in step_ids:
            if state.get(sid, 0) == 0 and _has_cycle(sid):
                raise ValueError("Playbook step dependencies contain a cycle.")
        return self


class PlaybookUpdate(BaseSchema):
    """Partial update for an automation playbook."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    trigger_type: PlaybookTriggerType | None = None
    schedule_cron: CronExpressionStr | None = None
    is_enabled: bool | None = None
    supports_dry_run: bool | None = None
    require_approval: bool | None = None
    max_concurrency: int | None = Field(default=None, ge=1, le=100)
    timeout_seconds: int | None = Field(default=None, ge=10, le=14_400)
    parameters_schema: MetadataDict | None = None
    steps: list[PlaybookStepSpec] | None = Field(default=None, min_length=1, max_length=100)
    tags: TagMap | None = None


class PlaybookRead(TenantEntityReadSchema):
    """Full representation of a playbook."""

    name: str
    slug: str
    description: str | None = None
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL
    schedule_cron: str | None = None
    is_enabled: bool = True
    supports_dry_run: bool = True
    require_approval: bool = False
    max_concurrency: int = 10
    timeout_seconds: int = 600
    parameters_schema: MetadataDict = Field(default_factory=dict)
    steps: list[PlaybookStepSpec] = Field(default_factory=list)
    run_count: int = Field(default=0, ge=0)
    last_run_at: UTCDatetime | None = None
    last_run_status: PlaybookRunStatus | None = None
    tags: TagMap = Field(default_factory=dict)


class PlaybookExecuteRequest(BaseSchema):
    """Invoke a playbook against target devices with runtime parameters."""

    target_device_ids: list[str] = Field(default_factory=list, max_length=500)
    target_group_ids: list[str] = Field(default_factory=list, max_length=50)
    parameters: MetadataDict = Field(default_factory=dict)
    dry_run: bool = Field(default=False)
    alert_event_id: str | None = None
    incident_id: str | None = None
    idempotency_key: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=500)


class PlaybookStepRunRead(BaseSchema):
    """Execution trace of a single step within a playbook run."""

    step_id: str
    step_name: str
    step_type: PlaybookStepType
    device_id: str | None = None
    status: PlaybookRunStatus
    started_at: UTCDatetime | None = None
    completed_at: UTCDatetime | None = None
    duration_ms: float | None = Field(default=None, ge=0.0)
    output: MetadataDict = Field(default_factory=dict)
    stdout: str | None = None
    error_message: str | None = None


class PlaybookRunRead(TenantEntityReadSchema):
    """Full audit and execution record for a playbook invocation."""

    playbook_id: str
    playbook_name: str | None = None
    status: PlaybookRunStatus = PlaybookRunStatus.PENDING
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL
    triggered_by_user_id: str | None = None
    approved_by_user_id: str | None = None
    alert_event_id: str | None = None
    incident_id: str | None = None
    dry_run: bool = False
    target_device_ids: list[str] = Field(default_factory=list)
    parameters: MetadataDict = Field(default_factory=dict)
    started_at: UTCDatetime | None = None
    completed_at: UTCDatetime | None = None
    duration_ms: float | None = Field(default=None, ge=0.0)
    step_runs: list[PlaybookStepRunRead] = Field(default_factory=list)
    summary: str | None = None
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Scheduled & Generated Report Schemas
# ---------------------------------------------------------------------------


class ScheduledReportCreate(BaseSchema):
    """Configure a recurring analytical report job."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=500)
    report_type: ReportType = Field(default=ReportType.EXECUTIVE_SUMMARY)
    output_format: ReportFormat = Field(default=ReportFormat.PDF)
    cron_expression: CronExpressionStr = Field(..., description="5-field cron schedule.")
    timezone_name: str = Field(default="UTC", max_length=64)
    lookback_days: int = Field(default=7, ge=1, le=365)
    recipients: list[EmailAddress] = Field(default_factory=list, max_length=50)
    notification_channel_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    filters: MetadataDict = Field(default_factory=dict)
    is_enabled: bool = Field(default=True)


class ScheduledReportUpdate(BaseSchema):
    """Partial update for a scheduled report."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=500)
    output_format: ReportFormat | None = None
    cron_expression: CronExpressionStr | None = None
    timezone_name: str | None = Field(default=None, max_length=64)
    lookback_days: int | None = Field(default=None, ge=1, le=365)
    recipients: list[EmailAddress] | None = None
    notification_channel_ids: list[str] | None = None
    site_ids: list[str] | None = None
    group_ids: list[str] | None = None
    filters: MetadataDict | None = None
    is_enabled: bool | None = None


class ScheduledReportRead(TenantEntityReadSchema):
    """Persisted scheduled report configuration."""

    name: str
    description: str | None = None
    report_type: ReportType
    output_format: ReportFormat
    cron_expression: str
    timezone_name: str = "UTC"
    lookback_days: int = 7
    recipients: list[str] = Field(default_factory=list)
    notification_channel_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    filters: MetadataDict = Field(default_factory=dict)
    is_enabled: bool = True
    last_run_at: UTCDatetime | None = None
    next_run_at: UTCDatetime | None = None


class GeneratedReportRead(TenantEntityReadSchema):
    """Artifact metadata for a completed or in-progress generated report."""

    schedule_id: str | None = None
    name: str
    report_type: ReportType
    output_format: ReportFormat
    status: ReportStatus = ReportStatus.QUEUED
    period_start: UTCDatetime
    period_end: UTCDatetime
    file_size_bytes: int | None = Field(default=None, ge=0)
    checksum_sha256: str | None = None
    download_url: str | None = None
    row_count: int | None = Field(default=None, ge=0)
    generated_at: UTCDatetime | None = None
    expires_at: UTCDatetime | None = None
    summary_metrics: MetadataDict = Field(default_factory=dict)
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Extensible Platform Plugin Schemas
# ---------------------------------------------------------------------------


class PluginRegister(BaseSchema):
    """Register a custom collector, notifier, remediator, or exporter plugin."""

    name: str = Field(..., min_length=2, max_length=120)
    slug: SlugStr
    version: SemVerStr = Field(default="1.0.0")
    category: PluginCategory
    description: str | None = Field(default=None, max_length=1000)
    author: str | None = Field(default=None, max_length=120)
    entrypoint: str | None = Field(
        default=None,
        max_length=256,
        description="Python dotted entrypoint (e.g. 'netpulse_ext.cisco:Collector').",
    )
    webhook_url: HttpUrlStr | None = Field(
        default=None, description="Optional remote HTTP plugin hook endpoint."
    )
    capabilities: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    config_schema: MetadataDict = Field(default_factory=dict)
    config: MetadataDict = Field(default_factory=dict)
    is_enabled: bool = Field(default=True)

    @model_validator(mode="after")
    def _require_entrypoint_or_webhook(self) -> Self:
        if not self.entrypoint and not self.webhook_url:
            raise ValueError("Plugin registration requires either 'entrypoint' or 'webhook_url'.")
        return self


class PluginUpdate(BaseSchema):
    """Partial update for a registered plugin."""

    version: SemVerStr | None = None
    description: str | None = Field(default=None, max_length=1000)
    webhook_url: HttpUrlStr | None = None
    capabilities: list[str] | None = None
    config: MetadataDict | None = None
    is_enabled: bool | None = None


class PluginRead(TenantEntityReadSchema):
    """Full representation of a registered platform plugin."""

    name: str
    slug: str
    version: str
    category: PluginCategory
    status: PluginStatus = PluginStatus.ACTIVE
    description: str | None = None
    author: str | None = None
    entrypoint: str | None = None
    webhook_url: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    config_schema: MetadataDict = Field(default_factory=dict)
    redacted_config: MetadataDict = Field(default_factory=dict)
    is_enabled: bool = True
    last_invoked_at: UTCDatetime | None = None
    invocation_count: int = Field(default=0, ge=0)
    last_error: str | None = None
