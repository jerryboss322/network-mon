"""Configuration management, compliance auditing, playbooks, reporting, and plugin ORM models.

Implements the network automation and governance persistence layer:
- ``ConfigSnapshot`` & ``ConfigDiff``: Versioned device configurations, SHA-256 drift detection, and unified diffs.
- ``CompliancePolicy`` & ``ComplianceEvaluation``: CIS/PCI-DSS/NIST/custom policy definitions and scored evaluations.
- ``PlaybookDefinition`` & ``PlaybookRun``: Automated remediation playbooks with approval gates and step logs.
- ``ScheduledReport`` & ``GeneratedReport``: Recurring executive/SLA/compliance reports and archived outputs.
- ``PluginRegistration``: Extensible collector/notifier/remediation plugin registry with health state.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
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
# Automation & Governance Constants
# ---------------------------------------------------------------------------

VALID_CONFIG_TYPES: frozenset[str] = frozenset(
    {"running", "startup", "candidate", "vlan", "acl", "routing", "firewall"}
)

VALID_DIFF_SEVERITIES: frozenset[str] = frozenset({"none", "low", "medium", "high", "critical"})

VALID_COMPLIANCE_STATUSES: frozenset[str] = frozenset(
    {"pending", "compliant", "non_compliant", "partial", "error"}
)

VALID_PLAYBOOK_TRIGGERS: frozenset[str] = frozenset(
    {"manual", "alert", "incident", "schedule", "webhook", "drift", "compliance"}
)

VALID_PLAYBOOK_RUN_STATUSES: frozenset[str] = frozenset(
    {"pending", "awaiting_approval", "running", "succeeded", "failed", "cancelled", "timed_out"}
)

TERMINAL_PLAYBOOK_STATUSES: frozenset[str] = frozenset(
    {"succeeded", "failed", "cancelled", "timed_out"}
)

VALID_REPORT_FORMATS: frozenset[str] = frozenset({"pdf", "csv", "json", "html", "markdown"})

VALID_PLUGIN_TYPES: frozenset[str] = frozenset(
    {"collector", "notifier", "enrichment", "remediation", "exporter", "compliance", "discovery"}
)

VALID_PLUGIN_HEALTH: frozenset[str] = frozenset(
    {"healthy", "degraded", "unhealthy", "unknown", "disabled"}
)

_HIGH_RISK_CONFIG_RE = re.compile(
    r"\b(aaa|access-list|ip\s+access-group|firewall|security-policy|crypto|ipsec|password|secret|snmp-server\s+community|router\s+bgp|neighbor\s+\S+\s+remote-as)\b",
    re.IGNORECASE,
)

_MEDIUM_RISK_CONFIG_RE = re.compile(
    r"\b(interface|vlan|ip\s+route|ospf|spanning-tree|ntp|logging|tacacs|radius|ssh|vty)\b",
    re.IGNORECASE,
)

_SECRET_KEY_MARKERS: tuple[str, ...] = ("secret", "token", "password", "api_key", "private_key", "passphrase")


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


# ---------------------------------------------------------------------------
# Configuration Snapshots & Diffs
# ---------------------------------------------------------------------------


class ConfigSnapshot(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Immutable versioned backup of a network device's configuration."""

    __tablename__ = "config_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "device_id",
            "config_type",
            "version_number",
            name="uq_config_snapshot_device_type_ver",
        ),
        CheckConstraint("version_number >= 1", name="config_version_positive"),
        CheckConstraint("size_bytes >= 0", name="config_size_non_negative"),
        Index("ix_config_snapshots_org_device_ts", "org_id", "device_id", "created_at"),
        Index("ix_config_snapshots_org_drift", "org_id", "device_id", "has_drift"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    config_type: Mapped[str] = mapped_column(String(50), nullable=False, default="running")
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content_text: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    captured_by: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    capture_method: Mapped[str] = mapped_column(String(50), nullable=False, default="ssh")
    has_drift: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    previous_snapshot_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("config_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    @validates("config_type")
    def _validate_config_type(self, _key: str, value: str) -> str:
        normalized = (value or "running").strip().lower()
        if normalized not in VALID_CONFIG_TYPES:
            raise ValueError(
                f"Invalid config_type '{value}'. Expected one of {sorted(VALID_CONFIG_TYPES)}."
            )
        return normalized

    @staticmethod
    def compute_sha256(content: str) -> str:
        """Compute canonical SHA-256 hex digest using LF-normalized newlines."""
        normalized = content.replace("\r\n", "\n")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def populate_integrity_fields(self, *, previous_hash: str | None = None) -> None:
        """Compute SHA-256 digest, byte size, and drift status against a prior snapshot."""
        self.sha256_hash = self.compute_sha256(self.content_text or "")
        self.size_bytes = len((self.content_text or "").encode("utf-8"))
        if previous_hash is not None:
            self.has_drift = self.sha256_hash != previous_hash

    @property
    def line_count(self) -> int:
        if not self.content_text:
            return 0
        return len(self.content_text.splitlines())

    def diff_against(self, other: ConfigSnapshot) -> tuple[str, int, int]:
        """Compute a unified diff from ``self`` (base) to ``other`` (target).

        Returns ``(unified_diff_text, lines_added, lines_removed)``.
        """
        base_lines = (self.content_text or "").splitlines(keepends=True)
        target_lines = (other.content_text or "").splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                base_lines,
                target_lines,
                fromfile=f"{self.config_type}:v{self.version_number}",
                tofile=f"{other.config_type}:v{other.version_number}",
                lineterm="",
            )
        )
        added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
        return "\n".join(ln.rstrip("\n") for ln in diff_lines), added, removed

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "config_type": self.config_type,
            "version_number": self.version_number,
            "sha256_hash": self.sha256_hash,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "captured_by": self.captured_by,
            "capture_method": self.capture_method,
            "has_drift": self.has_drift,
            "previous_snapshot_id": self.previous_snapshot_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_content:
            payload["content_text"] = self.content_text
        return payload

    def __repr__(self) -> str:
        return (
            f"<ConfigSnapshot id={self.id!r} device_id={self.device_id!r} "
            f"type={self.config_type!r} v{self.version_number}>"
        )


class ConfigDiff(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Persisted configuration comparison and risk assessment between two snapshots."""

    __tablename__ = "config_diffs"
    __table_args__ = (
        CheckConstraint("lines_added >= 0", name="diff_lines_added_non_negative"),
        CheckConstraint("lines_removed >= 0", name="diff_lines_removed_non_negative"),
        Index("ix_config_diffs_org_device_ts", "org_id", "device_id", "created_at"),
        Index("ix_config_diffs_org_severity", "org_id", "severity_assessment"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    base_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("config_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("config_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    lines_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lines_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unified_diff: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity_assessment: Mapped[str] = mapped_column(
        String(50), nullable=False, default="low", index=True
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    base_snapshot: Mapped[ConfigSnapshot] = relationship(
        "ConfigSnapshot", foreign_keys=[base_snapshot_id]
    )
    target_snapshot: Mapped[ConfigSnapshot] = relationship(
        "ConfigSnapshot", foreign_keys=[target_snapshot_id]
    )

    @validates("severity_assessment")
    def _validate_severity(self, _key: str, value: str) -> str:
        normalized = (value or "low").strip().lower()
        if normalized not in VALID_DIFF_SEVERITIES:
            raise ValueError(
                f"Invalid severity_assessment '{value}'. Expected one of {sorted(VALID_DIFF_SEVERITIES)}."
            )
        return normalized

    @property
    def is_reviewed(self) -> bool:
        return self.reviewed_at is not None

    @property
    def total_changed_lines(self) -> int:
        return (self.lines_added or 0) + (self.lines_removed or 0)

    def mark_reviewed(self, reviewer: str, *, at: datetime | None = None) -> None:
        self.reviewed_by = reviewer
        self.reviewed_at = at or utcnow()

    @staticmethod
    def assess_diff_severity(unified_diff: str, lines_added: int, lines_removed: int) -> str:
        """Heuristic risk assessment based on security/routing keywords and change volume."""
        total = lines_added + lines_removed
        if total == 0:
            return "none"
        changed_lines = [
            ln[1:]
            for ln in unified_diff.splitlines()
            if (ln.startswith("+") and not ln.startswith("+++"))
            or (ln.startswith("-") and not ln.startswith("---"))
        ]
        changed_blob = "\n".join(changed_lines)
        high_hits = len(_HIGH_RISK_CONFIG_RE.findall(changed_blob))
        if high_hits >= 3 or (high_hits >= 1 and total >= 25):
            return "critical"
        if high_hits >= 1:
            return "high"
        if _MEDIUM_RISK_CONFIG_RE.search(changed_blob) or total >= 20:
            return "medium"
        return "low"

    @classmethod
    def from_snapshots(cls, base: ConfigSnapshot, target: ConfigSnapshot) -> ConfigDiff:
        """Construct an unsaved ConfigDiff directly from two ConfigSnapshot instances."""
        diff_text, added, removed = base.diff_against(target)
        severity = cls.assess_diff_severity(diff_text, added, removed)
        return cls(
            org_id=target.org_id,
            device_id=target.device_id,
            base_snapshot_id=base.id,
            target_snapshot_id=target.id,
            lines_added=added,
            lines_removed=removed,
            unified_diff=diff_text,
            severity_assessment=severity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "base_snapshot_id": self.base_snapshot_id,
            "target_snapshot_id": self.target_snapshot_id,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "total_changed_lines": self.total_changed_lines,
            "unified_diff": self.unified_diff,
            "severity_assessment": self.severity_assessment,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "is_reviewed": self.is_reviewed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<ConfigDiff id={self.id!r} +{self.lines_added}/-{self.lines_removed} "
            f"severity={self.severity_assessment!r}>"
        )


# ---------------------------------------------------------------------------
# Compliance Policies & Evaluations
# ---------------------------------------------------------------------------


class CompliancePolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Declarative configuration compliance benchmark (CIS, PCI-DSS, NIST, or custom)."""

    __tablename__ = "compliance_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", "version", name="uq_compliance_policy_org_name_ver"),
        Index("ix_compliance_policies_org_enabled", "org_id", "enabled"),
        Index("ix_compliance_policies_org_framework", "org_id", "framework"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    framework: Mapped[str] = mapped_column(String(64), nullable=False, default="custom", index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rules_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    target_vendors_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    evaluations: Mapped[list[ComplianceEvaluation]] = relationship(
        "ComplianceEvaluation",
        back_populates="policy",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("rules_json")
    def _validate_rules(self, _key: str, value: Any) -> list[dict[str, Any]]:
        return [dict(r) if isinstance(r, dict) else {"rule": r} for r in _coerce_json_list(value)]

    @validates("target_vendors_json")
    def _validate_vendors(self, _key: str, value: Any) -> list[str]:
        return [str(v).strip().lower() for v in _coerce_json_list(value) if str(v).strip()]

    @property
    def rule_count(self) -> int:
        return len(self.rules_json or [])

    def applies_to_vendor(self, vendor: str | None) -> bool:
        """Return True if this policy applies to ``vendor`` (empty target list = all vendors)."""
        targets = self.target_vendors_json or []
        if not targets:
            return True
        if not vendor:
            return False
        normalized = vendor.strip().lower()
        return any(t in normalized or normalized in t for t in targets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "framework": self.framework,
            "version": self.version,
            "description": self.description,
            "rules_json": self.rules_json or [],
            "rule_count": self.rule_count,
            "target_vendors_json": self.target_vendors_json or [],
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<CompliancePolicy id={self.id!r} name={self.name!r} "
            f"framework={self.framework!r} rules={self.rule_count}>"
        )


class ComplianceEvaluation(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Scored compliance audit result for a device against a CompliancePolicy."""

    __tablename__ = "compliance_evaluations"
    __table_args__ = (
        CheckConstraint("score_pct >= 0.0 AND score_pct <= 100.0", name="compliance_score_range"),
        CheckConstraint("passed_count >= 0 AND failed_count >= 0", name="compliance_counts_non_negative"),
        Index(
            "ix_compliance_eval_org_policy_device_ts",
            "org_id",
            "policy_id",
            "device_id",
            "evaluated_at",
        ),
        Index("ix_compliance_eval_org_status_ts", "org_id", "status", "evaluated_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("compliance_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("config_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    score_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    passed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    policy: Mapped[CompliancePolicy] = relationship("CompliancePolicy", back_populates="evaluations")
    snapshot: Mapped[ConfigSnapshot | None] = relationship("ConfigSnapshot")

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "pending").strip().lower()
        if normalized not in VALID_COMPLIANCE_STATUSES:
            raise ValueError(
                f"Invalid compliance status '{value}'. Expected one of {sorted(VALID_COMPLIANCE_STATUSES)}."
            )
        return normalized

    @validates("findings_json")
    def _validate_findings(self, _key: str, value: Any) -> list[dict[str, Any]]:
        return [dict(f) if isinstance(f, dict) else {"message": str(f)} for f in _coerce_json_list(value)]

    def recompute_score(self) -> float:
        """Recalculate score_pct and status from passed_count and failed_count."""
        passed = self.passed_count or 0
        failed = self.failed_count or 0
        total = passed + failed
        if total <= 0:
            self.score_pct = 100.0
            self.status = "compliant"
            return self.score_pct
        self.score_pct = round((passed / total) * 100.0, 2)
        if failed == 0:
            self.status = "compliant"
        elif passed == 0:
            self.status = "non_compliant"
        else:
            self.status = "partial"
        return self.score_pct

    def critical_failures(self) -> list[dict[str, Any]]:
        """Return failed findings marked as critical or high severity."""
        return [
            f
            for f in (self.findings_json or [])
            if not f.get("passed", False)
            and str(f.get("severity", "")).lower() in {"critical", "high"}
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "policy_id": self.policy_id,
            "device_id": self.device_id,
            "snapshot_id": self.snapshot_id,
            "status": self.status,
            "score_pct": self.score_pct,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "findings_json": self.findings_json or [],
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<ComplianceEvaluation id={self.id!r} policy_id={self.policy_id!r} "
            f"status={self.status!r} score={self.score_pct}%>"
        )


# ---------------------------------------------------------------------------
# Remediation Playbooks & Runs
# ---------------------------------------------------------------------------


class PlaybookDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Multi-step automation or remediation workflow triggered manually or by events."""

    __tablename__ = "playbook_definitions"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_playbook_def_org_name"),
        CheckConstraint("timeout_seconds > 0", name="playbook_timeout_positive"),
        CheckConstraint("version >= 1", name="playbook_version_positive"),
        Index("ix_playbook_defs_org_enabled", "org_id", "enabled"),
        Index("ix_playbook_defs_org_trigger", "org_id", "trigger_type"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False, default="manual", index=True)
    trigger_config_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    steps_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    require_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    runs: Mapped[list[PlaybookRun]] = relationship(
        "PlaybookRun",
        back_populates="playbook",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("trigger_type")
    def _validate_trigger_type(self, _key: str, value: str) -> str:
        normalized = (value or "manual").strip().lower()
        if normalized not in VALID_PLAYBOOK_TRIGGERS:
            raise ValueError(
                f"Invalid trigger_type '{value}'. Expected one of {sorted(VALID_PLAYBOOK_TRIGGERS)}."
            )
        return normalized

    @validates("trigger_config_json")
    def _validate_trigger_config(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @validates("steps_json")
    def _validate_steps(self, _key: str, value: Any) -> list[dict[str, Any]]:
        return [dict(s) if isinstance(s, dict) else {"action": str(s)} for s in _coerce_json_list(value)]

    @property
    def step_count(self) -> int:
        return len(self.steps_json or [])

    def bump_version(self) -> int:
        self.version = (self.version or 1) + 1
        return self.version

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "trigger_type": self.trigger_type,
            "trigger_config_json": self.trigger_config_json or {},
            "steps_json": self.steps_json or [],
            "step_count": self.step_count,
            "timeout_seconds": self.timeout_seconds,
            "require_approval": self.require_approval,
            "enabled": self.enabled,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PlaybookDefinition id={self.id!r} name={self.name!r} "
            f"trigger={self.trigger_type!r} v{self.version}>"
        )


class PlaybookRun(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Execution instance and step-by-step output ledger for a PlaybookDefinition."""

    __tablename__ = "playbook_runs"
    __table_args__ = (
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="playbook_duration_non_negative"),
        Index("ix_playbook_runs_org_playbook_ts", "org_id", "playbook_id", "created_at"),
        Index("ix_playbook_runs_org_status_ts", "org_id", "status", "created_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    playbook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("playbook_definitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    triggered_by: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    trigger_context_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    step_results_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    playbook: Mapped[PlaybookDefinition] = relationship("PlaybookDefinition", back_populates="runs")

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "pending").strip().lower()
        if normalized not in VALID_PLAYBOOK_RUN_STATUSES:
            raise ValueError(
                f"Invalid PlaybookRun status '{value}'. Expected one of {sorted(VALID_PLAYBOOK_RUN_STATUSES)}."
            )
        return normalized

    @validates("trigger_context_json")
    def _validate_trigger_context(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @validates("step_results_json")
    def _validate_step_results(self, _key: str, value: Any) -> list[dict[str, Any]]:
        return [dict(r) if isinstance(r, dict) else {"output": r} for r in _coerce_json_list(value)]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_PLAYBOOK_STATUSES

    def start(self, *, at: datetime | None = None) -> None:
        self.status = "running"
        self.started_at = at or utcnow()
        self.completed_at = None
        self.error_message = None

    def record_step_result(
        self,
        step_name: str,
        *,
        status: str,
        output: Any = None,
        duration_ms: int | None = None,
        error: str | None = None,
    ) -> None:
        """Append an individual step execution record to ``step_results_json``."""
        results = list(self.step_results_json or [])
        results.append(
            {
                "step": step_name,
                "status": status,
                "output": output,
                "duration_ms": duration_ms,
                "error": error,
                "timestamp": utcnow().isoformat(),
            }
        )
        self.step_results_json = results

    def complete(
        self,
        *,
        succeeded: bool = True,
        status: str | None = None,
        error_message: str | None = None,
        at: datetime | None = None,
    ) -> None:
        now = at or utcnow()
        self.completed_at = now
        self.status = status or ("succeeded" if succeeded else "failed")
        self.error_message = error_message
        start = _ensure_utc(self.started_at)
        end = _ensure_utc(now)
        if start is not None and end is not None:
            self.duration_ms = max(0, int((end - start).total_seconds() * 1000))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "playbook_id": self.playbook_id,
            "triggered_by": self.triggered_by,
            "trigger_context_json": self.trigger_context_json or {},
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "step_results_json": self.step_results_json or [],
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PlaybookRun id={self.id!r} playbook_id={self.playbook_id!r} "
            f"status={self.status!r} duration_ms={self.duration_ms}>"
        )


# ---------------------------------------------------------------------------
# Scheduled & Generated Reports
# ---------------------------------------------------------------------------


class ScheduledReport(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Recurring report schedule (executive summary, SLA/SLO, compliance, capacity)."""

    __tablename__ = "scheduled_reports"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_scheduled_report_org_name"),
        Index("ix_scheduled_reports_org_enabled_next", "org_id", "enabled", "next_run_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    report_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="executive_summary", index=True
    )
    report_format: Mapped[str] = mapped_column(String(20), nullable=False, default="pdf")
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False, default="0 8 * * 1")
    recipients_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    generated_reports: Mapped[list[GeneratedReport]] = relationship(
        "GeneratedReport", back_populates="scheduled_report"
    )

    @validates("report_format")
    def _validate_format(self, _key: str, value: str) -> str:
        normalized = (value or "pdf").strip().lower()
        if normalized not in VALID_REPORT_FORMATS:
            raise ValueError(
                f"Invalid report_format '{value}'. Expected one of {sorted(VALID_REPORT_FORMATS)}."
            )
        return normalized

    @validates("recipients_json")
    def _validate_recipients(self, _key: str, value: Any) -> list[str]:
        return [str(r).strip() for r in _coerce_json_list(value) if str(r).strip()]

    @validates("parameters_json")
    def _validate_parameters(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    def is_due(self, *, now: datetime | None = None) -> bool:
        """Return True when enabled and ``next_run_at`` has passed."""
        if self.enabled is False or self.next_run_at is None:
            return False
        ref = _ensure_utc(now) or utcnow()
        due_at = _ensure_utc(self.next_run_at)
        return due_at is not None and due_at <= ref

    def mark_executed(
        self,
        *,
        executed_at: datetime | None = None,
        next_run_at: datetime | None = None,
    ) -> None:
        self.last_run_at = executed_at or utcnow()
        if next_run_at is not None:
            self.next_run_at = next_run_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "report_type": self.report_type,
            "report_format": self.report_format,
            "cron_expression": self.cron_expression,
            "recipients_json": self.recipients_json or [],
            "parameters_json": self.parameters_json or {},
            "enabled": self.enabled,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<ScheduledReport id={self.id!r} name={self.name!r} "
            f"type={self.report_type!r} cron={self.cron_expression!r}>"
        )


class GeneratedReport(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Rendered report artifact covering a specific time period."""

    __tablename__ = "generated_reports"
    __table_args__ = (
        CheckConstraint("period_end >= period_start", name="report_period_valid"),
        CheckConstraint("size_bytes >= 0", name="report_size_non_negative"),
        Index("ix_generated_reports_org_created", "org_id", "created_at"),
        Index("ix_generated_reports_schedule_ts", "scheduled_report_id", "created_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scheduled_report_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scheduled_reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    report_format: Mapped[str] = mapped_column(String(20), nullable=False, default="json")
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    content_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generated_by: Mapped[str] = mapped_column(String(120), nullable=False, default="scheduler")

    scheduled_report: Mapped[ScheduledReport | None] = relationship(
        "ScheduledReport", back_populates="generated_reports"
    )

    @validates("report_format")
    def _validate_format(self, _key: str, value: str) -> str:
        normalized = (value or "json").strip().lower()
        if normalized not in VALID_REPORT_FORMATS:
            raise ValueError(
                f"Invalid report_format '{value}'. Expected one of {sorted(VALID_REPORT_FORMATS)}."
            )
        return normalized

    @validates("summary_json")
    def _validate_summary(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @property
    def period_duration_hours(self) -> float:
        start = _ensure_utc(self.period_start)
        end = _ensure_utc(self.period_end)
        if start is None or end is None:
            return 0.0
        return round(max(0.0, (end - start).total_seconds() / 3600.0), 2)

    def sync_size_bytes(self) -> int:
        self.size_bytes = len((self.content_text or "").encode("utf-8"))
        return self.size_bytes

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "org_id": self.org_id,
            "scheduled_report_id": self.scheduled_report_id,
            "name": self.name,
            "report_format": self.report_format,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "period_duration_hours": self.period_duration_hours,
            "summary_json": self.summary_json or {},
            "size_bytes": self.size_bytes,
            "generated_by": self.generated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_content:
            payload["content_text"] = self.content_text
        return payload

    def __repr__(self) -> str:
        return (
            f"<GeneratedReport id={self.id!r} name={self.name!r} "
            f"format={self.report_format!r} size={self.size_bytes}B>"
        )


# ---------------------------------------------------------------------------
# Extensible Plugin Registry
# ---------------------------------------------------------------------------


class PluginRegistration(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Registered extension plugin (collector, notifier, enrichment, remediation)."""

    __tablename__ = "plugin_registrations"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_plugin_registration_org_name"),
        Index("ix_plugin_registrations_org_type_enabled", "org_id", "plugin_type", "enabled"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    plugin_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    entrypoint: Mapped[str] = mapped_column(String(255), nullable=False)
    config_schema_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    config_values_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    health_status: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown", index=True)

    @validates("plugin_type")
    def _validate_plugin_type(self, _key: str, value: str) -> str:
        normalized = (value or "collector").strip().lower()
        if normalized not in VALID_PLUGIN_TYPES:
            raise ValueError(
                f"Invalid plugin_type '{value}'. Expected one of {sorted(VALID_PLUGIN_TYPES)}."
            )
        return normalized

    @validates("health_status")
    def _validate_health_status(self, _key: str, value: str) -> str:
        normalized = (value or "unknown").strip().lower()
        if normalized not in VALID_PLUGIN_HEALTH:
            raise ValueError(
                f"Invalid health_status '{value}'. Expected one of {sorted(VALID_PLUGIN_HEALTH)}."
            )
        return normalized

    @validates("config_schema_json", "config_values_json")
    def _validate_config_dicts(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    def validate_required_config(self) -> list[str]:
        """Return list of missing required configuration keys defined in ``config_schema_json``."""
        schema = self.config_schema_json or {}
        required = schema.get("required", [])
        if not isinstance(required, list):
            return []
        values = self.config_values_json or {}
        return [str(k) for k in required if k not in values or values[k] in (None, "")]

    def set_health(self, status: str) -> None:
        self.health_status = status

    def _masked_config_values(self) -> dict[str, Any]:
        masked: dict[str, Any] = {}
        for key, val in (self.config_values_json or {}).items():
            lower_key = key.lower()
            if any(marker in lower_key for marker in _SECRET_KEY_MARKERS) and val:
                masked[key] = "***"
            else:
                masked[key] = val
        return masked

    def to_dict(self, *, mask_secrets: bool = True) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "plugin_type": self.plugin_type,
            "version": self.version,
            "entrypoint": self.entrypoint,
            "config_schema_json": self.config_schema_json or {},
            "config_values_json": (
                self._masked_config_values() if mask_secrets else (self.config_values_json or {})
            ),
            "enabled": self.enabled,
            "health_status": self.health_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PluginRegistration id={self.id!r} name={self.name!r} "
            f"type={self.plugin_type!r} health={self.health_status!r}>"
        )


__all__ = [
    "ConfigSnapshot",
    "ConfigDiff",
    "CompliancePolicy",
    "ComplianceEvaluation",
    "PlaybookDefinition",
    "PlaybookRun",
    "ScheduledReport",
    "GeneratedReport",
    "PluginRegistration",
    "VALID_CONFIG_TYPES",
    "VALID_DIFF_SEVERITIES",
    "VALID_COMPLIANCE_STATUSES",
    "VALID_PLAYBOOK_TRIGGERS",
    "VALID_PLAYBOOK_RUN_STATUSES",
    "TERMINAL_PLAYBOOK_STATUSES",
    "VALID_REPORT_FORMATS",
    "VALID_PLUGIN_TYPES",
    "VALID_PLUGIN_HEALTH",
]
