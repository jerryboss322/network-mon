"""Telemetry, flow, syslog, BGP, synthetic monitoring, and edge-agent ORM models.

This module defines the time-series and telemetry persistence schema for NetPulse:
- ``MetricDefinition``: Catalog of metric metadata, units, aggregation defaults, and retention.
- ``SnmpMetricSample``: High-frequency SNMP device health, interface throughput, and raw OID captures.
- ``IcmpMetricSample``: ICMP reachability, RTT quantiles, jitter, TTL, and packet-loss samples.
- ``SyntheticProbeConfig`` & ``SyntheticProbeResult``: Active HTTP/HTTPS/TCP/DNS/TLS probes and timings.
- ``HostMetricSample``: OS-level host resource utilization (CPU breakdown, load, memory, disk, network, FDs).
- ``MetricRollup``: Pre-aggregated downsampled buckets (1m, 5m, 15m, 1h, 1d) with percentiles.
- ``SyslogEvent``: RFC 5424/3164 syslog events with structured fields and deduplication fingerprints.
- ``NetFlowRecord``: NetFlow/IPFIX/sFlow 5-tuple traffic telemetry with ASN and application classification.
- ``BgpPeerSession``: BGP neighbor state machine snapshots, prefix counts, and 24-hour flap counters.
- ``EdgeAgent``: Distributed remote collector agents, capabilities, heartbeat health, and buffer metrics.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
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
# Protocol & Standards Constants
# ---------------------------------------------------------------------------

VALID_METRIC_CATEGORIES: frozenset[str] = frozenset(
    {"snmp", "icmp", "synthetic", "host", "flow", "syslog", "bgp", "agent", "custom"}
)

VALID_AGGREGATIONS: frozenset[str] = frozenset(
    {"avg", "sum", "min", "max", "p50", "p95", "p99", "last", "count"}
)

VALID_BUCKET_SIZES: dict[str, int] = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "6h": 21600,
    "1d": 86400,
}

VALID_PROBE_TYPES: frozenset[str] = frozenset(
    {"http", "https", "tcp", "dns", "tls", "icmp", "grpc", "udp"}
)

DEFAULT_PROBE_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "tls": 443,
    "dns": 53,
    "grpc": 443,
}

VALID_BGP_STATES: frozenset[str] = frozenset(
    {"idle", "connect", "active", "opensent", "openconfirm", "established"}
)

SYSLOG_SEVERITY_NAMES: dict[int, str] = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

SYSLOG_FACILITY_NAMES: dict[int, str] = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

IANA_PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

TCP_FLAG_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)

_FINGERPRINT_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_FINGERPRINT_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FINGERPRINT_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_FINGERPRINT_NUM_RE = re.compile(r"\b\d+\b")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize naive datetimes (e.g. from SQLite) to timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_json_dict(value: Any) -> dict[str, Any]:
    """Accept dicts, None, or JSON-encoded strings and normalize to a dict."""
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
        raise ValueError("Expected a JSON object for dictionary column.")
    raise ValueError(f"Unsupported value type {type(value).__name__} for JSON object column.")


def _coerce_json_list(value: Any) -> list[Any]:
    """Accept lists, tuples, None, or JSON-encoded strings and normalize to a list."""
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
        raise ValueError("Expected a JSON array for list column.")
    raise ValueError(f"Unsupported value type {type(value).__name__} for JSON array column.")


# ---------------------------------------------------------------------------
# Metric Catalog
# ---------------------------------------------------------------------------


class MetricDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Canonical registry entry describing a collectible or derived metric."""

    __tablename__ = "metric_definitions"
    __table_args__ = (
        CheckConstraint("retention_days > 0", name="retention_days_positive"),
        Index("ix_metric_definitions_category_name", "category", "name"),
    )

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="snmp", index=True)
    unit: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    aggregation_default: Mapped[str] = mapped_column(String(20), nullable=False, default="avg")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    is_counter: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    @validates("aggregation_default")
    def _validate_aggregation(self, _key: str, value: str) -> str:
        normalized = (value or "avg").strip().lower()
        if normalized not in VALID_AGGREGATIONS:
            raise ValueError(
                f"Invalid aggregation_default '{value}'. Expected one of {sorted(VALID_AGGREGATIONS)}."
            )
        return normalized

    @property
    def is_gauge(self) -> bool:
        """Return True when this metric represents an instantaneous gauge."""
        return not self.is_counter

    def compute_rate(
        self,
        previous_value: float,
        current_value: float,
        elapsed_seconds: float,
        *,
        counter_bits: int = 64,
    ) -> float:
        """Compute per-second rate for counter metrics, handling 32/64-bit counter wrap."""
        if elapsed_seconds <= 0:
            return 0.0
        if not self.is_counter:
            return current_value
        delta = current_value - previous_value
        if delta < 0:
            modulus = float(1 << counter_bits)
            delta = (modulus - previous_value) + current_value
            if delta < 0:
                return 0.0
        return delta / elapsed_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "unit": self.unit,
            "description": self.description,
            "aggregation_default": self.aggregation_default,
            "retention_days": self.retention_days,
            "is_counter": self.is_counter,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<MetricDefinition id={self.id!r} name={self.name!r} "
            f"category={self.category!r} unit={self.unit!r}>"
        )


# ---------------------------------------------------------------------------
# SNMP Telemetry
# ---------------------------------------------------------------------------


class SnmpMetricSample(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """Point-in-time SNMP polling sample for a managed network device."""

    __tablename__ = "snmp_metric_samples"
    __table_args__ = (
        CheckConstraint("cpu_pct IS NULL OR (cpu_pct >= 0.0 AND cpu_pct <= 100.0)", name="cpu_pct_range"),
        CheckConstraint("mem_pct IS NULL OR (mem_pct >= 0.0 AND mem_pct <= 100.0)", name="mem_pct_range"),
        Index("ix_snmp_samples_org_device_ts", "org_id", "device_id", "timestamp"),
        Index("ix_snmp_samples_device_ts", "device_id", "timestamp"),
        Index("ix_snmp_samples_org_ts", "org_id", "timestamp"),
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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    cpu_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_used_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_total_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    temp_celsius: Mapped[float | None] = mapped_column(Float, nullable=True)
    if_in_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    if_out_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    if_errors: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    if_discards: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    active_connections: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sys_uptime_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    raw_oids_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    @validates("raw_oids_json")
    def _validate_raw_oids(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @property
    def total_throughput_mbps(self) -> float:
        """Combined inbound + outbound interface throughput in Mbps."""
        return float(self.if_in_mbps or 0.0) + float(self.if_out_mbps or 0.0)

    @property
    def effective_mem_pct(self) -> float | None:
        """Return explicit memory percentage or derive it from used/total MB."""
        if self.mem_pct is not None:
            return self.mem_pct
        if self.mem_used_mb is not None and self.mem_total_mb and self.mem_total_mb > 0:
            return round((self.mem_used_mb / self.mem_total_mb) * 100.0, 2)
        return None

    @property
    def uptime_days(self) -> float | None:
        """System uptime converted to fractional days."""
        if self.sys_uptime_seconds is None:
            return None
        return round(self.sys_uptime_seconds / 86400.0, 2)

    def get_oid(self, oid: str, default: Any = None) -> Any:
        """Safely retrieve a raw OID value from the captured OID map."""
        return (self.raw_oids_json or {}).get(oid, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "cpu_pct": self.cpu_pct,
            "mem_pct": self.effective_mem_pct,
            "mem_used_mb": self.mem_used_mb,
            "mem_total_mb": self.mem_total_mb,
            "temp_celsius": self.temp_celsius,
            "if_in_mbps": self.if_in_mbps,
            "if_out_mbps": self.if_out_mbps,
            "total_throughput_mbps": self.total_throughput_mbps,
            "if_errors": self.if_errors,
            "if_discards": self.if_discards,
            "active_connections": self.active_connections,
            "sys_uptime_seconds": self.sys_uptime_seconds,
            "reachable": self.reachable,
            "raw_oids_json": self.raw_oids_json or {},
        }

    def __repr__(self) -> str:
        return (
            f"<SnmpMetricSample id={self.id!r} device_id={self.device_id!r} "
            f"cpu={self.cpu_pct} reachable={self.reachable}>"
        )


# ---------------------------------------------------------------------------
# ICMP Telemetry
# ---------------------------------------------------------------------------


class IcmpMetricSample(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """ICMP echo probe measurement capturing latency distribution, jitter, and loss."""

    __tablename__ = "icmp_metric_samples"
    __table_args__ = (
        CheckConstraint(
            "packet_loss_pct >= 0.0 AND packet_loss_pct <= 100.0",
            name="packet_loss_pct_range",
        ),
        CheckConstraint("packets_sent >= 0 AND packets_received >= 0", name="packets_non_negative"),
        Index("ix_icmp_samples_org_device_ts", "org_id", "device_id", "timestamp"),
        Index("ix_icmp_samples_org_ip_ts", "org_id", "target_ip", "timestamp"),
        Index("ix_icmp_samples_org_status_ts", "org_id", "status", "timestamp"),
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
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    avg_rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    min_rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    p95_rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    jitter_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    packets_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    packets_received: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="up", index=True)

    @property
    def is_reachable(self) -> bool:
        """Return True when at least one echo reply was received."""
        received = self.packets_received or 0
        loss = self.packet_loss_pct if self.packet_loss_pct is not None else 0.0
        return received > 0 and loss < 100.0

    @property
    def latency_spread_ms(self) -> float | None:
        """Difference between max and min RTT in milliseconds."""
        if self.max_rtt_ms is None or self.min_rtt_ms is None:
            return None
        return round(max(0.0, self.max_rtt_ms - self.min_rtt_ms), 3)

    def compute_loss_pct(self) -> float:
        """Recompute packet loss percentage from sent/received packet counters."""
        sent = self.packets_sent or 0
        received = self.packets_received or 0
        if sent <= 0:
            self.packet_loss_pct = 100.0
        else:
            lost = max(0, sent - received)
            self.packet_loss_pct = round((lost / sent) * 100.0, 2)
        return self.packet_loss_pct

    def classify_status(self, *, degraded_loss_pct: float = 5.0, degraded_rtt_ms: float = 150.0) -> str:
        """Derive and update status ('up', 'degraded', 'down') from loss and latency."""
        received = self.packets_received or 0
        loss = self.packet_loss_pct if self.packet_loss_pct is not None else 0.0
        if received <= 0 or loss >= 100.0:
            self.status = "down"
        elif loss >= degraded_loss_pct or (
            self.avg_rtt_ms is not None and self.avg_rtt_ms >= degraded_rtt_ms
        ):
            self.status = "degraded"
        else:
            self.status = "up"
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "target_ip": self.target_ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "avg_rtt_ms": self.avg_rtt_ms,
            "min_rtt_ms": self.min_rtt_ms,
            "max_rtt_ms": self.max_rtt_ms,
            "p95_rtt_ms": self.p95_rtt_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "jitter_ms": self.jitter_ms,
            "ttl": self.ttl,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "status": self.status,
        }

    def __repr__(self) -> str:
        return (
            f"<IcmpMetricSample id={self.id!r} target_ip={self.target_ip!r} "
            f"avg_rtt_ms={self.avg_rtt_ms} loss={self.packet_loss_pct}%>"
        )


# ---------------------------------------------------------------------------
# Synthetic Probes
# ---------------------------------------------------------------------------


class SyntheticProbeConfig(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Configuration for an active synthetic monitor (HTTP/HTTPS/TCP/DNS/TLS/gRPC)."""

    __tablename__ = "synthetic_probe_configs"
    __table_args__ = (
        CheckConstraint("interval_seconds >= 5", name="interval_min_5s"),
        CheckConstraint("timeout_seconds > 0", name="timeout_positive"),
        CheckConstraint("tls_warn_days >= 0", name="tls_warn_days_non_negative"),
        Index("ix_synthetic_probes_org_enabled", "org_id", "enabled"),
        Index("ix_synthetic_probes_org_type", "org_id", "probe_type"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    probe_type: Mapped[str] = mapped_column(String(50), nullable=False, default="http", index=True)
    target_url_or_host: Mapped[str] = mapped_column(String(512), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=10.0)
    expected_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, default=200)
    expected_body_substring: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_verify: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tls_warn_days: Mapped[int] = mapped_column(Integer, nullable=False, default=14)
    headers_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    locations_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    results: Mapped[list[SyntheticProbeResult]] = relationship(
        "SyntheticProbeResult",
        back_populates="probe",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("probe_type")
    def _validate_probe_type(self, _key: str, value: str) -> str:
        normalized = (value or "http").strip().lower()
        if normalized not in VALID_PROBE_TYPES:
            raise ValueError(
                f"Invalid probe_type '{value}'. Expected one of {sorted(VALID_PROBE_TYPES)}."
            )
        return normalized

    @validates("headers_json")
    def _validate_headers(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @validates("locations_json")
    def _validate_locations(self, _key: str, value: Any) -> list[str]:
        return [str(loc) for loc in _coerce_json_list(value)]

    @property
    def effective_port(self) -> int | None:
        """Return explicit port or well-known default port for this probe type."""
        if self.port is not None:
            return self.port
        return DEFAULT_PROBE_PORTS.get(self.probe_type)

    def effective_locations(self) -> list[str]:
        """Return configured vantage points, defaulting to ['default']."""
        locs = self.locations_json or []
        return list(locs) if locs else ["default"]

    def matches_response(self, status_code: int | None, body: str | None = None) -> tuple[bool, str | None]:
        """Evaluate whether a probe response satisfies configured status & body assertions."""
        if self.expected_status_code is not None and status_code != self.expected_status_code:
            return (
                False,
                f"Expected status code {self.expected_status_code}, got {status_code}",
            )
        if self.expected_body_substring:
            if not body or self.expected_body_substring not in body:
                return (
                    False,
                    f"Expected body substring {self.expected_body_substring!r} not found",
                )
        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "name": self.name,
            "probe_type": self.probe_type,
            "target_url_or_host": self.target_url_or_host,
            "port": self.effective_port,
            "interval_seconds": self.interval_seconds,
            "timeout_seconds": self.timeout_seconds,
            "expected_status_code": self.expected_status_code,
            "expected_body_substring": self.expected_body_substring,
            "tls_verify": self.tls_verify,
            "tls_warn_days": self.tls_warn_days,
            "headers_json": self.headers_json or {},
            "enabled": self.enabled,
            "locations_json": self.effective_locations(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<SyntheticProbeConfig id={self.id!r} name={self.name!r} "
            f"type={self.probe_type!r} target={self.target_url_or_host!r}>"
        )


class SyntheticProbeResult(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """Single execution result for a configured synthetic probe from a specific location."""

    __tablename__ = "synthetic_probe_results"
    __table_args__ = (
        Index("ix_synthetic_results_org_probe_ts", "org_id", "probe_id", "timestamp"),
        Index("ix_synthetic_results_probe_loc_ts", "probe_id", "location", "timestamp"),
        Index("ix_synthetic_results_org_success_ts", "org_id", "success", "timestamp"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    probe_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("synthetic_probe_configs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    location: Mapped[str] = mapped_column(String(80), nullable=False, default="default", index=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    connect_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    tls_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ttfb_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    tls_days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tls_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    response_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    probe: Mapped[SyntheticProbeConfig] = relationship(
        "SyntheticProbeConfig", back_populates="results"
    )

    def tls_expiring_soon(self, warn_days: int = 14) -> bool:
        """Return True if a TLS certificate expires within ``warn_days``."""
        return self.tls_days_remaining is not None and self.tls_days_remaining <= warn_days

    def timing_breakdown(self) -> dict[str, float | None]:
        """Return phased network timings in milliseconds."""
        return {
            "dns_ms": self.dns_ms,
            "connect_ms": self.connect_ms,
            "tls_ms": self.tls_ms,
            "ttfb_ms": self.ttfb_ms,
            "total_ms": self.total_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "probe_id": self.probe_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "location": self.location,
            "success": self.success,
            "status_code": self.status_code,
            "dns_ms": self.dns_ms,
            "connect_ms": self.connect_ms,
            "tls_ms": self.tls_ms,
            "ttfb_ms": self.ttfb_ms,
            "total_ms": self.total_ms,
            "tls_days_remaining": self.tls_days_remaining,
            "tls_issuer": self.tls_issuer,
            "response_size_bytes": self.response_size_bytes,
            "error_message": self.error_message,
        }

    def __repr__(self) -> str:
        return (
            f"<SyntheticProbeResult id={self.id!r} probe_id={self.probe_id!r} "
            f"success={self.success} total_ms={self.total_ms}>"
        )


# ---------------------------------------------------------------------------
# Host / Server OS Telemetry
# ---------------------------------------------------------------------------


class HostMetricSample(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """Operating-system level telemetry sample from a server or host agent."""

    __tablename__ = "host_metric_samples"
    __table_args__ = (
        Index("ix_host_samples_org_device_ts", "org_id", "device_id", "timestamp"),
        Index("ix_host_samples_device_ts", "device_id", "timestamp"),
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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    cpu_user_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_system_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_iowait_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    load_1m: Mapped[float | None] = mapped_column(Float, nullable=True)
    load_5m: Mapped[float | None] = mapped_column(Float, nullable=True)
    load_15m: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_used_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    swap_used_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_used_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    disk_write_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    net_rx_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    net_tx_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    open_fds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    @property
    def cpu_total_pct(self) -> float | None:
        """Combined active CPU utilization (user + system + iowait), capped at 100%."""
        parts = [v for v in (self.cpu_user_pct, self.cpu_system_pct, self.cpu_iowait_pct) if v is not None]
        if not parts:
            return None
        return round(min(100.0, sum(parts)), 2)

    @property
    def disk_total_mbps(self) -> float:
        return float(self.disk_read_mbps or 0.0) + float(self.disk_write_mbps or 0.0)

    @property
    def net_total_mbps(self) -> float:
        return float(self.net_rx_mbps or 0.0) + float(self.net_tx_mbps or 0.0)

    def is_under_pressure(
        self,
        *,
        cpu_threshold: float = 85.0,
        mem_threshold: float = 90.0,
        disk_threshold: float = 90.0,
    ) -> bool:
        """Return True if CPU, memory, or disk utilization exceeds pressure thresholds."""
        cpu = self.cpu_total_pct
        if cpu is not None and cpu >= cpu_threshold:
            return True
        if self.mem_used_pct is not None and self.mem_used_pct >= mem_threshold:
            return True
        if self.disk_used_pct is not None and self.disk_used_pct >= disk_threshold:
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "cpu_user_pct": self.cpu_user_pct,
            "cpu_system_pct": self.cpu_system_pct,
            "cpu_iowait_pct": self.cpu_iowait_pct,
            "cpu_total_pct": self.cpu_total_pct,
            "load_1m": self.load_1m,
            "load_5m": self.load_5m,
            "load_15m": self.load_15m,
            "mem_used_pct": self.mem_used_pct,
            "swap_used_pct": self.swap_used_pct,
            "disk_used_pct": self.disk_used_pct,
            "disk_read_mbps": self.disk_read_mbps,
            "disk_write_mbps": self.disk_write_mbps,
            "net_rx_mbps": self.net_rx_mbps,
            "net_tx_mbps": self.net_tx_mbps,
            "open_fds": self.open_fds,
            "process_count": self.process_count,
        }

    def __repr__(self) -> str:
        return (
            f"<HostMetricSample id={self.id!r} device_id={self.device_id!r} "
            f"cpu_total={self.cpu_total_pct} mem={self.mem_used_pct}>"
        )


# ---------------------------------------------------------------------------
# Downsampled Time-Series Rollups
# ---------------------------------------------------------------------------


class MetricRollup(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """Pre-aggregated time-series rollup bucket for fast historical queries."""

    __tablename__ = "metric_rollups"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "device_id",
            "metric_name",
            "bucket_size",
            "bucket_start",
            name="uq_metric_rollup_bucket",
        ),
        CheckConstraint("sample_count >= 0", name="sample_count_non_negative"),
        Index(
            "ix_metric_rollups_lookup",
            "org_id",
            "device_id",
            "metric_name",
            "bucket_size",
            "bucket_start",
        ),
        Index("ix_metric_rollups_org_metric_ts", "org_id", "metric_name", "bucket_start"),
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
    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    bucket_size: Mapped[str] = mapped_column(String(16), nullable=False, default="5m", index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    min_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    avg_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    p50_val: Mapped[float | None] = mapped_column(Float, nullable=True)
    p95_val: Mapped[float | None] = mapped_column(Float, nullable=True)
    p99_val: Mapped[float | None] = mapped_column(Float, nullable=True)
    sum_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    @validates("bucket_size")
    def _validate_bucket_size(self, _key: str, value: str) -> str:
        normalized = (value or "5m").strip().lower()
        if normalized not in VALID_BUCKET_SIZES:
            raise ValueError(
                f"Invalid bucket_size '{value}'. Expected one of {sorted(VALID_BUCKET_SIZES)}."
            )
        return normalized

    @property
    def bucket_seconds(self) -> int:
        """Return the bucket width in seconds."""
        return VALID_BUCKET_SIZES.get(self.bucket_size, 300)

    def merge_sample(self, value: float) -> None:
        """Incrementally fold a new scalar sample into this rollup bucket."""
        count = self.sample_count or 0
        if count <= 0:
            self.sample_count = 1
            self.min_val = value
            self.max_val = value
            self.sum_val = value
            self.avg_val = value
        else:
            self.sample_count = count + 1
            if self.min_val is None or value < self.min_val:
                self.min_val = value
            if self.max_val is None or value > self.max_val:
                self.max_val = value
            self.sum_val = (self.sum_val or 0.0) + value
            self.avg_val = self.sum_val / self.sample_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "metric_name": self.metric_name,
            "bucket_size": self.bucket_size,
            "bucket_start": self.bucket_start.isoformat() if self.bucket_start else None,
            "sample_count": self.sample_count,
            "min_val": self.min_val,
            "max_val": self.max_val,
            "avg_val": self.avg_val,
            "p50_val": self.p50_val,
            "p95_val": self.p95_val,
            "p99_val": self.p99_val,
            "sum_val": self.sum_val,
        }

    def __repr__(self) -> str:
        return (
            f"<MetricRollup id={self.id!r} metric={self.metric_name!r} "
            f"bucket={self.bucket_size!r} avg={self.avg_val}>"
        )


# ---------------------------------------------------------------------------
# Syslog Events
# ---------------------------------------------------------------------------


class SyslogEvent(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """Ingested RFC 5424 / RFC 3164 syslog record with parsed fields and fingerprint."""

    __tablename__ = "syslog_events"
    __table_args__ = (
        CheckConstraint("facility >= 0 AND facility <= 23", name="syslog_facility_range"),
        CheckConstraint("severity >= 0 AND severity <= 7", name="syslog_severity_range"),
        Index("ix_syslog_org_ts", "org_id", "timestamp"),
        Index("ix_syslog_org_sev_ts", "org_id", "severity", "timestamp"),
        Index("ix_syslog_org_device_ts", "org_id", "device_id", "timestamp"),
        Index("ix_syslog_org_fingerprint", "org_id", "fingerprint"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    facility: Mapped[int] = mapped_column(Integer, nullable=False, default=16)
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=6, index=True)
    app_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    proc_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    msg_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_fields_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    @validates("parsed_fields_json")
    def _validate_parsed_fields(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @property
    def severity_label(self) -> str:
        return SYSLOG_SEVERITY_NAMES.get(self.severity, "unknown")

    @property
    def facility_label(self) -> str:
        return SYSLOG_FACILITY_NAMES.get(self.facility, f"facility-{self.facility}")

    @property
    def priority(self) -> int:
        """RFC 5424 PRI value (facility * 8 + severity)."""
        return (self.facility * 8) + self.severity

    @property
    def is_error_or_higher(self) -> bool:
        """Return True for Emergency (0), Alert (1), Critical (2), or Error (3)."""
        return self.severity <= 3

    @staticmethod
    def compute_fingerprint(source_ip: str, app_name: str | None, message: str) -> str:
        """Build a stable SHA-256 prefix fingerprint by normalizing volatile tokens."""
        normalized = _FINGERPRINT_UUID_RE.sub("<UUID>", message)
        normalized = _FINGERPRINT_IP_RE.sub("<IP>", normalized)
        normalized = _FINGERPRINT_HEX_RE.sub("<HEX>", normalized)
        normalized = _FINGERPRINT_NUM_RE.sub("<NUM>", normalized)
        normalized = " ".join(normalized.strip().lower().split())
        payload = f"{source_ip}|{app_name or ''}|{normalized}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    def ensure_fingerprint(self) -> str:
        """Compute and assign ``fingerprint`` when empty."""
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint(self.source_ip, self.app_name, self.message)
        return self.fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "facility": self.facility,
            "facility_label": self.facility_label,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "app_name": self.app_name,
            "proc_id": self.proc_id,
            "msg_id": self.msg_id,
            "message": self.message,
            "parsed_fields_json": self.parsed_fields_json or {},
            "fingerprint": self.fingerprint,
        }

    def __repr__(self) -> str:
        return (
            f"<SyslogEvent id={self.id!r} source_ip={self.source_ip!r} "
            f"severity={self.severity_label!r} app={self.app_name!r}>"
        )


# ---------------------------------------------------------------------------
# NetFlow / IPFIX Traffic Telemetry
# ---------------------------------------------------------------------------


class NetFlowRecord(Base, UUIDPrimaryKeyMixin, TenantScopedMixin):
    """NetFlow v5/v9 or IPFIX network flow record for traffic analytics and top-talkers."""

    __tablename__ = "netflow_records"
    __table_args__ = (
        CheckConstraint("bytes_count >= 0", name="netflow_bytes_non_negative"),
        CheckConstraint("packets_count >= 0", name="netflow_packets_non_negative"),
        CheckConstraint("src_port >= 0 AND src_port <= 65535", name="netflow_src_port_range"),
        CheckConstraint("dst_port >= 0 AND dst_port <= 65535", name="netflow_dst_port_range"),
        Index("ix_netflow_org_ts", "org_id", "timestamp"),
        Index("ix_netflow_org_src_dst_ts", "org_id", "src_ip", "dst_ip", "timestamp"),
        Index("ix_netflow_org_exporter_ts", "org_id", "exporter_device_id", "timestamp"),
        Index("ix_netflow_org_app_ts", "org_id", "application_tag", "timestamp"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    exporter_device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    protocol: Mapped[int] = mapped_column(Integer, nullable=False, default=6, index=True)
    bytes_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    tcp_flags: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    tos: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    input_if_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_if_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    src_asn: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    dst_asn: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    flow_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    application_tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    @property
    def protocol_name(self) -> str:
        return IANA_PROTOCOL_NAMES.get(self.protocol, str(self.protocol))

    @property
    def tcp_flag_names(self) -> list[str]:
        """Decode TCP control flag bitmask into human-readable mnemonics."""
        if not self.tcp_flags:
            return []
        return [label for mask, label in TCP_FLAG_BITS if self.tcp_flags & mask]

    @property
    def bitrate_mbps(self) -> float:
        """Estimated flow bitrate in Mbps (uses 1-second floor for instantaneous flows)."""
        duration_sec = max((self.flow_duration_ms or 0) / 1000.0, 1.0)
        return round(((self.bytes_count or 0) * 8.0) / (duration_sec * 1_000_000.0), 4)

    @property
    def avg_packet_size_bytes(self) -> float:
        packets = self.packets_count or 0
        if packets <= 0:
            return 0.0
        return round((self.bytes_count or 0) / packets, 2)

    @property
    def five_tuple(self) -> tuple[str, int, str, int, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "exporter_device_id": self.exporter_device_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "bytes_count": self.bytes_count,
            "packets_count": self.packets_count,
            "tcp_flags": self.tcp_flags,
            "tcp_flag_names": self.tcp_flag_names,
            "tos": self.tos,
            "input_if_index": self.input_if_index,
            "output_if_index": self.output_if_index,
            "src_asn": self.src_asn,
            "dst_asn": self.dst_asn,
            "flow_duration_ms": self.flow_duration_ms,
            "bitrate_mbps": self.bitrate_mbps,
            "application_tag": self.application_tag,
        }

    def __repr__(self) -> str:
        return (
            f"<NetFlowRecord id={self.id!r} {self.src_ip}:{self.src_port}->"
            f"{self.dst_ip}:{self.dst_port} proto={self.protocol_name} bytes={self.bytes_count}>"
        )


# ---------------------------------------------------------------------------
# BGP Peer Sessions
# ---------------------------------------------------------------------------


class BgpPeerSession(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """BGP routing neighbor session state, prefix counters, and stability metrics."""

    __tablename__ = "bgp_peer_sessions"
    __table_args__ = (
        UniqueConstraint("org_id", "device_id", "peer_ip", name="uq_bgp_peer_org_device_ip"),
        CheckConstraint("prefixes_received >= 0", name="bgp_prefixes_rx_non_negative"),
        CheckConstraint("prefixes_advertised >= 0", name="bgp_prefixes_tx_non_negative"),
        CheckConstraint("flaps_24h >= 0", name="bgp_flaps_non_negative"),
        Index("ix_bgp_peers_org_device_state", "org_id", "device_id", "state"),
        Index("ix_bgp_peers_org_asn", "org_id", "peer_asn"),
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
    peer_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    peer_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    local_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    peer_description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(50), nullable=False, default="idle", index=True)
    prefixes_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prefixes_advertised: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flaps_24h: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    @validates("state")
    def _validate_state(self, _key: str, value: str) -> str:
        normalized = (value or "idle").strip().lower()
        if normalized not in VALID_BGP_STATES:
            raise ValueError(
                f"Invalid BGP state '{value}'. Expected one of {sorted(VALID_BGP_STATES)}."
            )
        return normalized

    @property
    def is_established(self) -> bool:
        return self.state == "established"

    @property
    def is_ebgp(self) -> bool:
        return self.peer_asn != self.local_asn

    @property
    def is_ibgp(self) -> bool:
        return self.peer_asn == self.local_asn

    def is_flapping(self, threshold: int = 3) -> bool:
        """Return True when 24-hour flap count meets or exceeds ``threshold``."""
        return (self.flaps_24h or 0) >= threshold

    def record_state_transition(self, new_state: str, *, at: datetime | None = None) -> bool:
        """Transition BGP state, incrementing flap counters if leaving Established."""
        target = new_state.strip().lower()
        current = self.state or "idle"
        changed = target != current
        if current == "established" and target != "established":
            self.flaps_24h = (self.flaps_24h or 0) + 1
            self.uptime_seconds = 0
        self.state = target
        self.last_updated_at = at or utcnow()
        return changed

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "peer_ip": self.peer_ip,
            "peer_asn": self.peer_asn,
            "local_asn": self.local_asn,
            "session_type": "eBGP" if self.is_ebgp else "iBGP",
            "peer_description": self.peer_description,
            "state": self.state,
            "is_established": self.is_established,
            "prefixes_received": self.prefixes_received,
            "prefixes_advertised": self.prefixes_advertised,
            "uptime_seconds": self.uptime_seconds,
            "flaps_24h": self.flaps_24h,
            "last_updated_at": self.last_updated_at.isoformat() if self.last_updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<BgpPeerSession id={self.id!r} peer={self.peer_ip!r} "
            f"AS{self.peer_asn} state={self.state!r}>"
        )


# ---------------------------------------------------------------------------
# Distributed Edge Collector Agents
# ---------------------------------------------------------------------------


class EdgeAgent(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantScopedMixin):
    """Registered remote collector agent pushing telemetry from edge sites or VPCs."""

    __tablename__ = "edge_agents"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_edge_agents_org_name"),
        CheckConstraint("metrics_sent_total >= 0", name="edge_agent_metrics_non_negative"),
        CheckConstraint("buffer_depth >= 0", name="edge_agent_buffer_non_negative"),
        Index("ix_edge_agents_org_status", "org_id", "status"),
        Index("ix_edge_agents_org_region", "org_id", "region"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agent_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    region: Mapped[str] = mapped_column(String(80), nullable=False, default="default", index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    capabilities_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    auth_token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    metrics_sent_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    buffer_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cpu_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_mb: Mapped[float | None] = mapped_column(Float, nullable=True)

    @validates("capabilities_json")
    def _validate_capabilities(self, _key: str, value: Any) -> list[str]:
        return [str(item) for item in _coerce_json_list(value)]

    def has_capability(self, capability: str) -> bool:
        """Return True if this agent advertises the specified collector capability."""
        return capability.lower() in {c.lower() for c in (self.capabilities_json or [])}

    def is_stale(self, *, stale_after_seconds: int = 90, now: datetime | None = None) -> bool:
        """Return True if the agent has never checked in or missed its heartbeat window."""
        last_hb = _ensure_utc(self.last_heartbeat_at)
        if last_hb is None:
            return True
        reference = _ensure_utc(now) or utcnow()
        return (reference - last_hb).total_seconds() > stale_after_seconds

    def record_heartbeat(
        self,
        *,
        metrics_sent_delta: int = 0,
        buffer_depth: int | None = None,
        cpu_pct: float | None = None,
        mem_mb: float | None = None,
        agent_version: str | None = None,
        ip_address: str | None = None,
        at: datetime | None = None,
    ) -> None:
        """Update liveness metadata and resource usage from an agent heartbeat."""
        self.last_heartbeat_at = at or utcnow()
        if metrics_sent_delta > 0:
            self.metrics_sent_total = (self.metrics_sent_total or 0) + metrics_sent_delta
        if buffer_depth is not None:
            self.buffer_depth = max(0, buffer_depth)
        if cpu_pct is not None:
            self.cpu_pct = cpu_pct
        if mem_mb is not None:
            self.mem_mb = mem_mb
        if agent_version:
            self.agent_version = agent_version
        if ip_address:
            self.ip_address = ip_address
        if self.status != "revoked":
            self.status = "degraded" if ((self.buffer_depth or 0) > 10_000) else "online"

    def to_dict(self, *, include_sensitive: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "hostname": self.hostname,
            "agent_version": self.agent_version,
            "ip_address": self.ip_address,
            "region": self.region,
            "status": self.status,
            "capabilities_json": self.capabilities_json or [],
            "last_heartbeat_at": (
                self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None
            ),
            "metrics_sent_total": self.metrics_sent_total,
            "buffer_depth": self.buffer_depth,
            "cpu_pct": self.cpu_pct,
            "mem_mb": self.mem_mb,
            "is_stale": self.is_stale(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_sensitive:
            payload["auth_token_hash"] = self.auth_token_hash
        return payload

    def __repr__(self) -> str:
        return (
            f"<EdgeAgent id={self.id!r} name={self.name!r} "
            f"region={self.region!r} status={self.status!r}>"
        )


__all__ = [
    "MetricDefinition",
    "SnmpMetricSample",
    "IcmpMetricSample",
    "SyntheticProbeConfig",
    "SyntheticProbeResult",
    "HostMetricSample",
    "MetricRollup",
    "SyslogEvent",
    "NetFlowRecord",
    "BgpPeerSession",
    "EdgeAgent",
    "VALID_METRIC_CATEGORIES",
    "VALID_AGGREGATIONS",
    "VALID_BUCKET_SIZES",
    "VALID_PROBE_TYPES",
    "VALID_BGP_STATES",
    "SYSLOG_SEVERITY_NAMES",
    "SYSLOG_FACILITY_NAMES",
    "IANA_PROTOCOL_NAMES",
]
