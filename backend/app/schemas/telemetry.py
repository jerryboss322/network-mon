"""Telemetry ingestion, metric querying, synthetic probes, syslog, NetFlow, BGP, and edge agents.

Provides strongly typed Pydantic v2 contracts for:
- SNMP & ICMP polling samples (`SnmpSampleIn/Read`, `IcmpSampleIn/Read`)
- Synthetic monitoring probes & execution results (`SyntheticProbeCreate/Update/Read`,
  `SyntheticResultRead`)
- Host/server resource telemetry (`HostSampleIn/Read`)
- Time-series metric query & rollup responses (`MetricQueryRequest/Response`, `RollupPoint`)
- RFC 5424 Syslog ingestion and search (`SyslogEventIn/Read/Query`)
- NetFlow/IPFIX flow records and top-talker analytics (`NetFlowRecordIn/Read`,
  `TopTalkersResponse`)
- BGP peering telemetry (`BgpPeerRead`)
- Distributed edge collector agents (`EdgeAgentRegister`, `EdgeAgentHeartbeat`,
  `EdgeAgentIngestBatch`, `EdgeAgentRead`)
- Fleet telemetry overview (`TelemetryOverviewResponse`)
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal, Self

from pydantic import Field, computed_field, field_validator, model_validator

from app.schemas.common import (
    AggregationFunction,
    BaseSchema,
    IPAddressStr,
    KeyValueFilter,
    MetricSeries,
    MetadataDict,
    OIDStr,
    SortOrder,
    TagMap,
    TenantEntityReadSchema,
    TimeGranularity,
    TimeRangeQuery,
    UTCDatetime,
    utcnow,
)

# ---------------------------------------------------------------------------
# Telemetry Enums
# ---------------------------------------------------------------------------


class CollectorSource(str, Enum):
    """Origin of an ingested telemetry sample."""

    CENTRAL = "central"
    EDGE_AGENT = "edge_agent"
    PUSH_API = "push_api"
    SIMULATOR = "simulator"


class ProbeType(str, Enum):
    """Supported synthetic probe check protocols."""

    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    DNS = "dns"
    TLS = "tls"
    ICMP = "icmp"
    WEBSOCKET = "websocket"
    GRPC = "grpc"


class ProbeStatus(str, Enum):
    """Outcome state of a synthetic probe execution."""

    PASSING = "passing"
    DEGRADED = "degraded"
    FAILING = "failing"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class SyslogSeverity(int, Enum):
    """RFC 5424 syslog severity levels (0 = Emergency .. 7 = Debug)."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class FlowProtocol(str, Enum):
    """Common IP transport protocols in NetFlow/IPFIX records."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    GRE = "gre"
    ESP = "esp"
    OSPF = "ospf"
    SCTP = "sctp"
    OTHER = "other"


class BgpSessionState(str, Enum):
    """RFC 4271 BGP finite-state machine states."""

    IDLE = "idle"
    CONNECT = "connect"
    ACTIVE = "active"
    OPENSENT = "opensent"
    OPENCONFIRM = "openconfirm"
    ESTABLISHED = "established"


class EdgeAgentStatus(str, Enum):
    """Operational connectivity state of a remote edge collector agent."""

    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DRAINING = "draining"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# SNMP Telemetry Schemas
# ---------------------------------------------------------------------------


class SnmpInterfaceCounter(BaseSchema):
    """Per-interface 64-bit counter snapshot collected during an SNMP poll."""

    if_index: int = Field(..., ge=0)
    if_name: str = Field(..., min_length=1, max_length=128)
    admin_status: str = Field(default="up", max_length=32)
    oper_status: str = Field(default="up", max_length=32)
    speed_mbps: int | None = Field(default=None, ge=0)
    in_octets: int = Field(default=0, ge=0)
    out_octets: int = Field(default=0, ge=0)
    in_bps: float | None = Field(default=None, ge=0.0)
    out_bps: float | None = Field(default=None, ge=0.0)
    in_packets: int = Field(default=0, ge=0)
    out_packets: int = Field(default=0, ge=0)
    in_errors: int = Field(default=0, ge=0)
    out_errors: int = Field(default=0, ge=0)
    in_discards: int = Field(default=0, ge=0)
    out_discards: int = Field(default=0, ge=0)
    utilization_in_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    utilization_out_pct: float | None = Field(default=None, ge=0.0, le=100.0)


class SnmpSampleIn(BaseSchema):
    """Inbound SNMP polling sample for a managed network device."""

    device_id: str = Field(..., description="Target device UUID.")
    timestamp: UTCDatetime = Field(default_factory=utcnow)
    source: CollectorSource = Field(default=CollectorSource.CENTRAL)
    edge_agent_id: str | None = None
    poll_duration_ms: float | None = Field(default=None, ge=0.0)
    sys_uptime_seconds: int | None = Field(default=None, ge=0)
    cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_used_bytes: int | None = Field(default=None, ge=0)
    memory_total_bytes: int | None = Field(default=None, ge=0)
    memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    temperature_c: float | None = Field(default=None, ge=-80.0, le=200.0)
    fan_rpm: int | None = Field(default=None, ge=0)
    power_watts: float | None = Field(default=None, ge=0.0)
    interfaces: list[SnmpInterfaceCounter] = Field(default_factory=list)
    custom_oids: dict[OIDStr, str | int | float] = Field(
        default_factory=dict, description="Additional polled OID-to-value mappings."
    )
    success: bool = Field(default=True)
    error_message: str | None = Field(default=None, max_length=500)


class SnmpSampleRead(TenantEntityReadSchema):
    """Persisted SNMP telemetry sample."""

    device_id: str
    timestamp: UTCDatetime
    source: CollectorSource = CollectorSource.CENTRAL
    edge_agent_id: str | None = None
    poll_duration_ms: float | None = None
    sys_uptime_seconds: int | None = None
    cpu_pct: float | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None
    memory_pct: float | None = None
    temperature_c: float | None = None
    fan_rpm: int | None = None
    power_watts: float | None = None
    interfaces: list[SnmpInterfaceCounter] = Field(default_factory=list)
    custom_oids: dict[str, str | int | float] = Field(default_factory=dict)
    success: bool = True
    error_message: str | None = None


# ---------------------------------------------------------------------------
# ICMP Telemetry Schemas
# ---------------------------------------------------------------------------


class IcmpSampleIn(BaseSchema):
    """Inbound ICMP ping reachability and latency sample."""

    device_id: str = Field(..., description="Target device UUID.")
    target_ip: IPAddressStr | None = None
    timestamp: UTCDatetime = Field(default_factory=utcnow)
    source: CollectorSource = Field(default=CollectorSource.CENTRAL)
    edge_agent_id: str | None = None
    packets_sent: int = Field(default=4, ge=1, le=1000)
    packets_received: int = Field(default=4, ge=0, le=1000)
    packet_loss_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    rtt_min_ms: float | None = Field(default=None, ge=0.0)
    rtt_avg_ms: float | None = Field(default=None, ge=0.0)
    rtt_max_ms: float | None = Field(default=None, ge=0.0)
    jitter_ms: float | None = Field(default=None, ge=0.0)
    ttl: int | None = Field(default=None, ge=1, le=255)
    reachable: bool = Field(default=True)
    error_message: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _validate_icmp_consistency(self) -> Self:
        if self.packets_received > self.packets_sent:
            raise ValueError("'packets_received' cannot exceed 'packets_sent'.")
        if self.packet_loss_pct is None:
            loss = ((self.packets_sent - self.packets_received) / self.packets_sent) * 100.0
            self.packet_loss_pct = round(loss, 2)
        if (
            self.rtt_min_ms is not None
            and self.rtt_max_ms is not None
            and self.rtt_min_ms > self.rtt_max_ms
        ):
            raise ValueError("'rtt_min_ms' cannot be greater than 'rtt_max_ms'.")
        if (
            self.rtt_min_ms is not None
            and self.rtt_avg_ms is not None
            and self.rtt_avg_ms < self.rtt_min_ms
        ):
            raise ValueError("'rtt_avg_ms' cannot be less than 'rtt_min_ms'.")
        if (
            self.rtt_max_ms is not None
            and self.rtt_avg_ms is not None
            and self.rtt_avg_ms > self.rtt_max_ms
        ):
            raise ValueError("'rtt_avg_ms' cannot exceed 'rtt_max_ms'.")
        return self


class IcmpSampleRead(TenantEntityReadSchema):
    """Persisted ICMP telemetry sample."""

    device_id: str
    target_ip: str | None = None
    timestamp: UTCDatetime
    source: CollectorSource = CollectorSource.CENTRAL
    edge_agent_id: str | None = None
    packets_sent: int = 4
    packets_received: int = 4
    packet_loss_pct: float = 0.0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    rtt_max_ms: float | None = None
    jitter_ms: float | None = None
    ttl: int | None = None
    reachable: bool = True
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Synthetic Monitoring Probe & Result Schemas
# ---------------------------------------------------------------------------


class SyntheticProbeCreate(BaseSchema):
    """Configuration for a continuous synthetic endpoint probe (HTTP/TCP/DNS/TLS)."""

    name: str = Field(..., min_length=2, max_length=120)
    probe_type: ProbeType = Field(default=ProbeType.HTTPS)
    target: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Target URL, host:port, or domain name depending on probe_type.",
    )
    device_id: str | None = None
    site_id: str | None = None
    edge_agent_ids: list[str] = Field(
        default_factory=list, description="Optional edge locations running this probe."
    )
    interval_seconds: int = Field(default=60, ge=10, le=86400)
    timeout_seconds: float = Field(default=10.0, ge=0.5, le=120.0)
    http_method: Literal["GET", "HEAD", "POST", "PUT", "OPTIONS"] = Field(default="GET")
    http_headers: dict[str, str] = Field(default_factory=dict)
    http_body: str | None = Field(default=None, max_length=16_384)
    expected_status_codes: list[int] = Field(default_factory=lambda: [200])
    expected_body_regex: str | None = Field(default=None, max_length=512)
    dns_record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV"] | None = None
    dns_server: IPAddressStr | None = None
    expected_dns_answer: str | None = Field(default=None, max_length=255)
    tls_verify: bool = Field(default=True)
    tls_min_days_valid: int | None = Field(default=14, ge=0, le=3650)
    latency_warn_ms: float | None = Field(default=500.0, ge=1.0)
    latency_crit_ms: float | None = Field(default=2000.0, ge=1.0)
    follow_redirects: bool = Field(default=True)
    is_enabled: bool = Field(default=True)
    tags: TagMap = Field(default_factory=dict)

    @field_validator("expected_body_regex")
    @classmethod
    def _validate_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"Invalid expected_body_regex: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _validate_probe_config(self) -> Self:
        if self.timeout_seconds >= self.interval_seconds:
            raise ValueError("'timeout_seconds' must be strictly less than 'interval_seconds'.")
        if (
            self.latency_warn_ms is not None
            and self.latency_crit_ms is not None
            and self.latency_warn_ms > self.latency_crit_ms
        ):
            raise ValueError("'latency_warn_ms' cannot exceed 'latency_crit_ms'.")
        for code in self.expected_status_codes:
            if code < 100 or code > 599:
                raise ValueError(f"Invalid HTTP status code {code}; expected 100..599.")
        return self


class SyntheticProbeUpdate(BaseSchema):
    """Partial update for a synthetic probe definition."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    target: str | None = Field(default=None, min_length=1, max_length=512)
    interval_seconds: int | None = Field(default=None, ge=10, le=86400)
    timeout_seconds: float | None = Field(default=None, ge=0.5, le=120.0)
    http_method: Literal["GET", "HEAD", "POST", "PUT", "OPTIONS"] | None = None
    http_headers: dict[str, str] | None = None
    http_body: str | None = Field(default=None, max_length=16_384)
    expected_status_codes: list[int] | None = None
    expected_body_regex: str | None = Field(default=None, max_length=512)
    tls_verify: bool | None = None
    tls_min_days_valid: int | None = Field(default=None, ge=0, le=3650)
    latency_warn_ms: float | None = Field(default=None, ge=1.0)
    latency_crit_ms: float | None = Field(default=None, ge=1.0)
    follow_redirects: bool | None = None
    is_enabled: bool | None = None
    tags: TagMap | None = None


class SyntheticProbeRead(TenantEntityReadSchema):
    """Full representation of a configured synthetic probe with latest status."""

    name: str
    probe_type: ProbeType
    target: str
    device_id: str | None = None
    site_id: str | None = None
    edge_agent_ids: list[str] = Field(default_factory=list)
    interval_seconds: int = 60
    timeout_seconds: float = 10.0
    http_method: str = "GET"
    expected_status_codes: list[int] = Field(default_factory=lambda: [200])
    expected_body_regex: str | None = None
    dns_record_type: str | None = None
    tls_verify: bool = True
    tls_min_days_valid: int | None = 14
    latency_warn_ms: float | None = None
    latency_crit_ms: float | None = None
    is_enabled: bool = True
    current_status: ProbeStatus = ProbeStatus.UNKNOWN
    last_checked_at: UTCDatetime | None = None
    last_latency_ms: float | None = None
    uptime_24h_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    tags: TagMap = Field(default_factory=dict)


class SyntheticResultRead(TenantEntityReadSchema):
    """Detailed timing breakdown and assertion result of a single synthetic probe run."""

    probe_id: str
    timestamp: UTCDatetime
    edge_agent_id: str | None = None
    status: ProbeStatus
    success: bool
    http_status_code: int | None = None
    dns_ms: float | None = Field(default=None, ge=0.0)
    tcp_connect_ms: float | None = Field(default=None, ge=0.0)
    tls_handshake_ms: float | None = Field(default=None, ge=0.0)
    ttfb_ms: float | None = Field(default=None, ge=0.0)
    total_ms: float = Field(..., ge=0.0)
    response_bytes: int | None = Field(default=None, ge=0)
    resolved_ips: list[str] = Field(default_factory=list)
    tls_cert_subject: str | None = None
    tls_days_remaining: int | None = None
    assertions_passed: bool = True
    assertion_failures: list[str] = Field(default_factory=list)
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Host / Server Resource Telemetry Schemas
# ---------------------------------------------------------------------------


class HostDiskMetric(BaseSchema):
    """Per-filesystem utilization and I/O telemetry for a monitored server."""

    mount_point: str = Field(..., min_length=1, max_length=255)
    device_name: str | None = Field(default=None, max_length=128)
    fs_type: str | None = Field(default=None, max_length=32)
    total_bytes: int = Field(..., ge=0)
    used_bytes: int = Field(..., ge=0)
    free_bytes: int = Field(..., ge=0)
    used_pct: float = Field(..., ge=0.0, le=100.0)
    read_iops: float | None = Field(default=None, ge=0.0)
    write_iops: float | None = Field(default=None, ge=0.0)
    read_bps: float | None = Field(default=None, ge=0.0)
    write_bps: float | None = Field(default=None, ge=0.0)


class HostNetworkMetric(BaseSchema):
    """Per-NIC throughput and error metrics for a monitored server."""

    interface_name: str = Field(..., min_length=1, max_length=64)
    rx_bps: float = Field(default=0.0, ge=0.0)
    tx_bps: float = Field(default=0.0, ge=0.0)
    rx_packets_per_sec: float = Field(default=0.0, ge=0.0)
    tx_packets_per_sec: float = Field(default=0.0, ge=0.0)
    rx_errors: int = Field(default=0, ge=0)
    tx_errors: int = Field(default=0, ge=0)
    rx_dropped: int = Field(default=0, ge=0)
    tx_dropped: int = Field(default=0, ge=0)


class HostSampleIn(BaseSchema):
    """Inbound OS/host telemetry sample (CPU, memory, load, disks, network, processes)."""

    device_id: str
    timestamp: UTCDatetime = Field(default_factory=utcnow)
    source: CollectorSource = Field(default=CollectorSource.CENTRAL)
    edge_agent_id: str | None = None
    cpu_pct: float = Field(..., ge=0.0, le=100.0)
    cpu_user_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cpu_system_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cpu_iowait_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cpu_cores: int | None = Field(default=None, ge=1)
    load_1m: float | None = Field(default=None, ge=0.0)
    load_5m: float | None = Field(default=None, ge=0.0)
    load_15m: float | None = Field(default=None, ge=0.0)
    memory_total_bytes: int = Field(..., ge=0)
    memory_used_bytes: int = Field(..., ge=0)
    memory_available_bytes: int | None = Field(default=None, ge=0)
    memory_pct: float = Field(..., ge=0.0, le=100.0)
    swap_total_bytes: int | None = Field(default=None, ge=0)
    swap_used_bytes: int | None = Field(default=None, ge=0)
    swap_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    process_count: int | None = Field(default=None, ge=0)
    open_file_descriptors: int | None = Field(default=None, ge=0)
    uptime_seconds: int | None = Field(default=None, ge=0)
    disks: list[HostDiskMetric] = Field(default_factory=list)
    network_interfaces: list[HostNetworkMetric] = Field(default_factory=list)


class HostSampleRead(TenantEntityReadSchema):
    """Persisted host resource sample."""

    device_id: str
    timestamp: UTCDatetime
    source: CollectorSource = CollectorSource.CENTRAL
    edge_agent_id: str | None = None
    cpu_pct: float
    cpu_user_pct: float | None = None
    cpu_system_pct: float | None = None
    cpu_iowait_pct: float | None = None
    cpu_cores: int | None = None
    load_1m: float | None = None
    load_5m: float | None = None
    load_15m: float | None = None
    memory_total_bytes: int
    memory_used_bytes: int
    memory_available_bytes: int | None = None
    memory_pct: float
    swap_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    swap_pct: float | None = None
    process_count: int | None = None
    open_file_descriptors: int | None = None
    uptime_seconds: int | None = None
    disks: list[HostDiskMetric] = Field(default_factory=list)
    network_interfaces: list[HostNetworkMetric] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Time-Series Metric Query & Rollup Schemas
# ---------------------------------------------------------------------------


class RollupPoint(BaseSchema):
    """Aggregated statistical bucket produced by the time-series rollup engine."""

    bucket_start: UTCDatetime
    bucket_end: UTCDatetime
    sample_count: int = Field(..., ge=0)
    avg: float | None = None
    min: float | None = None
    max: float | None = None
    sum: float | None = None
    p50: float | None = None
    p95: float | None = None
    p99: float | None = None
    rate_per_sec: float | None = None


class MetricQueryRequest(BaseSchema):
    """Structured query or DSL expression for fetching time-series metrics."""

    metrics: list[str] = Field(
        default_factory=list,
        description="Metric names (e.g. ['icmp.rtt_avg_ms', 'snmp.cpu_pct']).",
    )
    query_dsl: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional NetPulse query language expression.",
    )
    device_ids: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    interface_names: list[str] = Field(default_factory=list)
    filters: list[KeyValueFilter] = Field(default_factory=list)
    time_range: TimeRangeQuery = Field(default_factory=lambda: TimeRangeQuery(relative="1h"))
    granularity: TimeGranularity = Field(default=TimeGranularity.FIVE_MINUTES)
    aggregation: AggregationFunction = Field(default=AggregationFunction.AVG)
    group_by: list[str] = Field(
        default_factory=list, description="Dimensions to split series by (e.g. ['device_id'])."
    )
    fill_policy: Literal["null", "zero", "previous", "linear"] = Field(default="null")
    limit_series: int = Field(default=50, ge=1, le=500)

    @model_validator(mode="after")
    def _ensure_metric_or_dsl(self) -> Self:
        if not self.metrics and not self.query_dsl:
            raise ValueError("Provide at least one metric name in 'metrics' or a 'query_dsl'.")
        return self


class MetricQueryResponse(BaseSchema):
    """Result envelope returned by the time-series query engine."""

    start: UTCDatetime
    end: UTCDatetime
    granularity: TimeGranularity
    aggregation: AggregationFunction
    execution_ms: float = Field(default=0.0, ge=0.0)
    series: list[MetricSeries] = Field(default_factory=list)
    rollups: dict[str, list[RollupPoint]] = Field(
        default_factory=dict, description="Optional full rollup buckets keyed by series ID."
    )
    truncated: bool = Field(default=False)
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Syslog Schemas (RFC 5424)
# ---------------------------------------------------------------------------


class SyslogEventIn(BaseSchema):
    """Inbound RFC 5424 / RFC 3164 syslog message."""

    timestamp: UTCDatetime = Field(default_factory=utcnow)
    source_ip: IPAddressStr
    device_id: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    facility: int = Field(default=16, ge=0, le=23, description="RFC 5424 facility code (0-23).")
    severity: SyslogSeverity = Field(default=SyslogSeverity.INFORMATIONAL)
    app_name: str | None = Field(default=None, max_length=64)
    proc_id: str | None = Field(default=None, max_length=64)
    msg_id: str | None = Field(default=None, max_length=64)
    message: str = Field(..., min_length=1, max_length=16_384)
    raw_message: str | None = Field(default=None, max_length=16_384)
    structured_data: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)

    @computed_field
    @property
    def priority(self) -> int:
        """Compute RFC 5424 PRI value (facility * 8 + severity)."""
        return self.facility * 8 + int(self.severity)


class SyslogEventRead(TenantEntityReadSchema):
    """Persisted syslog event with parsed classification metadata."""

    timestamp: UTCDatetime
    source_ip: str
    device_id: str | None = None
    hostname: str | None = None
    facility: int
    severity: SyslogSeverity
    priority: int = Field(default=134, ge=0, le=191)
    app_name: str | None = None
    proc_id: str | None = None
    msg_id: str | None = None
    message: str
    structured_data: MetadataDict = Field(default_factory=dict)
    parsed_fields: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)


class SyslogEventQuery(BaseSchema):
    """Search parameters for querying syslog streams."""

    device_id: str | None = None
    source_ip: IPAddressStr | None = None
    hostname: str | None = Field(default=None, max_length=255)
    min_severity: SyslogSeverity | None = Field(
        default=None,
        description="Maximum numeric severity (e.g. ERROR=3 includes 0..3).",
    )
    facilities: list[int] = Field(default_factory=list)
    app_name: str | None = Field(default=None, max_length=64)
    search: str | None = Field(default=None, max_length=300)
    regex_pattern: str | None = Field(default=None, max_length=300)
    time_range: TimeRangeQuery = Field(default_factory=lambda: TimeRangeQuery(relative="1h"))
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=500)
    sort_order: SortOrder = SortOrder.DESC


# ---------------------------------------------------------------------------
# NetFlow / IPFIX Schemas
# ---------------------------------------------------------------------------


class NetFlowRecordIn(BaseSchema):
    """Inbound NetFlow v5/v9 or IPFIX flow record."""

    exporter_ip: IPAddressStr
    device_id: str | None = None
    timestamp: UTCDatetime = Field(default_factory=utcnow)
    flow_start: UTCDatetime | None = None
    flow_end: UTCDatetime | None = None
    src_ip: IPAddressStr
    dst_ip: IPAddressStr
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: FlowProtocol = Field(default=FlowProtocol.TCP)
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    bytes_count: int = Field(..., ge=0)
    packets_count: int = Field(..., ge=1)
    tcp_flags: int | None = Field(default=None, ge=0, le=255)
    tos: int | None = Field(default=None, ge=0, le=255)
    input_if_index: int | None = Field(default=None, ge=0)
    output_if_index: int | None = Field(default=None, ge=0)
    src_asn: int | None = Field(default=None, ge=0)
    dst_asn: int | None = Field(default=None, ge=0)
    next_hop_ip: IPAddressStr | None = None
    application: str | None = Field(default=None, max_length=64)


class NetFlowRecordRead(TenantEntityReadSchema):
    """Persisted NetFlow/IPFIX record."""

    exporter_ip: str
    device_id: str | None = None
    timestamp: UTCDatetime
    flow_start: UTCDatetime | None = None
    flow_end: UTCDatetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: FlowProtocol = FlowProtocol.TCP
    protocol_number: int | None = None
    bytes_count: int
    packets_count: int
    tcp_flags: int | None = None
    tos: int | None = None
    input_if_index: int | None = None
    output_if_index: int | None = None
    src_asn: int | None = None
    dst_asn: int | None = None
    next_hop_ip: str | None = None
    application: str | None = None


class TopTalkerEntry(BaseSchema):
    """Aggregated flow volume for a single top-talker endpoint or conversation."""

    key: str = Field(..., description="IP address, ASN, application, or src->dst pair.")
    label: str | None = None
    total_bytes: int = Field(..., ge=0)
    total_packets: int = Field(..., ge=0)
    flow_count: int = Field(..., ge=0)
    avg_bps: float = Field(default=0.0, ge=0.0)
    share_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    dominant_protocol: FlowProtocol | None = None


class TopTalkersResponse(BaseSchema):
    """Ranked bandwidth consumers and protocol distribution across a time window."""

    start: UTCDatetime
    end: UTCDatetime
    dimension: Literal["src_ip", "dst_ip", "conversation", "application", "dst_port", "asn"] = (
        "src_ip"
    )
    total_bytes: int = Field(default=0, ge=0)
    total_packets: int = Field(default=0, ge=0)
    total_flows: int = Field(default=0, ge=0)
    talkers: list[TopTalkerEntry] = Field(default_factory=list)
    protocol_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Total bytes grouped by IP protocol."
    )


# ---------------------------------------------------------------------------
# BGP Peering Telemetry Schemas
# ---------------------------------------------------------------------------


class BgpPeerRead(TenantEntityReadSchema):
    """BGP neighbor session state and prefix table telemetry."""

    device_id: str
    device_name: str | None = None
    vrf: str = Field(default="default", max_length=64)
    local_asn: int = Field(..., ge=1, le=4_294_967_295)
    remote_asn: int = Field(..., ge=1, le=4_294_967_295)
    peer_ip: str
    peer_description: str | None = None
    state: BgpSessionState = BgpSessionState.IDLE
    admin_enabled: bool = True
    prefixes_received: int = Field(default=0, ge=0)
    prefixes_accepted: int = Field(default=0, ge=0)
    prefixes_advertised: int = Field(default=0, ge=0)
    prefix_limit: int | None = Field(default=None, ge=1)
    flap_count_24h: int = Field(default=0, ge=0)
    uptime_seconds: int = Field(default=0, ge=0)
    hold_time_seconds: int = Field(default=90, ge=0)
    keepalive_seconds: int = Field(default=30, ge=0)
    last_state_change_at: UTCDatetime | None = None
    last_error_code: str | None = None


# ---------------------------------------------------------------------------
# Distributed Edge Collector Agent Schemas
# ---------------------------------------------------------------------------


class EdgeAgentRegister(BaseSchema):
    """Registration payload sent by a remote NetPulse edge collector agent."""

    name: str = Field(..., min_length=2, max_length=120)
    site_id: str | None = None
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: IPAddressStr | None = None
    agent_version: str = Field(..., min_length=1, max_length=32)
    os_platform: str | None = Field(default=None, max_length=64)
    capabilities: list[
        Literal["icmp", "snmp", "synthetic", "host", "syslog", "netflow", "discovery", "config"]
    ] = Field(default_factory=lambda: ["icmp", "snmp", "synthetic"])
    max_concurrent_jobs: int = Field(default=64, ge=1, le=4096)
    tags: TagMap = Field(default_factory=dict)


class EdgeAgentHeartbeat(BaseSchema):
    """Periodic liveness and queue telemetry reported by an edge collector agent."""

    status: EdgeAgentStatus = Field(default=EdgeAgentStatus.ONLINE)
    agent_version: str | None = Field(default=None, max_length=32)
    cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    queue_depth: int = Field(default=0, ge=0)
    active_jobs: int = Field(default=0, ge=0)
    samples_buffered: int = Field(default=0, ge=0)
    uptime_seconds: int = Field(default=0, ge=0)
    reported_at: UTCDatetime = Field(default_factory=utcnow)


class EdgeAgentIngestBatch(BaseSchema):
    """High-throughput batched telemetry upload from an edge collector agent."""

    agent_id: str
    batch_id: str = Field(..., min_length=1, max_length=128)
    sent_at: UTCDatetime = Field(default_factory=utcnow)
    snmp_samples: list[SnmpSampleIn] = Field(default_factory=list, max_length=2000)
    icmp_samples: list[IcmpSampleIn] = Field(default_factory=list, max_length=5000)
    host_samples: list[HostSampleIn] = Field(default_factory=list, max_length=2000)
    syslog_events: list[SyslogEventIn] = Field(default_factory=list, max_length=5000)
    netflow_records: list[NetFlowRecordIn] = Field(default_factory=list, max_length=10_000)

    @computed_field
    @property
    def total_records(self) -> int:
        """Total number of telemetry records carried in this batch."""
        return (
            len(self.snmp_samples)
            + len(self.icmp_samples)
            + len(self.host_samples)
            + len(self.syslog_events)
            + len(self.netflow_records)
        )


class EdgeAgentIngestResult(BaseSchema):
    """Acknowledgement returned to an edge collector after batch ingestion."""

    batch_id: str
    accepted: int = Field(..., ge=0)
    rejected: int = Field(default=0, ge=0)
    processing_ms: float = Field(default=0.0, ge=0.0)
    errors: list[str] = Field(default_factory=list)


class EdgeAgentRead(TenantEntityReadSchema):
    """Full edge collector agent state."""

    name: str
    site_id: str | None = None
    hostname: str
    ip_address: str | None = None
    agent_version: str
    os_platform: str | None = None
    status: EdgeAgentStatus = EdgeAgentStatus.OFFLINE
    capabilities: list[str] = Field(default_factory=list)
    max_concurrent_jobs: int = 64
    assigned_device_count: int = Field(default=0, ge=0)
    cpu_pct: float | None = None
    memory_pct: float | None = None
    queue_depth: int = 0
    last_heartbeat_at: UTCDatetime | None = None
    total_samples_ingested: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Telemetry Overview Dashboard Schema
# ---------------------------------------------------------------------------


class TelemetryOverviewResponse(BaseSchema):
    """High-level real-time telemetry overview across the organization's fleet."""

    generated_at: UTCDatetime = Field(default_factory=utcnow)
    window_minutes: int = Field(default=60, ge=1)
    devices_monitored: int = Field(default=0, ge=0)
    devices_reachable: int = Field(default=0, ge=0)
    avg_rtt_ms: float | None = Field(default=None, ge=0.0)
    p95_rtt_ms: float | None = Field(default=None, ge=0.0)
    avg_packet_loss_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    avg_cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    avg_memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    total_ingress_bps: float = Field(default=0.0, ge=0.0)
    total_egress_bps: float = Field(default=0.0, ge=0.0)
    synthetic_probes_total: int = Field(default=0, ge=0)
    synthetic_probes_passing: int = Field(default=0, ge=0)
    bgp_sessions_total: int = Field(default=0, ge=0)
    bgp_sessions_established: int = Field(default=0, ge=0)
    syslog_events_window: int = Field(default=0, ge=0)
    syslog_errors_window: int = Field(default=0, ge=0)
    netflow_bytes_window: int = Field(default=0, ge=0)
    edge_agents_online: int = Field(default=0, ge=0)
    top_latency_devices: list[MetadataDict] = Field(default_factory=list)
    top_utilized_interfaces: list[MetadataDict] = Field(default_factory=list)
    recent_series: list[MetricSeries] = Field(default_factory=list)
