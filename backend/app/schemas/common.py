"""Common Pydantic v2 schemas, shared validators, pagination, and primitives.

Provides the foundational `BaseSchema`, ORM-compatible timestamp/tenant mixins,
strict network & identity type validators (IP, CIDR, MAC, hostname, slug, email,
URL, cron), generic cursor/page pagination envelopes, time-range query resolution,
time-series metric structures, health reporting, bulk action envelopes,
structured error responses matching `NetPulseError`, and platform-wide summary
statistics.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any, Generic, Literal, Self, TypeVar
from urllib.parse import urlparse
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Compiled Regular Expressions & Constants
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
_MAC_RE = re.compile(
    r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
    r"|^(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$"
)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
_OID_RE = re.compile(r"^\.?(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+$")
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
)
_RELATIVE_DURATION_RE = re.compile(r"^(?P<amount>[1-9][0-9]{0,4})(?P<unit>[smhdw])$")
_CRON_FIELD_RE = re.compile(r"^[0-9*,/-]+$")

_DURATION_UNIT_SECONDS: dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}

# ---------------------------------------------------------------------------
# Reusable Validator Functions
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Normalize a datetime to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_uuid_str(value: str) -> str:
    """Validate and canonicalize a UUID string."""
    try:
        parsed = UUID(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid UUID format: {value!r}") from exc
    return str(parsed)


def validate_slug(value: str) -> str:
    """Validate a lowercase URL-safe slug (e.g. 'core-dc-east-1')."""
    normalized = value.strip().lower()
    if not normalized or len(normalized) > 100 or not _SLUG_RE.match(normalized):
        raise ValueError(
            "Slug must be 1-100 characters of lowercase alphanumerics separated by single hyphens."
        )
    return normalized


def validate_hostname(value: str) -> str:
    """Validate an RFC 1123 hostname or FQDN."""
    candidate = value.strip().rstrip(".")
    if not candidate or not _HOSTNAME_RE.match(candidate):
        raise ValueError(f"Invalid hostname or FQDN: {value!r}")
    return candidate.lower()


def validate_ip_address(value: str) -> str:
    """Validate and canonicalize an IPv4 or IPv6 address."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4/IPv6 address: {value!r}") from exc


def validate_cidr(value: str) -> str:
    """Validate and normalize an IPv4 or IPv6 CIDR block (strict=False)."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network block: {value!r}") from exc
    return str(network)


def validate_mac_address(value: str) -> str:
    """Validate a MAC address and canonicalize it to lowercase colon-separated notation."""
    candidate = value.strip()
    if not _MAC_RE.match(candidate):
        raise ValueError(f"Invalid MAC address format: {value!r}")
    hex_digits = re.sub(r"[:.\-]", "", candidate).lower()
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))


def validate_email(value: str) -> str:
    """Validate and lowercase an email address without external package requirements."""
    candidate = value.strip().lower()
    if len(candidate) > 254 or not _EMAIL_RE.match(candidate):
        raise ValueError(f"Invalid email address: {value!r}")
    local_part = candidate.split("@", 1)[0]
    if len(local_part) > 64 or ".." in local_part:
        raise ValueError(f"Invalid email local part: {value!r}")
    return candidate


def validate_http_url(value: str) -> str:
    """Validate an HTTP or HTTPS URL with a valid network host."""
    candidate = value.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid HTTP/HTTPS URL: {value!r}")
    if parsed.hostname is None:
        raise ValueError(f"URL is missing a hostname: {value!r}")
    return candidate


def validate_oid(value: str) -> str:
    """Validate an ASN.1 SNMP Object Identifier (e.g. '1.3.6.1.2.1.1.3.0')."""
    candidate = value.strip()
    if not _OID_RE.match(candidate):
        raise ValueError(f"Invalid SNMP OID: {value!r}")
    return candidate.lstrip(".")


def validate_semver(value: str) -> str:
    """Validate a Semantic Versioning 2.0.0 string (e.g. '2.1.0-beta.1')."""
    candidate = value.strip()
    if not _SEMVER_RE.match(candidate):
        raise ValueError(f"Invalid semantic version: {value!r}")
    return candidate


def validate_cron_expression(value: str) -> str:
    """Validate a standard 5-field POSIX cron expression."""
    candidate = " ".join(value.strip().split())
    parts = candidate.split(" ")
    if len(parts) != 5:
        raise ValueError("Cron expression must contain exactly 5 space-separated fields.")
    for idx, part in enumerate(parts):
        if not _CRON_FIELD_RE.match(part):
            raise ValueError(f"Invalid syntax in cron field #{idx + 1}: {part!r}")
    return candidate


def parse_relative_duration(spec: str) -> timedelta:
    """Parse a relative duration string like '15m', '6h', '7d', '2w' into a timedelta."""
    match = _RELATIVE_DURATION_RE.match(spec.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid relative duration {spec!r}; expected e.g. '15m', '1h', '24h', '7d', '4w'."
        )
    amount = int(match.group("amount"))
    unit = match.group("unit")
    return timedelta(seconds=amount * _DURATION_UNIT_SECONDS[unit])


# Constrained / Annotated Reusable Types
UUIDStr = Annotated[str, AfterValidator(validate_uuid_str)]
SlugStr = Annotated[str, AfterValidator(validate_slug)]
HostnameStr = Annotated[str, AfterValidator(validate_hostname)]
IPAddressStr = Annotated[str, AfterValidator(validate_ip_address)]
CIDRStr = Annotated[str, AfterValidator(validate_cidr)]
MACAddressStr = Annotated[str, AfterValidator(validate_mac_address)]
EmailAddress = Annotated[str, AfterValidator(validate_email)]
HttpUrlStr = Annotated[str, AfterValidator(validate_http_url)]
OIDStr = Annotated[str, AfterValidator(validate_oid)]
SemVerStr = Annotated[str, AfterValidator(validate_semver)]
CronExpressionStr = Annotated[str, AfterValidator(validate_cron_expression)]
UTCDatetime = Annotated[datetime, AfterValidator(ensure_utc)]
TagMap = dict[str, str]
MetadataDict = dict[str, Any]


# ---------------------------------------------------------------------------
# Shared Enums
# ---------------------------------------------------------------------------


class SortOrder(str, Enum):
    """Result ordering direction."""

    ASC = "asc"
    DESC = "desc"


class HealthStatus(str, Enum):
    """Canonical health state for services, components, and devices."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Platform-wide severity scale."""

    INFO = "info"
    LOW = "low"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class BulkActionType(str, Enum):
    """Supported generic bulk entity operations."""

    DELETE = "delete"
    RESTORE = "restore"
    ENABLE = "enable"
    DISABLE = "disable"
    ADD_TAGS = "add_tags"
    REMOVE_TAGS = "remove_tags"
    ASSIGN_GROUP = "assign_group"
    UNASSIGN_GROUP = "unassign_group"
    TRIGGER_POLL = "trigger_poll"
    ACKNOWLEDGE = "acknowledge"
    RESOLVE = "resolve"


class TimeGranularity(str, Enum):
    """Time-series aggregation rollup bucket sizes."""

    RAW = "raw"
    ONE_MINUTE = "1m"
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    ONE_HOUR = "1h"
    SIX_HOURS = "6h"
    ONE_DAY = "1d"


class AggregationFunction(str, Enum):
    """Statistical reducers for metric rollups and queries."""

    AVG = "avg"
    MIN = "min"
    MAX = "max"
    SUM = "sum"
    COUNT = "count"
    P50 = "p50"
    P90 = "p90"
    P95 = "p95"
    P99 = "p99"
    RATE = "rate"
    LAST = "last"


class FilterOperator(str, Enum):
    """Comparison operators for dynamic key-value queries and group rules."""

    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EXISTS = "exists"


# ---------------------------------------------------------------------------
# Base Schema & ORM Mixins
# ---------------------------------------------------------------------------


class BaseSchema(BaseModel):
    """Base class for all NetPulse Pydantic v2 request and response schemas."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=False,
        use_enum_values=False,
        validate_assignment=True,
        arbitrary_types_allowed=False,
    )


class IdentifierSchema(BaseSchema):
    """Mixin for entities identified by a canonical UUID primary key."""

    id: str = Field(..., description="Unique UUID4 entity identifier.")


class TimestampedSchema(BaseSchema):
    """Mixin aligning with SQLAlchemy `TimestampMixin`."""

    created_at: UTCDatetime = Field(..., description="UTC creation timestamp.")
    updated_at: UTCDatetime = Field(..., description="UTC last-modification timestamp.")


class TenantScopedSchema(BaseSchema):
    """Mixin aligning with SQLAlchemy `TenantScopedMixin`."""

    org_id: str = Field(..., description="Owning organization tenant UUID.")


class SoftDeletableSchema(BaseSchema):
    """Mixin aligning with SQLAlchemy `SoftDeleteMixin`."""

    is_deleted: bool = Field(default=False, description="Soft-deletion tombstone flag.")
    deleted_at: UTCDatetime | None = Field(
        default=None, description="UTC timestamp when the entity was soft-deleted."
    )


class EntityReadSchema(IdentifierSchema, TimestampedSchema):
    """Standard read schema base with UUID primary key and audit timestamps."""


class TenantEntityReadSchema(IdentifierSchema, TenantScopedSchema, TimestampedSchema):
    """Standard read schema base for multi-tenant entities."""


# ---------------------------------------------------------------------------
# Pagination & Filtering
# ---------------------------------------------------------------------------


class PaginationParams(BaseSchema):
    """Query parameters for paginated collection endpoints."""

    page: int = Field(default=1, ge=1, le=100_000, description="1-indexed page number.")
    page_size: int = Field(
        default=50, ge=1, le=500, description="Maximum number of records returned per page."
    )
    sort_by: str | None = Field(
        default=None, max_length=64, description="Column or attribute name to sort by."
    )
    sort_order: SortOrder = Field(default=SortOrder.DESC, description="Sort direction.")

    @computed_field
    @property
    def offset(self) -> int:
        """Compute SQL OFFSET from page and page_size."""
        return (self.page - 1) * self.page_size


class PaginationMeta(BaseSchema):
    """Metadata describing a single page within a paginated result set."""

    total: int = Field(..., ge=0, description="Total matching records across all pages.")
    page: int = Field(..., ge=1, description="Current 1-indexed page number.")
    page_size: int = Field(..., ge=1, description="Requested page size.")
    total_pages: int = Field(..., ge=0, description="Total available pages.")
    has_next: bool = Field(..., description="True if another page exists after this one.")
    has_prev: bool = Field(..., description="True if a previous page exists.")
    next_cursor: str | None = Field(
        default=None, description="Optional opaque cursor for keyset pagination."
    )

    @classmethod
    def from_counts(
        cls,
        total: int,
        page: int = 1,
        page_size: int = 50,
        *,
        next_cursor: str | None = None,
    ) -> PaginationMeta:
        """Construct `PaginationMeta` accurately from total item count and page parameters."""
        safe_total = max(0, total)
        safe_page_size = max(1, page_size)
        total_pages = (safe_total + safe_page_size - 1) // safe_page_size if safe_total else 0
        return cls(
            total=safe_total,
            page=page,
            page_size=safe_page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
            next_cursor=next_cursor,
        )


class PaginatedResponse(BaseSchema, Generic[T]):
    """Generic envelope for paginated API responses."""

    items: list[T] = Field(default_factory=list, description="Items on the current page.")
    meta: PaginationMeta = Field(..., description="Pagination metadata.")

    @classmethod
    def create(
        cls,
        items: list[T],
        total: int,
        page: int = 1,
        page_size: int = 50,
        *,
        next_cursor: str | None = None,
    ) -> PaginatedResponse[T]:
        """Factory helper to construct a paginated response envelope."""
        return cls(
            items=items,
            meta=PaginationMeta.from_counts(
                total=total, page=page, page_size=page_size, next_cursor=next_cursor
            ),
        )


class KeyValueFilter(BaseSchema):
    """Structured predicate for filtering by labels, tags, or entity attributes."""

    key: str = Field(..., min_length=1, max_length=128, description="Attribute or tag key.")
    operator: FilterOperator = Field(
        default=FilterOperator.EQ, description="Comparison operator."
    )
    value: str | int | float | bool | list[str | int | float] | None = Field(
        default=None, description="Target value or list of values for comparison."
    )

    @model_validator(mode="after")
    def _validate_operator_value_pair(self) -> Self:
        if self.operator in {FilterOperator.IN, FilterOperator.NOT_IN}:
            if not isinstance(self.value, list) or len(self.value) == 0:
                raise ValueError(
                    f"Operator '{self.operator.value}' requires a non-empty list value."
                )
        elif self.operator == FilterOperator.EXISTS:
            if self.value is not None and not isinstance(self.value, bool):
                raise ValueError("Operator 'exists' accepts a boolean or null value.")
        elif self.operator == FilterOperator.REGEX:
            if not isinstance(self.value, str) or not self.value:
                raise ValueError("Operator 'regex' requires a non-empty pattern string.")
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(f"Invalid regular expression {self.value!r}: {exc}") from exc
        elif self.value is None:
            raise ValueError(f"Operator '{self.operator.value}' requires a non-null value.")
        return self


# ---------------------------------------------------------------------------
# Time Ranges & Time-Series Primitives
# ---------------------------------------------------------------------------


class TimeRangeQuery(BaseSchema):
    """Flexible time-window specification supporting absolute bounds or relative presets.

    Callers may specify either `relative` (e.g. '15m', '1h', '24h', '7d') or explicit
    `start` and `end` UTC timestamps. When both are omitted, defaults to the last 1 hour.
    """

    start: UTCDatetime | None = Field(
        default=None, description="Inclusive start timestamp (UTC)."
    )
    end: UTCDatetime | None = Field(
        default=None, description="Inclusive end timestamp (UTC)."
    )
    relative: str | None = Field(
        default=None,
        description="Relative lookback duration such as '15m', '1h', '6h', '24h', '7d', '30d'.",
    )
    granularity: TimeGranularity | None = Field(
        default=None, description="Optional rollup bucket granularity override."
    )
    timezone_name: str = Field(
        default="UTC", max_length=64, description="Display timezone hint (IANA name)."
    )

    @field_validator("relative")
    @classmethod
    def _validate_relative(cls, value: str | None) -> str | None:
        if value is None:
            return None
        delta = parse_relative_duration(value)
        if delta > timedelta(days=366):
            raise ValueError("Relative time window cannot exceed 366 days.")
        return value.strip().lower()

    @model_validator(mode="after")
    def _validate_bounds(self) -> Self:
        if self.start is not None and self.end is not None:
            if self.start >= self.end:
                raise ValueError("'start' timestamp must be strictly earlier than 'end'.")
            if (self.end - self.start) > timedelta(days=366):
                raise ValueError("Requested time range cannot exceed 366 days.")
        return self

    def resolve(self, *, now: datetime | None = None) -> tuple[datetime, datetime]:
        """Resolve into concrete `(start_utc, end_utc)` bounds."""
        anchor = ensure_utc(now) if now is not None else utcnow()
        if self.start is not None and self.end is not None:
            return self.start, self.end
        if self.relative is not None:
            delta = parse_relative_duration(self.relative)
            end = self.end or anchor
            return end - delta, end
        if self.start is not None:
            return self.start, anchor
        end = self.end or anchor
        return end - timedelta(hours=1), end


class MetricPoint(BaseSchema):
    """Single timestamped numerical sample in a time-series."""

    timestamp: UTCDatetime = Field(..., description="Sample timestamp in UTC.")
    value: float = Field(..., description="Primary numeric metric value.")
    min_value: float | None = Field(
        default=None, description="Minimum observed value within the rollup bucket."
    )
    max_value: float | None = Field(
        default=None, description="Maximum observed value within the rollup bucket."
    )
    sample_count: int | None = Field(
        default=None, ge=1, description="Number of raw samples aggregated into this point."
    )
    quality: Literal["good", "interpolated", "partial", "stale"] = Field(
        default="good", description="Data quality indicator for this point."
    )


class MetricSeries(BaseSchema):
    """Named metric time-series with dimensional labels and summary helpers."""

    metric: str = Field(..., min_length=1, max_length=160, description="Canonical metric name.")
    display_name: str | None = Field(
        default=None, max_length=160, description="Human-readable label for charts."
    )
    unit: str = Field(
        default="", max_length=32, description="Measurement unit (e.g. 'ms', 'bps', '%', 'bytes')."
    )
    granularity: TimeGranularity = Field(
        default=TimeGranularity.RAW, description="Bucket resolution of points."
    )
    aggregation: AggregationFunction = Field(
        default=AggregationFunction.AVG, description="Aggregation applied to produce values."
    )
    labels: TagMap = Field(
        default_factory=dict, description="Dimensional key-value labels (device_id, interface, etc.)."
    )
    points: list[MetricPoint] = Field(
        default_factory=list, description="Chronologically ordered metric samples."
    )

    @computed_field
    @property
    def latest_value(self) -> float | None:
        """Return the most recent point value, if any."""
        return self.points[-1].value if self.points else None

    @computed_field
    @property
    def avg_value(self) -> float | None:
        """Compute arithmetic mean across points in this series."""
        if not self.points:
            return None
        return round(sum(p.value for p in self.points) / len(self.points), 4)


# ---------------------------------------------------------------------------
# Health Check & Platform Statistics
# ---------------------------------------------------------------------------


class ComponentHealth(BaseSchema):
    """Health report for an individual subsystem (database, collectors, cache, etc.)."""

    name: str = Field(..., min_length=1, max_length=80, description="Component identifier.")
    status: HealthStatus = Field(..., description="Current health status.")
    latency_ms: float | None = Field(
        default=None, ge=0.0, description="Self-check round-trip latency in milliseconds."
    )
    message: str | None = Field(
        default=None, max_length=500, description="Human-readable diagnostic message."
    )
    details: MetadataDict = Field(
        default_factory=dict, description="Optional subsystem-specific diagnostics."
    )
    checked_at: UTCDatetime = Field(
        default_factory=utcnow, description="UTC timestamp of the health probe."
    )


class HealthCheckResponse(BaseSchema):
    """Top-level platform readiness and liveness payload."""

    status: HealthStatus = Field(..., description="Aggregated overall platform health.")
    service: str = Field(
        default="NetPulse Observability Platform", description="Service name."
    )
    version: str = Field(default="2.0.0", description="Deployed software version.")
    environment: str = Field(default="development", description="Runtime environment.")
    uptime_seconds: float = Field(default=0.0, ge=0.0, description="Process uptime in seconds.")
    timestamp: UTCDatetime = Field(
        default_factory=utcnow, description="UTC timestamp when report was generated."
    )
    components: list[ComponentHealth] = Field(
        default_factory=list, description="Per-component health checks."
    )

    @computed_field
    @property
    def is_healthy(self) -> bool:
        """True only when overall status is strictly healthy."""
        return self.status == HealthStatus.HEALTHY


class PlatformStatsSummary(BaseSchema):
    """Executive KPI snapshot summarizing fleet, telemetry, alerting, and automation health."""

    generated_at: UTCDatetime = Field(
        default_factory=utcnow, description="UTC timestamp when statistics were computed."
    )
    organizations_total: int = Field(default=0, ge=0)
    users_active: int = Field(default=0, ge=0)
    sites_total: int = Field(default=0, ge=0)
    devices_total: int = Field(default=0, ge=0)
    devices_online: int = Field(default=0, ge=0)
    devices_degraded: int = Field(default=0, ge=0)
    devices_offline: int = Field(default=0, ge=0)
    devices_maintenance: int = Field(default=0, ge=0)
    interfaces_monitored: int = Field(default=0, ge=0)
    subnets_managed: int = Field(default=0, ge=0)
    ip_utilization_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    active_alerts_total: int = Field(default=0, ge=0)
    active_alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    open_incidents: int = Field(default=0, ge=0)
    synthetic_probes_total: int = Field(default=0, ge=0)
    synthetic_probes_passing: int = Field(default=0, ge=0)
    edge_agents_online: int = Field(default=0, ge=0)
    samples_ingested_last_hour: int = Field(default=0, ge=0)
    avg_fleet_latency_ms: float | None = Field(default=None, ge=0.0)
    avg_compliance_score_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    playbooks_executed_24h: int = Field(default=0, ge=0)

    @computed_field
    @property
    def fleet_availability_pct(self) -> float:
        """Compute percentage of managed devices currently online."""
        if self.devices_total == 0:
            return 100.0
        return round((self.devices_online / self.devices_total) * 100.0, 2)


# ---------------------------------------------------------------------------
# Bulk Operations & Error Envelopes
# ---------------------------------------------------------------------------


class BulkActionRequest(BaseSchema):
    """Generic request payload for applying an action to a batch of entity IDs."""

    action: BulkActionType = Field(..., description="Operation to perform on each target.")
    ids: list[str] = Field(
        ..., min_length=1, max_length=500, description="Unique target entity IDs."
    )
    parameters: MetadataDict = Field(
        default_factory=dict,
        description="Action-specific parameters (e.g. tags, group_id, resolution note).",
    )
    dry_run: bool = Field(
        default=False, description="Validate permissions and targets without mutating state."
    )

    @field_validator("ids")
    @classmethod
    def _deduplicate_ids(cls, values: list[str]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for raw in values:
            cleaned = raw.strip()
            if not cleaned:
                raise ValueError("Bulk action IDs must not contain blank values.")
            if cleaned not in seen:
                seen.add(cleaned)
                unique.append(cleaned)
        return unique


class BulkActionItemResult(BaseSchema):
    """Per-entity outcome within a bulk action execution."""

    id: str = Field(..., description="Target entity ID.")
    success: bool = Field(..., description="Whether the action succeeded for this entity.")
    error_code: str | None = Field(default=None, description="Machine-readable error code.")
    message: str | None = Field(default=None, description="Optional status or failure detail.")


class BulkActionResponse(BaseSchema):
    """Aggregated response for a bulk operation."""

    action: BulkActionType = Field(..., description="Action that was executed.")
    dry_run: bool = Field(default=False, description="Whether this was a dry-run validation.")
    requested: int = Field(..., ge=0, description="Number of unique IDs submitted.")
    succeeded: int = Field(..., ge=0, description="Number of targets that succeeded.")
    failed: int = Field(..., ge=0, description="Number of targets that failed.")
    results: list[BulkActionItemResult] = Field(
        default_factory=list, description="Per-target status breakdown."
    )


class FieldError(BaseSchema):
    """Validation failure detail pinned to a specific request field."""

    field: str = Field(..., description="Dot-delimited field location.")
    message: str = Field(..., description="Human-readable validation error.")
    code: str = Field(default="invalid_value", description="Short error type identifier.")


class ErrorDetail(BaseSchema):
    """Structured error body matching `NetPulseError.to_dict()['error']`."""

    code: str = Field(..., description="Machine-readable domain error code.")
    message: str = Field(..., description="Human-readable summary of the error.")
    details: MetadataDict = Field(
        default_factory=dict, description="Additional structured error context."
    )
    field_errors: list[FieldError] = Field(
        default_factory=list, description="Field-level validation errors, if applicable."
    )


class ErrorResponse(BaseSchema):
    """Top-level API error envelope returned on 4xx/5xx responses."""

    error: ErrorDetail = Field(..., description="Structured error payload.")
    request_id: str | None = Field(
        default=None, description="Correlation request ID for log tracing."
    )
    timestamp: UTCDatetime = Field(
        default_factory=utcnow, description="UTC timestamp when the error occurred."
    )
