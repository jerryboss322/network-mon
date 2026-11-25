"""CMDB Devices, Network Interfaces & Device Groups REST API router (v1).

Implements the complete managed-asset inventory surface for NetPulse:

- **Devices**: Multi-criteria search/filtering (site, rack, group, status,
  device_type, vendor, tag, text search, pagination, multi-field sorting),
  full CRUD with rack U-slot collision checking, fleet health summaries,
  bulk onboarding import (with dry-run and hostname upsert), and JSON/CSV
  inventory export.
- **Device Interfaces**: Per-device interface catalog, creation with automatic
  ``if_index`` allocation, partial updates (admin/oper status, VLAN, speed,
  uplink/monitoring flags), and deletion.
- **Device Groups**: Static and dynamic rule-based device groups, bulk member
  assignment/removal, and live dynamic membership resolution via
  :meth:`DeviceGroup.matches_device`.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import AliasChoices, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db_session as get_db
from app.api.v1.sites import (
    TenantRequestContext,
    record_audit_event,
    resolve_tenant_context,
)
from app.core.events import Event, EventSeverity, get_event_bus
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.db.base import utcnow
from app.db.repositories.inventory import (
    CredentialRepository,
    DeviceGroupRepository,
    DeviceRepository,
    InterfaceRepository,
    RackRepository,
    SiteRepository,
)
from app.models.enums import (
    AuditAction,
    DeviceStatus,
    DeviceType,
    DeviceVendor,
    DuplexMode,
    InterfaceStatus,
    InterfaceType,
)
from app.models.inventory import (
    CredentialProfile,
    Device,
    DeviceGroup,
    DeviceInterface,
    Rack,
    Site,
    normalize_ip_address,
    normalize_mac_address,
)
from app.schemas.common import BaseSchema, PaginationMeta

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Devices & Groups"])


# ---------------------------------------------------------------------------
# Enum Normalization Helpers
# ---------------------------------------------------------------------------

_STATUS_ALIASES: dict[str, str] = {
    "online": DeviceStatus.UP.value,
    "offline": DeviceStatus.DOWN.value,
    "healthy": DeviceStatus.UP.value,
    "error": DeviceStatus.CRITICAL.value,
}

_DEVICE_TYPE_ALIASES: dict[str, str] = {
    "other": DeviceType.UNKNOWN.value,
    "edge_gateway": DeviceType.GATEWAY.value,
    "sd_wan": DeviceType.SDWAN_EDGE.value,
}

_VENDOR_ALIASES: dict[str, str] = {
    "cisco systems": DeviceVendor.CISCO.value,
    "arista networks": DeviceVendor.ARISTA.value,
    "juniper networks": DeviceVendor.JUNIPER.value,
    "palo alto": DeviceVendor.PALO_ALTO.value,
    "palo alto networks": DeviceVendor.PALO_ALTO.value,
    "paloalto": DeviceVendor.PALO_ALTO.value,
    "f5 networks": DeviceVendor.F5.value,
    "aruba": DeviceVendor.HPE_ARUBA.value,
    "hpe": DeviceVendor.HPE_ARUBA.value,
    "hp": DeviceVendor.HPE_ARUBA.value,
    "check point": DeviceVendor.CHECKPOINT.value,
    "ubuntu": DeviceVendor.LINUX.value,
    "debian": DeviceVendor.LINUX.value,
    "rhel": DeviceVendor.LINUX.value,
    "redhat": DeviceVendor.LINUX.value,
    "centos": DeviceVendor.LINUX.value,
}

_INTERFACE_TYPE_ALIASES: dict[str, str] = {
    "vlan_svi": InterfaceType.SVI.value,
    "10gbe": InterfaceType.TEN_GIGABIT_ETHERNET.value,
    "1gbe": InterfaceType.GIGABIT_ETHERNET.value,
    "100gbe": InterfaceType.HUNDRED_GIGABIT_ETHERNET.value,
}


def _normalize_device_status(raw: str | DeviceStatus | None) -> str:
    if raw is None:
        return DeviceStatus.UNKNOWN.value
    if isinstance(raw, DeviceStatus):
        return raw.value
    cleaned = raw.strip().lower()
    mapped = _STATUS_ALIASES.get(cleaned, cleaned)
    try:
        return DeviceStatus(mapped).value
    except ValueError as exc:
        valid = [s.value for s in DeviceStatus]
        raise ValidationError(
            f"Invalid device status {raw!r}; expected one of {valid}",
            details={"status": raw, "valid": valid},
        ) from exc


def _normalize_device_type(raw: str | DeviceType | None) -> str:
    if raw is None:
        return DeviceType.UNKNOWN.value
    if isinstance(raw, DeviceType):
        return raw.value
    cleaned = raw.strip().lower().replace("-", "_").replace(" ", "_")
    mapped = _DEVICE_TYPE_ALIASES.get(cleaned, cleaned)
    try:
        return DeviceType(mapped).value
    except ValueError as exc:
        valid = [t.value for t in DeviceType]
        raise ValidationError(
            f"Invalid device_type {raw!r}; expected one of {valid}",
            details={"device_type": raw, "valid": valid},
        ) from exc


def _normalize_device_vendor(raw: str | DeviceVendor | None) -> str:
    if raw is None or not str(raw).strip():
        return DeviceVendor.UNKNOWN.value
    if isinstance(raw, DeviceVendor):
        return raw.value
    cleaned = raw.strip().lower()
    mapped = _VENDOR_ALIASES.get(cleaned, cleaned.replace("-", "_").replace(" ", "_"))
    try:
        return DeviceVendor(mapped).value
    except ValueError:
        return DeviceVendor.GENERIC.value


def _normalize_interface_type(raw: str | InterfaceType | None) -> str:
    if raw is None:
        return InterfaceType.ETHERNET.value
    if isinstance(raw, InterfaceType):
        return raw.value
    cleaned = raw.strip().lower().replace("-", "_").replace(" ", "_")
    mapped = _INTERFACE_TYPE_ALIASES.get(cleaned, cleaned)
    try:
        return InterfaceType(mapped).value
    except ValueError as exc:
        valid = [t.value for t in InterfaceType]
        raise ValidationError(
            f"Invalid interface_type {raw!r}; expected one of {valid}",
            details={"interface_type": raw, "valid": valid},
        ) from exc


def _normalize_tags(raw: list[str] | dict[str, Any] | None) -> list[str]:
    """Normalize tags from either a list of strings or a key-value dict."""
    if raw is None:
        return []
    result: list[str] = []
    seen: set[str] = set()
    if isinstance(raw, dict):
        for k, v in raw.items():
            tag = f"{k}:{v}" if v not in (None, "", True) else str(k)
            cleaned = tag.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.append(cleaned)
    else:
        for item in raw:
            cleaned = str(item).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.append(cleaned)
    return result


# ---------------------------------------------------------------------------
# Device, Interface & Device Group API Schemas
# ---------------------------------------------------------------------------


class DeviceCreateRequest(BaseSchema):
    """Request payload to onboard a new managed device."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        validation_alias=AliasChoices("hostname", "name"),
    )
    fqdn: str | None = Field(default=None, max_length=255)
    management_ip: str = Field(
        ...,
        min_length=2,
        max_length=64,
        validation_alias=AliasChoices("management_ip", "ip_address"),
    )
    secondary_ips_json: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("secondary_ips_json", "secondary_ips"),
    )
    mac_address: str | None = Field(default=None, max_length=32)
    device_type: str = Field(default=DeviceType.ROUTER.value, max_length=32)
    vendor: str = Field(default=DeviceVendor.UNKNOWN.value, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    serial_number: str | None = Field(default=None, max_length=128)
    asset_tag: str | None = Field(default=None, max_length=128)
    site_id: str | None = None
    rack_id: str | None = None
    rack_unit_start: int | None = Field(
        default=None,
        ge=1,
        le=100,
        validation_alias=AliasChoices("rack_unit_start", "rack_u_position"),
    )
    rack_unit_height: int | None = Field(
        default=1,
        ge=1,
        le=42,
        validation_alias=AliasChoices("rack_unit_height", "rack_u_height"),
    )
    credential_profile_id: str | None = None
    status: str = Field(default=DeviceStatus.UNKNOWN.value, max_length=32)
    polling_enabled: bool = True
    snmp_enabled: bool = True
    icmp_enabled: bool = True
    polling_interval_seconds: int = Field(
        default=60,
        ge=5,
        le=86400,
        validation_alias=AliasChoices("polling_interval_seconds", "poll_interval_seconds"),
    )
    tags: list[str] | dict[str, Any] = Field(
        default_factory=list,
        validation_alias=AliasChoices("tags", "tags_json"),
    )
    custom_fields: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("custom_fields", "custom_fields_json"),
    )
    sys_descr: str | None = None
    sys_object_id: str | None = Field(default=None, max_length=128)
    sys_location: str | None = Field(default=None, max_length=255)
    sys_contact: str | None = Field(default=None, max_length=255)
    group_ids: list[str] = Field(default_factory=list)

    @field_validator("management_ip")
    @classmethod
    def _val_ip(cls, value: str) -> str:
        normalized = normalize_ip_address(value)
        if normalized is None:
            raise ValueError("management_ip must be a valid IPv4 or IPv6 address")
        return normalized

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)


class DeviceUpdateRequest(BaseSchema):
    """Partial update payload for an existing managed device."""

    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    management_ip: str | None = Field(default=None, min_length=2, max_length=64)
    secondary_ips_json: list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices("secondary_ips_json", "secondary_ips"),
    )
    mac_address: str | None = Field(default=None, max_length=32)
    device_type: str | None = Field(default=None, max_length=32)
    vendor: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    serial_number: str | None = Field(default=None, max_length=128)
    asset_tag: str | None = Field(default=None, max_length=128)
    site_id: str | None = None
    rack_id: str | None = None
    rack_unit_start: int | None = Field(
        default=None,
        ge=1,
        le=100,
        validation_alias=AliasChoices("rack_unit_start", "rack_u_position"),
    )
    rack_unit_height: int | None = Field(
        default=None,
        ge=1,
        le=42,
        validation_alias=AliasChoices("rack_unit_height", "rack_u_height"),
    )
    credential_profile_id: str | None = None
    status: str | None = Field(default=None, max_length=32)
    polling_enabled: bool | None = None
    snmp_enabled: bool | None = None
    icmp_enabled: bool | None = None
    polling_interval_seconds: int | None = Field(
        default=None,
        ge=5,
        le=86400,
        validation_alias=AliasChoices("polling_interval_seconds", "poll_interval_seconds"),
    )
    tags: list[str] | dict[str, Any] | None = Field(
        default=None,
        validation_alias=AliasChoices("tags", "tags_json"),
    )
    custom_fields: dict[str, Any] | None = Field(
        default=None,
        validation_alias=AliasChoices("custom_fields", "custom_fields_json"),
    )
    sys_descr: str | None = None
    sys_object_id: str | None = Field(default=None, max_length=128)
    sys_location: str | None = Field(default=None, max_length=255)
    sys_contact: str | None = Field(default=None, max_length=255)
    uptime_seconds: int | None = Field(default=None, ge=0)

    @field_validator("management_ip")
    @classmethod
    def _val_ip(cls, value: str | None) -> str | None:
        return normalize_ip_address(value)

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)


class DeviceResponse(BaseSchema):
    """Standard read representation of a managed network device."""

    id: str
    org_id: str
    site_id: str | None = None
    site_name: str | None = None
    rack_id: str | None = None
    rack_name: str | None = None
    credential_profile_id: str | None = None
    hostname: str
    fqdn: str | None = None
    management_ip: str
    secondary_ips: list[str] = Field(default_factory=list)
    mac_address: str | None = None
    device_type: str
    vendor: str
    model: str | None = None
    os_version: str | None = None
    serial_number: str | None = None
    asset_tag: str | None = None
    rack_unit_start: int | None = None
    rack_unit_height: int | None = 1
    status: str
    polling_enabled: bool
    snmp_enabled: bool
    icmp_enabled: bool
    polling_interval_seconds: int
    tags: list[str] = Field(default_factory=list)
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None
    uptime_seconds: int | None = None
    uptime_human: str | None = None
    is_stale: bool = False
    interface_count: int = 0
    last_seen_at: datetime | None = None
    last_polled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class DeviceInterfaceCreateRequest(BaseSchema):
    """Create payload for a physical or logical device interface."""

    if_index: int | None = Field(default=None, ge=0)
    name: str = Field(..., min_length=1, max_length=128)
    alias: str | None = Field(default=None, max_length=255)
    description: str | None = None
    mac_address: str | None = Field(default=None, max_length=32)
    ip_address: str | None = Field(default=None, max_length=64)
    subnet_mask: str | None = Field(default=None, max_length=64)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    interface_type: str = Field(default=InterfaceType.ETHERNET.value, max_length=32)
    speed_mbps: int | None = Field(default=None, ge=0, le=10_000_000)
    mtu: int | None = Field(default=1500, ge=68, le=65535)
    admin_status: str = Field(default=InterfaceStatus.UP.value, max_length=32)
    oper_status: str = Field(default=InterfaceStatus.UP.value, max_length=32)
    duplex: str = Field(default=DuplexMode.FULL.value, max_length=16)
    is_monitored: bool = True
    is_uplink: bool = False

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)

    @field_validator("ip_address")
    @classmethod
    def _val_ip(cls, value: str | None) -> str | None:
        return normalize_ip_address(value)


class DeviceInterfaceUpdateRequest(BaseSchema):
    """Partial update payload for a device interface."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    alias: str | None = Field(default=None, max_length=255)
    description: str | None = None
    mac_address: str | None = Field(default=None, max_length=32)
    ip_address: str | None = Field(default=None, max_length=64)
    subnet_mask: str | None = Field(default=None, max_length=64)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    interface_type: str | None = Field(default=None, max_length=32)
    speed_mbps: int | None = Field(default=None, ge=0, le=10_000_000)
    mtu: int | None = Field(default=None, ge=68, le=65535)
    admin_status: str | None = Field(default=None, max_length=32)
    oper_status: str | None = Field(default=None, max_length=32)
    duplex: str | None = Field(default=None, max_length=16)
    is_monitored: bool | None = None
    is_uplink: bool | None = None
    utilization_in_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    utilization_out_pct: float | None = Field(default=None, ge=0.0, le=100.0)

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)

    @field_validator("ip_address")
    @classmethod
    def _val_ip(cls, value: str | None) -> str | None:
        return normalize_ip_address(value)


class DeviceInterfaceResponse(BaseSchema):
    """Full representation of a network interface."""

    id: str
    org_id: str
    device_id: str
    if_index: int
    name: str
    alias: str | None = None
    description: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    vlan_id: int | None = None
    interface_type: str
    speed_mbps: int | None = None
    mtu: int | None = 1500
    admin_status: str
    oper_status: str
    duplex: str
    is_monitored: bool
    is_uplink: bool
    in_octets_last: int | None = None
    out_octets_last: int | None = None
    in_errors_last: int | None = None
    out_errors_last: int | None = None
    utilization_in_pct: float = 0.0
    utilization_out_pct: float = 0.0
    max_utilization_pct: float = 0.0
    is_up: bool = False
    created_at: datetime
    updated_at: datetime


class DeviceDetailResponse(DeviceResponse):
    """Expanded device view embedding site, rack, redacted credential, interfaces, and groups."""

    site: dict[str, Any] | None = None
    rack: dict[str, Any] | None = None
    credential_profile: dict[str, Any] | None = None
    interfaces: list[DeviceInterfaceResponse] = Field(default_factory=list)
    groups: list[dict[str, Any]] = Field(default_factory=list)


class DeviceListResponse(BaseSchema):
    """Paginated device collection envelope."""

    items: list[DeviceResponse]
    meta: PaginationMeta


class DeviceSummaryResponse(BaseSchema):
    """Fleet-wide CMDB inventory summary across statuses, types, vendors, and sites."""

    total: int
    online_count: int
    degraded_count: int
    offline_count: int
    maintenance_count: int
    availability_pct: float
    polling_enabled_count: int
    snmp_enabled_count: int
    icmp_enabled_count: int
    stale_count: int
    by_status: dict[str, int]
    by_type: dict[str, int]
    by_vendor: dict[str, int]
    by_site: dict[str, int]
    interfaces_by_status: dict[str, int]


class BulkImportRequest(BaseSchema):
    """Bulk device onboarding request supporting dry-run validation and hostname upsert."""

    devices: list[DeviceCreateRequest] = Field(..., min_length=1, max_length=500)
    upsert_on_hostname: bool = True
    default_site_id: str | None = None
    default_credential_profile_id: str | None = None
    dry_run: bool = False


class BulkImportRowError(BaseSchema):
    """Error recorded for an individual row during bulk import."""

    row_index: int
    hostname: str | None = None
    management_ip: str | None = None
    error_code: str
    message: str


class BulkImportResultResponse(BaseSchema):
    """Aggregated outcome of a bulk device import operation."""

    dry_run: bool = False
    total_submitted: int
    created_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    created_device_ids: list[str] = Field(default_factory=list)
    updated_device_ids: list[str] = Field(default_factory=list)
    errors: list[BulkImportRowError] = Field(default_factory=list)


class DeviceInterfaceListResponse(BaseSchema):
    """List of interfaces for a device with operational status breakdown."""

    device_id: str
    total: int
    status_summary: dict[str, int]
    items: list[DeviceInterfaceResponse]


class DeviceGroupCreateRequest(BaseSchema):
    """Create payload for a static or dynamic operational device group."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    group_type: Literal["static", "dynamic"] | None = None
    is_dynamic: bool | None = None
    dynamic_filter_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("dynamic_filter_json", "dynamic_filter"),
    )
    color: str = Field(default="#3b82f6", pattern=r"^#[0-9a-fA-F]{6}$")
    device_ids: list[str] = Field(default_factory=list)


class DeviceGroupUpdateRequest(BaseSchema):
    """Partial update payload for a device group."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    group_type: Literal["static", "dynamic"] | None = None
    is_dynamic: bool | None = None
    dynamic_filter_json: dict[str, Any] | None = Field(
        default=None,
        validation_alias=AliasChoices("dynamic_filter_json", "dynamic_filter"),
    )
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    device_ids: list[str] | None = None


class DeviceGroupMembersRequest(BaseSchema):
    """Payload for attaching one or more devices to a group."""

    device_ids: list[str] = Field(..., min_length=1, max_length=500)


class DeviceGroupResponse(BaseSchema):
    """Full representation of a device group."""

    id: str
    org_id: str
    name: str
    description: str | None = None
    group_type: str
    is_dynamic: bool
    dynamic_filter_json: dict[str, Any] = Field(default_factory=dict)
    color: str
    member_device_ids: list[str] = Field(default_factory=list)
    member_count: int = 0
    resolved_device_count: int = 0
    online_count: int = 0
    created_at: datetime
    updated_at: datetime


class DeviceGroupListResponse(BaseSchema):
    """Paginated device group list."""

    items: list[DeviceGroupResponse]
    meta: PaginationMeta


class ResolvedGroupDevicesResponse(BaseSchema):
    """Resolved devices belonging to a static or dynamic group."""

    group_id: str
    group_name: str
    group_type: str
    dynamic_filter_json: dict[str, Any] = Field(default_factory=dict)
    total: int
    items: list[DeviceResponse]


# ---------------------------------------------------------------------------
# Serialization & Validation Helpers
# ---------------------------------------------------------------------------


def _serialize_interface(iface: DeviceInterface) -> DeviceInterfaceResponse:
    return DeviceInterfaceResponse(
        id=iface.id,
        org_id=iface.org_id,
        device_id=iface.device_id,
        if_index=iface.if_index,
        name=iface.name,
        alias=iface.alias,
        description=iface.description,
        mac_address=iface.mac_address,
        ip_address=iface.ip_address,
        subnet_mask=iface.subnet_mask,
        vlan_id=iface.vlan_id,
        interface_type=iface.interface_type,
        speed_mbps=iface.speed_mbps,
        mtu=iface.mtu,
        admin_status=iface.admin_status,
        oper_status=iface.oper_status,
        duplex=iface.duplex,
        is_monitored=iface.is_monitored,
        is_uplink=iface.is_uplink,
        in_octets_last=iface.in_octets_last,
        out_octets_last=iface.out_octets_last,
        in_errors_last=iface.in_errors_last,
        out_errors_last=iface.out_errors_last,
        utilization_in_pct=float(iface.utilization_in_pct or 0.0),
        utilization_out_pct=float(iface.utilization_out_pct or 0.0),
        max_utilization_pct=float(iface.max_utilization_pct),
        is_up=iface.is_up,
        created_at=iface.created_at,
        updated_at=iface.updated_at,
    )


def _serialize_device(
    device: Device,
    *,
    site_name: str | None = None,
    rack_name: str | None = None,
    interface_count: int = 0,
) -> DeviceResponse:
    return DeviceResponse(
        id=device.id,
        org_id=device.org_id,
        site_id=device.site_id,
        site_name=site_name,
        rack_id=device.rack_id,
        rack_name=rack_name,
        credential_profile_id=device.credential_profile_id,
        hostname=device.hostname,
        fqdn=device.fqdn,
        management_ip=device.management_ip,
        secondary_ips=list(device.secondary_ips_json or []),
        mac_address=device.mac_address,
        device_type=device.device_type,
        vendor=device.vendor,
        model=device.model,
        os_version=device.os_version,
        serial_number=device.serial_number,
        asset_tag=device.asset_tag,
        rack_unit_start=device.rack_unit_start,
        rack_unit_height=device.rack_unit_height,
        status=device.status,
        polling_enabled=device.polling_enabled,
        snmp_enabled=device.snmp_enabled,
        icmp_enabled=device.icmp_enabled,
        polling_interval_seconds=device.polling_interval_seconds,
        tags=list(device.tags_json or []),
        custom_fields=dict(device.custom_fields_json or {}),
        sys_descr=device.sys_descr,
        sys_object_id=device.sys_object_id,
        sys_location=device.sys_location,
        sys_contact=device.sys_contact,
        uptime_seconds=device.uptime_seconds,
        uptime_human=device.uptime_human,
        is_stale=device.is_stale(),
        interface_count=interface_count,
        last_seen_at=device.last_seen_at,
        last_polled_at=device.last_polled_at,
        created_at=device.created_at,
        updated_at=device.updated_at,
    )


def _enrich_devices(db: Session, org_id: str, devices: list[Device]) -> list[DeviceResponse]:
    if not devices:
        return []
    device_ids = [d.id for d in devices]
    site_ids = list({d.site_id for d in devices if d.site_id})
    rack_ids = list({d.rack_id for d in devices if d.rack_id})

    site_names = {
        s.id: s.name for s in SiteRepository(db, org_id=org_id).get_many_by_ids(site_ids)
    }
    rack_names = {
        r.id: r.name for r in RackRepository(db, org_id=org_id).get_many_by_ids(rack_ids)
    }
    iface_rows = db.execute(
        select(DeviceInterface.device_id, func.count(DeviceInterface.id))
        .where(DeviceInterface.org_id == org_id, DeviceInterface.device_id.in_(device_ids))
        .group_by(DeviceInterface.device_id)
    ).all()
    iface_counts = {str(did): int(cnt) for did, cnt in iface_rows}

    return [
        _serialize_device(
            dev,
            site_name=site_names.get(dev.site_id) if dev.site_id else None,
            rack_name=rack_names.get(dev.rack_id) if dev.rack_id else None,
            interface_count=iface_counts.get(dev.id, 0),
        )
        for dev in devices
    ]


def _validate_device_foreign_keys(
    db: Session,
    org_id: str,
    *,
    site_id: str | None,
    rack_id: str | None,
    credential_profile_id: str | None,
    rack_unit_start: int | None,
    rack_unit_height: int | None,
    exclude_device_id: str | None = None,
) -> tuple[Site | None, Rack | None, CredentialProfile | None]:
    """Validate optional site, rack (plus U-slot collision), and credential profile references."""
    site: Site | None = None
    rack: Rack | None = None
    cred: CredentialProfile | None = None

    if site_id is not None:
        site = SiteRepository(db, org_id=org_id).get_by_id_or_raise(site_id)

    if rack_id is not None:
        rack = RackRepository(db, org_id=org_id).get_by_id_or_raise(rack_id)
        if site is not None and rack.site_id != site.id:
            raise ValidationError(
                f"Rack '{rack.name}' does not belong to site '{site.name}'",
                details={"rack_id": rack.id, "site_id": site.id, "rack_site_id": rack.site_id},
            )
        if rack_unit_start is not None:
            height = max(1, int(rack_unit_height or 1))
            if not rack.can_fit_device(
                rack_unit_start,
                height,
                exclude_device_id=exclude_device_id,
            ):
                raise ConflictError(
                    f"Rack '{rack.name}' cannot fit a {height}U device at U{rack_unit_start} "
                    f"(out of bounds or collides with mounted equipment)",
                    details={
                        "rack_id": rack.id,
                        "rack_unit_start": rack_unit_start,
                        "rack_unit_height": height,
                        "total_u": rack.total_u,
                    },
                )

    if credential_profile_id is not None:
        cred = CredentialRepository(db, org_id=org_id).get_by_id_or_raise(credential_profile_id)

    return site, rack, cred


def _resolve_group_devices(
    db: Session,
    org_id: str,
    group: DeviceGroup,
) -> list[Device]:
    """Resolve effective device list for a static or dynamic device group."""
    group_repo = DeviceGroupRepository(db, org_id=org_id)
    device_repo = DeviceRepository(db, org_id=org_id)

    static_members = group_repo.list_members(group.id)
    if not group.is_dynamic:
        return static_members

    all_devices = device_repo.list()
    matched_by_id: dict[str, Device] = {d.id: d for d in static_members}
    for dev in all_devices:
        if group.matches_device(dev):
            matched_by_id[dev.id] = dev
    return sorted(matched_by_id.values(), key=lambda d: d.hostname.lower())


def _serialize_group(
    db: Session,
    org_id: str,
    group: DeviceGroup,
) -> DeviceGroupResponse:
    group_repo = DeviceGroupRepository(db, org_id=org_id)
    member_ids = group_repo.list_member_device_ids(group.id)
    resolved = _resolve_group_devices(db, org_id, group)
    online_count = sum(1 for d in resolved if d.status == DeviceStatus.UP.value)
    return DeviceGroupResponse(
        id=group.id,
        org_id=group.org_id,
        name=group.name,
        description=group.description,
        group_type=group.group_type,
        is_dynamic=group.is_dynamic,
        dynamic_filter_json=dict(group.dynamic_filter_json or {}),
        color=group.color,
        member_device_ids=member_ids,
        member_count=len(member_ids),
        resolved_device_count=len(resolved),
        online_count=online_count,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


# ---------------------------------------------------------------------------
# Device Endpoints (static paths FIRST before /devices/{device_id})
# ---------------------------------------------------------------------------


@router.get(
    "/devices",
    response_model=DeviceListResponse,
    summary="List and filter managed devices",
)
def list_devices(
    site_id: str | None = Query(default=None),
    rack_id: str | None = Query(default=None),
    group_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    device_type: str | None = Query(default=None),
    vendor: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    polling_enabled: bool | None = Query(default=None),
    snmp_enabled: bool | None = Query(default=None),
    icmp_enabled: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    q: str | None = Query(default=None, max_length=200, description="Alias for search."),
    sort_by: str = Query(default="hostname", max_length=64),
    sort_order: Literal["asc", "desc"] = Query(default="asc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceListResponse:
    """Query devices with multi-dimensional filtering, full-text search, sorting, and pagination."""
    repo = DeviceRepository(db, org_id=ctx.org_id)

    allowed_sort = {
        "hostname",
        "management_ip",
        "status",
        "device_type",
        "vendor",
        "model",
        "uptime_seconds",
        "last_seen_at",
        "created_at",
        "updated_at",
    }
    if sort_by not in allowed_sort:
        raise ValidationError(
            f"Unsupported sort_by field '{sort_by}' for devices",
            details={"allowed": sorted(allowed_sort)},
        )

    normalized_status: list[str] | str | None = None
    if status_filter:
        parts = [p.strip() for p in status_filter.split(",") if p.strip()]
        normalized_list = [_normalize_device_status(p) for p in parts]
        normalized_status = normalized_list[0] if len(normalized_list) == 1 else normalized_list

    normalized_type: list[str] | str | None = None
    if device_type:
        parts = [p.strip() for p in device_type.split(",") if p.strip()]
        normalized_types = [_normalize_device_type(p) for p in parts]
        normalized_type = normalized_types[0] if len(normalized_types) == 1 else normalized_types

    order_expr = f"-{sort_by}" if sort_order == "desc" else sort_by
    page_res = repo.search(
        query=search or q,
        status=normalized_status,
        device_type=normalized_type,
        vendor=vendor,
        site_id=site_id,
        rack_id=rack_id,
        tag=tag,
        snmp_enabled=snmp_enabled,
        icmp_enabled=icmp_enabled,
        group_id=group_id,
        order_by=order_expr,
        page=page,
        page_size=page_size,
    )

    items = page_res.items
    total = page_res.total
    if polling_enabled is not None:
        items = [d for d in items if d.polling_enabled is polling_enabled]
        total = len(items)

    return DeviceListResponse(
        items=_enrich_devices(db, ctx.org_id, items),
        meta=PaginationMeta.from_counts(total=total, page=page, page_size=page_size),
    )


@router.get(
    "/devices/summary",
    response_model=DeviceSummaryResponse,
    summary="Get fleet-wide CMDB inventory summary",
)
def get_devices_summary(
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceSummaryResponse:
    """Aggregate device fleet counts by status, type, vendor, site, and polling posture."""
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)

    summary = device_repo.summary_counts()
    all_devices = device_repo.list()
    by_status = summary["by_status"]
    total = int(summary["total"])

    online = by_status.get(DeviceStatus.UP.value, 0)
    degraded = (
        by_status.get(DeviceStatus.DEGRADED.value, 0)
        + by_status.get(DeviceStatus.WARNING.value, 0)
    )
    offline = (
        by_status.get(DeviceStatus.DOWN.value, 0)
        + by_status.get(DeviceStatus.CRITICAL.value, 0)
        + by_status.get(DeviceStatus.UNREACHABLE.value, 0)
    )
    maintenance = by_status.get(DeviceStatus.MAINTENANCE.value, 0)
    availability = round((online / total) * 100.0, 2) if total > 0 else 100.0

    polling_enabled_count = sum(1 for d in all_devices if d.polling_enabled)
    snmp_enabled_count = sum(1 for d in all_devices if d.snmp_enabled)
    icmp_enabled_count = sum(1 for d in all_devices if d.icmp_enabled)
    stale_count = sum(1 for d in all_devices if d.is_stale())

    return DeviceSummaryResponse(
        total=total,
        online_count=online,
        degraded_count=degraded,
        offline_count=offline,
        maintenance_count=maintenance,
        availability_pct=availability,
        polling_enabled_count=polling_enabled_count,
        snmp_enabled_count=snmp_enabled_count,
        icmp_enabled_count=icmp_enabled_count,
        stale_count=stale_count,
        by_status=by_status,
        by_type=summary["by_type"],
        by_vendor=summary["by_vendor"],
        by_site=summary["by_site"],
        interfaces_by_status=iface_repo.status_summary(),
    )


@router.post(
    "/devices/bulk-import",
    response_model=BulkImportResultResponse,
    summary="Bulk onboard or upsert devices with optional dry-run validation",
)
def bulk_import_devices(
    payload: BulkImportRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> BulkImportResultResponse:
    """Validate and onboard up to 500 devices in a single API call."""
    ctx.require_write("devices")
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)

    # Pre-validate defaults if supplied
    if payload.default_site_id:
        SiteRepository(db, org_id=ctx.org_id).get_by_id_or_raise(payload.default_site_id)
    if payload.default_credential_profile_id:
        CredentialRepository(db, org_id=ctx.org_id).get_by_id_or_raise(
            payload.default_credential_profile_id
        )

    created_ids: list[str] = []
    updated_ids: list[str] = []
    skipped_count = 0
    errors: list[BulkImportRowError] = []
    seen_hostnames: set[str] = set()

    for idx, item in enumerate(payload.devices):
        hostname = item.hostname.strip()
        lower_host = hostname.lower()
        if lower_host in seen_hostnames:
            errors.append(
                BulkImportRowError(
                    row_index=idx,
                    hostname=hostname,
                    management_ip=item.management_ip,
                    error_code="DUPLICATE_IN_BATCH",
                    message=f"Duplicate hostname '{hostname}' inside bulk import payload",
                )
            )
            continue
        seen_hostnames.add(lower_host)

        eff_site_id = item.site_id or payload.default_site_id
        eff_cred_id = item.credential_profile_id or payload.default_credential_profile_id

        try:
            existing = device_repo.get_by_hostname(hostname)
            _validate_device_foreign_keys(
                db,
                ctx.org_id,
                site_id=eff_site_id,
                rack_id=item.rack_id,
                credential_profile_id=eff_cred_id,
                rack_unit_start=item.rack_unit_start,
                rack_unit_height=item.rack_unit_height,
                exclude_device_id=existing.id if existing else None,
            )
            normalized_type = _normalize_device_type(item.device_type)
            normalized_vendor = _normalize_device_vendor(item.vendor)
            normalized_status = _normalize_device_status(item.status)
            normalized_tags = _normalize_tags(item.tags)
            normalized_sec_ips = [
                ip for raw_ip in item.secondary_ips_json if (ip := normalize_ip_address(raw_ip))
            ]

            row_data: dict[str, Any] = {
                "org_id": ctx.org_id,
                "site_id": eff_site_id,
                "rack_id": item.rack_id,
                "credential_profile_id": eff_cred_id,
                "hostname": hostname,
                "fqdn": item.fqdn,
                "management_ip": item.management_ip,
                "secondary_ips_json": normalized_sec_ips,
                "mac_address": item.mac_address,
                "device_type": normalized_type,
                "vendor": normalized_vendor,
                "model": item.model,
                "os_version": item.os_version,
                "serial_number": item.serial_number,
                "asset_tag": item.asset_tag,
                "rack_unit_start": item.rack_unit_start,
                "rack_unit_height": item.rack_unit_height,
                "status": normalized_status,
                "polling_enabled": item.polling_enabled,
                "snmp_enabled": item.snmp_enabled,
                "icmp_enabled": item.icmp_enabled,
                "polling_interval_seconds": item.polling_interval_seconds,
                "tags_json": normalized_tags,
                "custom_fields_json": dict(item.custom_fields or {}),
                "sys_descr": item.sys_descr,
                "sys_object_id": item.sys_object_id,
                "sys_location": item.sys_location,
                "sys_contact": item.sys_contact,
            }

            if existing is not None:
                if not payload.upsert_on_hostname:
                    skipped_count += 1
                    continue
                if not payload.dry_run:
                    update_patch = {k: v for k, v in row_data.items() if k != "org_id"}
                    device_repo.update(existing, update_patch, flush=True)
                    if item.group_ids:
                        for gid in item.group_ids:
                            group_repo.add_member(gid, existing.id, flush=True)
                updated_ids.append(existing.id)
            else:
                if payload.dry_run:
                    created_ids.append(f"dry-run-{idx}")
                else:
                    created = device_repo.create(row_data, flush=True)
                    if item.group_ids:
                        for gid in item.group_ids:
                            group_repo.add_member(gid, created.id, flush=True)
                    created_ids.append(created.id)
        except Exception as exc:
            err_code = getattr(exc, "error_code", "ROW_VALIDATION_ERROR")
            errors.append(
                BulkImportRowError(
                    row_index=idx,
                    hostname=hostname,
                    management_ip=item.management_ip,
                    error_code=str(err_code),
                    message=str(exc),
                )
            )

    if not payload.dry_run:
        record_audit_event(
            db,
            ctx,
            action=AuditAction.CREATE,
            resource_type="device_bulk_import",
            summary=(
                f"Bulk imported {len(created_ids)} created, {len(updated_ids)} updated, "
                f"{len(errors)} failed devices"
            ),
            details={
                "submitted": len(payload.devices),
                "created": len(created_ids),
                "updated": len(updated_ids),
                "skipped": skipped_count,
                "failed": len(errors),
            },
        )
        db.commit()

    return BulkImportResultResponse(
        dry_run=payload.dry_run,
        total_submitted=len(payload.devices),
        created_count=len(created_ids),
        updated_count=len(updated_ids),
        skipped_count=skipped_count,
        failed_count=len(errors),
        created_device_ids=created_ids,
        updated_device_ids=updated_ids,
        errors=errors,
    )


@router.get(
    "/devices/export",
    summary="Export managed device inventory in JSON or CSV format",
)
def export_devices(
    format: Literal["json", "csv"] = Query(default="json"),
    site_id: str | None = Query(default=None),
    rack_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    device_type: str | None = Query(default=None),
    vendor: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Any:
    """Export filtered devices as either a structured JSON document or downloadable CSV."""
    repo = DeviceRepository(db, org_id=ctx.org_id)
    normalized_status = _normalize_device_status(status_filter) if status_filter else None
    normalized_type = _normalize_device_type(device_type) if device_type else None

    page_res = repo.search(
        query=search,
        status=normalized_status,
        device_type=normalized_type,
        vendor=vendor,
        site_id=site_id,
        rack_id=rack_id,
        tag=tag,
        page=1,
        page_size=5000,
    )
    enriched = _enrich_devices(db, ctx.org_id, page_res.items)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.EXPORT,
        resource_type="device",
        summary=f"Exported {len(enriched)} devices as {format.upper()}",
        details={"format": format, "count": len(enriched)},
    )
    db.commit()

    if format == "csv":
        buffer = io.StringIO()
        fieldnames = [
            "id",
            "hostname",
            "fqdn",
            "management_ip",
            "mac_address",
            "device_type",
            "vendor",
            "model",
            "os_version",
            "serial_number",
            "asset_tag",
            "status",
            "site_id",
            "site_name",
            "rack_id",
            "rack_name",
            "polling_enabled",
            "snmp_enabled",
            "icmp_enabled",
            "tags",
            "uptime_seconds",
            "last_seen_at",
        ]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for dev in enriched:
            writer.writerow(
                {
                    "id": dev.id,
                    "hostname": dev.hostname,
                    "fqdn": dev.fqdn or "",
                    "management_ip": dev.management_ip,
                    "mac_address": dev.mac_address or "",
                    "device_type": dev.device_type,
                    "vendor": dev.vendor,
                    "model": dev.model or "",
                    "os_version": dev.os_version or "",
                    "serial_number": dev.serial_number or "",
                    "asset_tag": dev.asset_tag or "",
                    "status": dev.status,
                    "site_id": dev.site_id or "",
                    "site_name": dev.site_name or "",
                    "rack_id": dev.rack_id or "",
                    "rack_name": dev.rack_name or "",
                    "polling_enabled": dev.polling_enabled,
                    "snmp_enabled": dev.snmp_enabled,
                    "icmp_enabled": dev.icmp_enabled,
                    "tags": ";".join(dev.tags),
                    "uptime_seconds": dev.uptime_seconds if dev.uptime_seconds is not None else "",
                    "last_seen_at": dev.last_seen_at.isoformat() if dev.last_seen_at else "",
                }
            )
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="netpulse-devices.csv"'},
        )

    return {
        "exported_at": utcnow().isoformat(),
        "format": "json",
        "count": len(enriched),
        "filters": {
            "site_id": site_id,
            "rack_id": rack_id,
            "status": normalized_status,
            "device_type": normalized_type,
            "vendor": vendor,
            "tag": tag,
            "search": search,
        },
        "devices": [d.model_dump(mode="json") for d in enriched],
    }


@router.post(
    "/devices",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new managed device",
)
def create_device(
    payload: DeviceCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceResponse:
    """Onboard a single managed device into the CMDB inventory."""
    ctx.require_write("devices")
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)

    hostname = payload.hostname.strip()
    if device_repo.get_by_hostname(hostname) is not None:
        raise ConflictError(
            f"Device with hostname '{hostname}' already exists in this organization",
            details={"hostname": hostname},
        )

    site, rack, _ = _validate_device_foreign_keys(
        db,
        ctx.org_id,
        site_id=payload.site_id,
        rack_id=payload.rack_id,
        credential_profile_id=payload.credential_profile_id,
        rack_unit_start=payload.rack_unit_start,
        rack_unit_height=payload.rack_unit_height,
    )
    resolved_site_id = site.id if site else (rack.site_id if rack else None)
    normalized_sec_ips = [
        ip for raw_ip in payload.secondary_ips_json if (ip := normalize_ip_address(raw_ip))
    ]

    device = device_repo.create(
        {
            "org_id": ctx.org_id,
            "site_id": resolved_site_id,
            "rack_id": rack.id if rack else None,
            "credential_profile_id": payload.credential_profile_id,
            "hostname": hostname,
            "fqdn": payload.fqdn,
            "management_ip": payload.management_ip,
            "secondary_ips_json": normalized_sec_ips,
            "mac_address": payload.mac_address,
            "device_type": _normalize_device_type(payload.device_type),
            "vendor": _normalize_device_vendor(payload.vendor),
            "model": payload.model,
            "os_version": payload.os_version,
            "serial_number": payload.serial_number,
            "asset_tag": payload.asset_tag,
            "rack_unit_start": payload.rack_unit_start,
            "rack_unit_height": payload.rack_unit_height,
            "status": _normalize_device_status(payload.status),
            "polling_enabled": payload.polling_enabled,
            "snmp_enabled": payload.snmp_enabled,
            "icmp_enabled": payload.icmp_enabled,
            "polling_interval_seconds": payload.polling_interval_seconds,
            "tags_json": _normalize_tags(payload.tags),
            "custom_fields_json": dict(payload.custom_fields or {}),
            "sys_descr": payload.sys_descr,
            "sys_object_id": payload.sys_object_id,
            "sys_location": payload.sys_location,
            "sys_contact": payload.sys_contact,
        }
    )

    for gid in payload.group_ids:
        group_repo.add_member(gid, device.id)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="device",
        resource_id=device.id,
        summary=f"Created device {device.hostname} ({device.management_ip})",
        details={"hostname": device.hostname, "management_ip": device.management_ip},
    )
    db.commit()
    db.refresh(device)

    get_event_bus().publish_sync(
        Event(
            topic="device.created",
            source="netpulse.api.devices",
            org_id=ctx.org_id,
            severity=EventSeverity.INFO,
            payload=device.to_summary_dict(),
        )
    )
    return _serialize_device(
        device,
        site_name=site.name if site else None,
        rack_name=rack.name if rack else None,
        interface_count=0,
    )


@router.get(
    "/devices/{device_id}",
    response_model=DeviceDetailResponse,
    summary="Get full CMDB details for a single device",
)
def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceDetailResponse:
    """Retrieve a managed device with embedded site, rack, redacted credential, interfaces, and groups."""
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)

    device = device_repo.get_by_id_or_raise(device_id)
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(device.site_id) if device.site_id else None
    rack = RackRepository(db, org_id=ctx.org_id).get_by_id(device.rack_id) if device.rack_id else None
    cred = (
        CredentialRepository(db, org_id=ctx.org_id).get_by_id(device.credential_profile_id)
        if device.credential_profile_id
        else None
    )
    interfaces = iface_repo.list_by_device(device.id)

    # Combine static memberships and dynamic group matches
    static_groups = group_repo.list_groups_for_device(device.id)
    groups_map: dict[str, DeviceGroup] = {g.id: g for g in static_groups}
    for dyn_group in group_repo.list(filters={"group_type": "dynamic"}):
        if dyn_group.matches_device(device):
            groups_map[dyn_group.id] = dyn_group

    base = _serialize_device(
        device,
        site_name=site.name if site else None,
        rack_name=rack.name if rack else None,
        interface_count=len(interfaces),
    )
    return DeviceDetailResponse(
        **base.model_dump(),
        site=site.to_summary_dict() if site else None,
        rack=(
            {
                "id": rack.id,
                "name": rack.name,
                "site_id": rack.site_id,
                "aisle": rack.aisle,
                "row": rack.row,
                "total_u": rack.total_u,
            }
            if rack
            else None
        ),
        credential_profile=cred.to_redacted_dict() if cred else None,
        interfaces=[_serialize_interface(i) for i in interfaces],
        groups=[
            {
                "id": g.id,
                "name": g.name,
                "group_type": g.group_type,
                "color": g.color,
            }
            for g in sorted(groups_map.values(), key=lambda g: g.name.lower())
        ],
    )


@router.patch(
    "/devices/{device_id}",
    response_model=DeviceResponse,
    summary="Update a managed device",
)
def update_device(
    device_id: str,
    payload: DeviceUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceResponse:
    """Partially update device inventory attributes, status, rack placement, or tags."""
    ctx.require_write("devices")
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    device = device_repo.get_by_id_or_raise(device_id)

    raw_patch = payload.model_dump(exclude_unset=True)
    patch: dict[str, Any] = {}

    if "hostname" in raw_patch and raw_patch["hostname"] is not None:
        new_host = raw_patch["hostname"].strip()
        existing = device_repo.get_by_hostname(new_host)
        if existing is not None and existing.id != device.id:
            raise ConflictError(
                f"Another device already uses hostname '{new_host}'",
                details={"hostname": new_host},
            )
        patch["hostname"] = new_host

    for direct_field in (
        "fqdn",
        "management_ip",
        "mac_address",
        "model",
        "os_version",
        "serial_number",
        "asset_tag",
        "site_id",
        "rack_id",
        "rack_unit_start",
        "rack_unit_height",
        "credential_profile_id",
        "polling_enabled",
        "snmp_enabled",
        "icmp_enabled",
        "polling_interval_seconds",
        "sys_descr",
        "sys_object_id",
        "sys_location",
        "sys_contact",
        "uptime_seconds",
    ):
        if direct_field in raw_patch:
            patch[direct_field] = raw_patch[direct_field]

    if "secondary_ips_json" in raw_patch and raw_patch["secondary_ips_json"] is not None:
        patch["secondary_ips_json"] = [
            ip for raw_ip in raw_patch["secondary_ips_json"] if (ip := normalize_ip_address(raw_ip))
        ]
    if "device_type" in raw_patch and raw_patch["device_type"] is not None:
        patch["device_type"] = _normalize_device_type(raw_patch["device_type"])
    if "vendor" in raw_patch and raw_patch["vendor"] is not None:
        patch["vendor"] = _normalize_device_vendor(raw_patch["vendor"])
    if "status" in raw_patch and raw_patch["status"] is not None:
        patch["status"] = _normalize_device_status(raw_patch["status"])
    if "tags" in raw_patch and raw_patch["tags"] is not None:
        patch["tags_json"] = _normalize_tags(raw_patch["tags"])
    if "custom_fields" in raw_patch and raw_patch["custom_fields"] is not None:
        patch["custom_fields_json"] = dict(raw_patch["custom_fields"])

    eff_site_id = patch.get("site_id", device.site_id)
    eff_rack_id = patch.get("rack_id", device.rack_id)
    eff_cred_id = patch.get("credential_profile_id", device.credential_profile_id)
    eff_u_start = patch.get("rack_unit_start", device.rack_unit_start)
    eff_u_height = patch.get("rack_unit_height", device.rack_unit_height)

    site, rack, _ = _validate_device_foreign_keys(
        db,
        ctx.org_id,
        site_id=eff_site_id,
        rack_id=eff_rack_id,
        credential_profile_id=eff_cred_id,
        rack_unit_start=eff_u_start,
        rack_unit_height=eff_u_height,
        exclude_device_id=device.id,
    )

    updated = device_repo.update(device, patch)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="device",
        resource_id=updated.id,
        summary=f"Updated device {updated.hostname}",
        details={"updated_fields": sorted(patch.keys())},
    )
    db.commit()
    db.refresh(updated)

    iface_count = InterfaceRepository(db, org_id=ctx.org_id).count(filters={"device_id": updated.id})
    return _serialize_device(
        updated,
        site_name=site.name if site else None,
        rack_name=rack.name if rack else None,
        interface_count=iface_count,
    )


@router.delete(
    "/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a managed device",
)
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a device from the CMDB inventory."""
    ctx.require_write("devices")
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    device = device_repo.get_by_id_or_raise(device_id)
    device_repo.soft_delete(device)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="device",
        resource_id=device.id,
        summary=f"Soft-deleted device {device.hostname}",
        details={"hostname": device.hostname, "management_ip": device.management_ip},
    )
    db.commit()

    get_event_bus().publish_sync(
        Event(
            topic="device.deleted",
            source="netpulse.api.devices",
            org_id=ctx.org_id,
            severity=EventSeverity.INFO,
            payload={"device_id": device.id, "hostname": device.hostname},
        )
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Device Interface Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/devices/{device_id}/interfaces",
    response_model=DeviceInterfaceListResponse,
    summary="List interfaces belonging to a device",
)
def list_device_interfaces(
    device_id: str,
    oper_status: str | None = Query(default=None),
    admin_status: str | None = Query(default=None),
    is_monitored: bool | None = Query(default=None),
    is_uplink: bool | None = Query(default=None),
    vlan_id: int | None = Query(default=None, ge=1, le=4094),
    search: str | None = Query(default=None, max_length=128),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceInterfaceListResponse:
    """List network interfaces for a specific device with optional status and VLAN filters."""
    DeviceRepository(db, org_id=ctx.org_id).get_by_id_or_raise(device_id)
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)

    interfaces = iface_repo.list_by_device(
        device_id,
        oper_status=oper_status.strip().lower() if oper_status else None,
        admin_status=admin_status.strip().lower() if admin_status else None,
    )
    if is_monitored is not None:
        interfaces = [i for i in interfaces if i.is_monitored is is_monitored]
    if is_uplink is not None:
        interfaces = [i for i in interfaces if i.is_uplink is is_uplink]
    if vlan_id is not None:
        interfaces = [i for i in interfaces if i.vlan_id == vlan_id]
    if search:
        needle = search.strip().lower()
        interfaces = [
            i
            for i in interfaces
            if needle in i.name.lower()
            or needle in (i.alias or "").lower()
            or needle in (i.description or "").lower()
            or needle in (i.ip_address or "").lower()
        ]

    status_summary = iface_repo.status_summary(device_id=device_id)
    return DeviceInterfaceListResponse(
        device_id=device_id,
        total=len(interfaces),
        status_summary=status_summary,
        items=[_serialize_interface(i) for i in interfaces],
    )


@router.post(
    "/devices/{device_id}/interfaces",
    response_model=DeviceInterfaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a network interface to a device",
)
def create_device_interface(
    device_id: str,
    payload: DeviceInterfaceCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceInterfaceResponse:
    """Create a physical or logical interface on an existing device."""
    ctx.require_write("interfaces")
    device = DeviceRepository(db, org_id=ctx.org_id).get_by_id_or_raise(device_id)
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)

    existing_ifaces = iface_repo.list_by_device(device.id)
    if payload.if_index is None:
        next_index = max((i.if_index for i in existing_ifaces), default=0) + 1
    else:
        next_index = payload.if_index
        if iface_repo.get_by_device_and_index(device.id, next_index) is not None:
            raise ConflictError(
                f"Interface with if_index={next_index} already exists on device '{device.hostname}'",
                details={"device_id": device.id, "if_index": next_index},
            )

    try:
        admin_st = InterfaceStatus(payload.admin_status.strip().lower()).value
        oper_st = InterfaceStatus(payload.oper_status.strip().lower()).value
        duplex_val = DuplexMode(payload.duplex.strip().lower()).value
    except ValueError as exc:
        raise ValidationError(f"Invalid interface status or duplex value: {exc}") from exc

    iface = iface_repo.create(
        {
            "org_id": ctx.org_id,
            "device_id": device.id,
            "if_index": next_index,
            "name": payload.name.strip(),
            "alias": payload.alias,
            "description": payload.description,
            "mac_address": payload.mac_address,
            "ip_address": payload.ip_address,
            "subnet_mask": payload.subnet_mask,
            "vlan_id": payload.vlan_id,
            "interface_type": _normalize_interface_type(payload.interface_type),
            "speed_mbps": payload.speed_mbps,
            "mtu": payload.mtu,
            "admin_status": admin_st,
            "oper_status": oper_st,
            "duplex": duplex_val,
            "is_monitored": payload.is_monitored,
            "is_uplink": payload.is_uplink,
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="device_interface",
        resource_id=iface.id,
        summary=f"Added interface {iface.name} (ifIndex={iface.if_index}) to {device.hostname}",
        details={"device_id": device.id, "name": iface.name, "if_index": iface.if_index},
    )
    db.commit()
    db.refresh(iface)
    return _serialize_interface(iface)


@router.patch(
    "/interfaces/{interface_id}",
    response_model=DeviceInterfaceResponse,
    summary="Update a device interface",
)
def update_interface(
    interface_id: str,
    payload: DeviceInterfaceUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceInterfaceResponse:
    """Partially update interface attributes, status, VLAN, or monitoring flags."""
    ctx.require_write("interfaces")
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)
    iface = iface_repo.get_by_id_or_raise(interface_id)

    patch = payload.model_dump(exclude_unset=True)
    if "name" in patch and patch["name"] is not None:
        patch["name"] = patch["name"].strip()
    if "interface_type" in patch and patch["interface_type"] is not None:
        patch["interface_type"] = _normalize_interface_type(patch["interface_type"])
    try:
        if "admin_status" in patch and patch["admin_status"] is not None:
            patch["admin_status"] = InterfaceStatus(patch["admin_status"].strip().lower()).value
        if "oper_status" in patch and patch["oper_status"] is not None:
            patch["oper_status"] = InterfaceStatus(patch["oper_status"].strip().lower()).value
        if "duplex" in patch and patch["duplex"] is not None:
            patch["duplex"] = DuplexMode(patch["duplex"].strip().lower()).value
    except ValueError as exc:
        raise ValidationError(f"Invalid interface enum value: {exc}") from exc

    updated = iface_repo.update(iface, patch)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="device_interface",
        resource_id=updated.id,
        summary=f"Updated interface {updated.name}",
        details={"updated_fields": sorted(patch.keys())},
    )
    db.commit()
    db.refresh(updated)
    return _serialize_interface(updated)


@router.delete(
    "/interfaces/{interface_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a device interface",
)
def delete_interface(
    interface_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Permanently delete a network interface record."""
    ctx.require_write("interfaces")
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)
    iface = iface_repo.get_by_id_or_raise(interface_id)
    iface_name = iface.name
    device_id = iface.device_id
    iface_repo.delete(iface)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="device_interface",
        resource_id=interface_id,
        summary=f"Deleted interface {iface_name}",
        details={"device_id": device_id, "name": iface_name},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Device Group Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/device-groups",
    response_model=DeviceGroupListResponse,
    summary="List static and dynamic device groups",
)
def list_device_groups(
    group_type: Literal["static", "dynamic"] | None = Query(default=None),
    search: str | None = Query(default=None, max_length=160),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceGroupListResponse:
    """List device groups with resolved membership counts."""
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    filters: dict[str, Any] = {}
    if group_type:
        filters["group_type"] = group_type
    if search:
        filters["name__icontains"] = search.strip()

    page_res = group_repo.paginate(page=page, page_size=page_size, filters=filters or None)
    items = [_serialize_group(db, ctx.org_id, g) for g in page_res.items]
    return DeviceGroupListResponse(
        items=items,
        meta=PaginationMeta.from_counts(total=page_res.total, page=page, page_size=page_size),
    )


@router.post(
    "/device-groups",
    response_model=DeviceGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a static or dynamic device group",
)
def create_device_group(
    payload: DeviceGroupCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceGroupResponse:
    """Create a new static or dynamic rule-based device group."""
    ctx.require_write("device_groups")
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)

    cleaned_name = payload.name.strip()
    if group_repo.get_by_name(cleaned_name) is not None:
        raise ConflictError(
            f"Device group '{cleaned_name}' already exists in this organization",
            details={"name": cleaned_name},
        )

    resolved_type = payload.group_type
    if resolved_type is None:
        resolved_type = "dynamic" if payload.is_dynamic else "static"
    if resolved_type == "dynamic" and not payload.dynamic_filter_json:
        raise ValidationError("Dynamic device groups must specify a non-empty dynamic_filter_json.")

    # Validate any initial device_ids belong to this org
    if payload.device_ids:
        found = {d.id for d in device_repo.get_many_by_ids(payload.device_ids)}
        missing = [did for did in payload.device_ids if did not in found]
        if missing:
            raise NotFoundError(
                f"Devices not found in organization: {', '.join(missing)}",
                details={"missing_device_ids": missing},
            )

    group = group_repo.create(
        {
            "org_id": ctx.org_id,
            "name": cleaned_name,
            "description": payload.description,
            "group_type": resolved_type,
            "dynamic_filter_json": dict(payload.dynamic_filter_json or {}),
            "color": payload.color.lower(),
        }
    )
    if payload.device_ids:
        group_repo.add_members(group.id, payload.device_ids)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="device_group",
        resource_id=group.id,
        summary=f"Created {group.group_type} device group '{group.name}'",
        details={"group_type": group.group_type, "initial_members": len(payload.device_ids)},
    )
    db.commit()
    db.refresh(group)
    return _serialize_group(db, ctx.org_id, group)


@router.get(
    "/device-groups/{group_id}",
    response_model=DeviceGroupResponse,
    summary="Get a single device group",
)
def get_device_group(
    group_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceGroupResponse:
    """Retrieve metadata and resolved membership statistics for a device group."""
    group = DeviceGroupRepository(db, org_id=ctx.org_id).get_by_id_or_raise(group_id)
    return _serialize_group(db, ctx.org_id, group)


@router.patch(
    "/device-groups/{group_id}",
    response_model=DeviceGroupResponse,
    summary="Update a device group",
)
def update_device_group(
    group_id: str,
    payload: DeviceGroupUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceGroupResponse:
    """Partially update a device group's metadata, filter rules, or static member list."""
    ctx.require_write("device_groups")
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    group = group_repo.get_by_id_or_raise(group_id)

    raw_patch = payload.model_dump(exclude_unset=True)
    patch: dict[str, Any] = {}

    if "name" in raw_patch and raw_patch["name"] is not None:
        cleaned = raw_patch["name"].strip()
        existing = group_repo.get_by_name(cleaned)
        if existing is not None and existing.id != group.id:
            raise ConflictError(
                f"Device group '{cleaned}' already exists",
                details={"name": cleaned},
            )
        patch["name"] = cleaned

    if "description" in raw_patch:
        patch["description"] = raw_patch["description"]
    if "color" in raw_patch and raw_patch["color"] is not None:
        patch["color"] = raw_patch["color"].lower()
    if "group_type" in raw_patch and raw_patch["group_type"] is not None:
        patch["group_type"] = raw_patch["group_type"]
    elif "is_dynamic" in raw_patch and raw_patch["is_dynamic"] is not None:
        patch["group_type"] = "dynamic" if raw_patch["is_dynamic"] else "static"
    if "dynamic_filter_json" in raw_patch and raw_patch["dynamic_filter_json"] is not None:
        patch["dynamic_filter_json"] = dict(raw_patch["dynamic_filter_json"])

    eff_type = patch.get("group_type", group.group_type)
    eff_filter = patch.get("dynamic_filter_json", group.dynamic_filter_json)
    if eff_type == "dynamic" and not eff_filter:
        raise ValidationError("Dynamic device groups must specify a non-empty dynamic_filter_json.")

    updated = group_repo.update(group, patch) if patch else group

    if "device_ids" in raw_patch and raw_patch["device_ids"] is not None:
        desired = list(dict.fromkeys(raw_patch["device_ids"]))
        if desired:
            found = {d.id for d in device_repo.get_many_by_ids(desired)}
            missing = [did for did in desired if did not in found]
            if missing:
                raise NotFoundError(
                    f"Devices not found in organization: {', '.join(missing)}",
                    details={"missing_device_ids": missing},
                )
        current_ids = set(group_repo.list_member_device_ids(updated.id))
        desired_set = set(desired)
        for to_remove in current_ids - desired_set:
            group_repo.remove_member(updated.id, to_remove)
        to_add = [did for did in desired if did not in current_ids]
        if to_add:
            group_repo.add_members(updated.id, to_add)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="device_group",
        resource_id=updated.id,
        summary=f"Updated device group '{updated.name}'",
        details={"updated_fields": sorted(raw_patch.keys())},
    )
    db.commit()
    db.refresh(updated)
    return _serialize_group(db, ctx.org_id, updated)


@router.delete(
    "/device-groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a device group",
)
def delete_device_group(
    group_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a device group."""
    ctx.require_write("device_groups")
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    group = group_repo.get_by_id_or_raise(group_id)
    group_repo.soft_delete(group)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="device_group",
        resource_id=group.id,
        summary=f"Soft-deleted device group '{group.name}'",
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/device-groups/{group_id}/members",
    response_model=DeviceGroupResponse,
    summary="Add devices to a device group",
)
def add_device_group_members(
    group_id: str,
    payload: DeviceGroupMembersRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> DeviceGroupResponse:
    """Idempotently attach one or more devices to a device group."""
    ctx.require_write("device_groups")
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)

    group = group_repo.get_by_id_or_raise(group_id)
    unique_ids = list(dict.fromkeys(payload.device_ids))
    found = {d.id for d in device_repo.get_many_by_ids(unique_ids)}
    missing = [did for did in unique_ids if did not in found]
    if missing:
        raise NotFoundError(
            f"Devices not found in organization: {', '.join(missing)}",
            details={"missing_device_ids": missing},
        )

    added = group_repo.add_members(group.id, unique_ids)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="device_group",
        resource_id=group.id,
        summary=f"Added {added} member(s) to device group '{group.name}'",
        details={"requested": len(unique_ids), "added": added},
    )
    db.commit()
    return _serialize_group(db, ctx.org_id, group)


@router.delete(
    "/device-groups/{group_id}/members/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a device from a device group",
)
def remove_device_group_member(
    group_id: str,
    device_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Detach a single static device member from a device group."""
    ctx.require_write("device_groups")
    group_repo = DeviceGroupRepository(db, org_id=ctx.org_id)
    group = group_repo.get_by_id_or_raise(group_id)
    removed = group_repo.remove_member(group.id, device_id)
    if not removed:
        raise NotFoundError(
            f"Device '{device_id}' is not a member of group '{group.name}'",
            details={"group_id": group.id, "device_id": device_id},
        )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="device_group",
        resource_id=group.id,
        summary=f"Removed device {device_id} from device group '{group.name}'",
        details={"device_id": device_id},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/device-groups/{group_id}/resolved-devices",
    response_model=ResolvedGroupDevicesResponse,
    summary="Resolve all devices matching a static or dynamic device group",
)
def get_resolved_group_devices(
    group_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> ResolvedGroupDevicesResponse:
    """Evaluate a device group and return all matching managed devices."""
    group = DeviceGroupRepository(db, org_id=ctx.org_id).get_by_id_or_raise(group_id)
    resolved = _resolve_group_devices(db, ctx.org_id, group)
    enriched = _enrich_devices(db, ctx.org_id, resolved)
    return ResolvedGroupDevicesResponse(
        group_id=group.id,
        group_name=group.name,
        group_type=group.group_type,
        dynamic_filter_json=dict(group.dynamic_filter_json or {}),
        total=len(enriched),
        items=enriched,
    )


__all__ = [
    "BulkImportRequest",
    "BulkImportResultResponse",
    "DeviceCreateRequest",
    "DeviceDetailResponse",
    "DeviceGroupCreateRequest",
    "DeviceGroupListResponse",
    "DeviceGroupMembersRequest",
    "DeviceGroupResponse",
    "DeviceGroupUpdateRequest",
    "DeviceInterfaceCreateRequest",
    "DeviceInterfaceListResponse",
    "DeviceInterfaceResponse",
    "DeviceInterfaceUpdateRequest",
    "DeviceListResponse",
    "DeviceResponse",
    "DeviceSummaryResponse",
    "DeviceUpdateRequest",
    "ResolvedGroupDevicesResponse",
    "router",
]
