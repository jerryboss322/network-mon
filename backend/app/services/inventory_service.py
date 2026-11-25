"""CMDB Inventory, IPAM, Site/Rack capacity, Interface, and Device Group service.

Implements :class:`InventoryService`, the primary domain service orchestrating
physical infrastructure, managed network devices, interfaces, IPAM address space,
and static/dynamic device collections for NetPulse:

- **Sites**: Tenant-scoped CRUD, coordinate & code validation, and real-time
  capacity/health rollups (device counts by status, availability score, rack
  utilization, and IPAM counts).
- **Racks**: Cabinet CRUD with strict U-position bounds and overlap/collision
  validation, rack elevation mapping, and next-available slot allocation.
- **Devices**: Full CMDB lifecycle with organization device-quota enforcement,
  IP/MAC normalization, automatic IEEE OUI vendor inference, state-machine
  status transitions publishing typed :class:`~app.core.events.Event` messages
  onto :class:`~app.core.events.EventBus`, rich search/filter/pagination,
  idempotent tag management, and fleet summary analytics.
- **Device Interfaces**: Interface CRUD, idempotent bulk synchronization from
  SNMP/API collectors, 32/64-bit wrap-safe counter utilization calculation,
  and uplink health listing.
- **IPAM Subnets, VLANs, and IP Allocations**: CIDR validation, cross-site and
  cross-organization overlap detection, subnet calculator wrapper, VLAN
  uniqueness enforcement per site, IP conflict detection, automatic utilization
  recalculation, and deterministic next-available-IP allocation
  (:meth:`InventoryService.allocate_next_free_ip`).
- **Device Groups**: Static membership management and a rich dynamic filter
  evaluation engine supporting glob patterns, tags, CIDRs, attributes, and
  structured operator rules.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.events import (
    Event,
    EventBus,
    EventSeverity,
    device_discovered_event,
    device_status_changed_event,
    device_updated_event,
    get_event_bus,
)
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.network_utils import (
    calculate_subnet,
    calculate_utilization_pct,
    cidrs_overlap,
    format_mac,
    ip_in_cidr,
    is_valid_cidr,
    is_valid_ip,
    is_valid_mac,
    lookup_oui_vendor,
    normalize_ip,
    parse_ip,
    parse_network,
    split_subnet,
)
from app.db.base import utcnow
from app.db.repositories.base import BaseRepository, PageResult, SortSpec
from app.db.repositories.identity import AuditLogRepository, OrganizationRepository
from app.db.repositories.inventory import (
    CredentialRepository,
    DeviceGroupRepository,
    DeviceRepository,
    InterfaceRepository,
    RackRepository,
    SiteRepository,
    SubnetRepository,
    VlanRepository,
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
    Device,
    DeviceGroup,
    DeviceInterface,
    IpAllocation,
    Rack,
    Site,
    Subnet,
    Vlan,
    normalize_mac_address,
)
from app.schemas.inventory import SubnetCalculationResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Normalization & Domain Mappings
# ---------------------------------------------------------------------------

_STATUS_ALIASES: dict[str, str] = {
    "online": DeviceStatus.UP.value,
    "active": DeviceStatus.UP.value,
    "healthy": DeviceStatus.UP.value,
    "ok": DeviceStatus.UP.value,
    "offline": DeviceStatus.DOWN.value,
    "failed": DeviceStatus.DOWN.value,
    "error": DeviceStatus.CRITICAL.value,
    "warn": DeviceStatus.WARNING.value,
    "maint": DeviceStatus.MAINTENANCE.value,
    "staged": DeviceStatus.PROVISIONING.value,
    "planned": DeviceStatus.PROVISIONING.value,
    "retired": DeviceStatus.DECOMMISSIONED.value,
}

_DEVICE_TYPE_ALIASES: dict[str, str] = {
    "other": DeviceType.UNKNOWN.value,
    "edge_gateway": DeviceType.GATEWAY.value,
    "l2_switch": DeviceType.ACCESS_SWITCH.value,
    "l3_switch": DeviceType.DISTRIBUTION_SWITCH.value,
    "spine": DeviceType.CORE_SWITCH.value,
    "leaf": DeviceType.DISTRIBUTION_SWITCH.value,
    "fw": DeviceType.FIREWALL.value,
    "ngfw": DeviceType.FIREWALL.value,
    "lb": DeviceType.LOAD_BALANCER.value,
    "adc": DeviceType.LOAD_BALANCER.value,
    "ap": DeviceType.ACCESS_POINT.value,
    "wlc": DeviceType.WIRELESS_CONTROLLER.value,
    "vm": DeviceType.VIRTUAL_MACHINE.value,
    "host": DeviceType.SERVER.value,
    "compute": DeviceType.SERVER.value,
    "sdwan": DeviceType.SDWAN_EDGE.value,
}

_INTERFACE_TYPE_ALIASES: dict[str, str] = {
    "vlan_svi": InterfaceType.SVI.value,
    "port-channel": InterfaceType.PORT_CHANNEL.value,
    "portchannel": InterfaceType.PORT_CHANNEL.value,
    "ae": InterfaceType.LAG.value,
    "bond": InterfaceType.LAG.value,
    "100g": InterfaceType.HUNDRED_GIGABIT_ETHERNET.value,
    "40g": InterfaceType.FORTY_GIGABIT_ETHERNET.value,
    "25g": InterfaceType.TWENTY_FIVE_GIGABIT_ETHERNET.value,
    "10g": InterfaceType.TEN_GIGABIT_ETHERNET.value,
    "1g": InterfaceType.GIGABIT_ETHERNET.value,
    "100m": InterfaceType.FAST_ETHERNET.value,
}

# Mapping from OUI vendor substring -> canonical DeviceVendor enum value
_OUI_VENDOR_KEYWORDS: tuple[tuple[str, DeviceVendor], ...] = (
    ("meraki", DeviceVendor.MERAKI),
    ("cisco", DeviceVendor.CISCO),
    ("arista", DeviceVendor.ARISTA),
    ("juniper", DeviceVendor.JUNIPER),
    ("palo alto", DeviceVendor.PALO_ALTO),
    ("fortinet", DeviceVendor.FORTINET),
    ("check point", DeviceVendor.CHECKPOINT),
    ("checkpoint", DeviceVendor.CHECKPOINT),
    ("f5", DeviceVendor.F5),
    ("aruba", DeviceVendor.HPE_ARUBA),
    ("hewlett packard", DeviceVendor.HPE_ARUBA),
    ("hpe", DeviceVendor.HPE_ARUBA),
    ("dell", DeviceVendor.DELL),
    ("huawei", DeviceVendor.HUAWEI),
    ("mikrotik", DeviceVendor.MIKROTIK),
    ("ubiquiti", DeviceVendor.UBIQUITI),
    ("extreme", DeviceVendor.EXTREME),
    ("nokia", DeviceVendor.NOKIA),
    ("alcatel", DeviceVendor.NOKIA),
    ("cumulus", DeviceVendor.CUMULUS),
    ("ruckus", DeviceVendor.RUCKUS),
    ("sonicwall", DeviceVendor.SONICWALL),
    ("sophos", DeviceVendor.SOPHOS),
    ("citrix", DeviceVendor.CITRIX),
    ("vmware", DeviceVendor.VMWARE),
    ("microsoft", DeviceVendor.WINDOWS),
    ("hyper-v", DeviceVendor.WINDOWS),
    ("qemu", DeviceVendor.LINUX),
    ("kvm", DeviceVendor.LINUX),
    ("proxmox", DeviceVendor.LINUX),
    ("docker", DeviceVendor.LINUX),
    ("raspberry", DeviceVendor.LINUX),
    ("linux", DeviceVendor.LINUX),
    ("aws", DeviceVendor.AWS),
    ("amazon", DeviceVendor.AWS),
    ("azure", DeviceVendor.AZURE),
    ("google", DeviceVendor.GCP),
    ("gcp", DeviceVendor.GCP),
    ("apc", DeviceVendor.APC),
    ("eaton", DeviceVendor.EATON),
)

_ACTIVE_ALLOCATION_STATUSES: frozenset[str] = frozenset({"active", "reserved", "dhcp", "allocated"})
_VALID_ALLOCATION_STATUSES: frozenset[str] = frozenset(
    {"active", "reserved", "dhcp", "deprecated", "conflict", "allocated"}
)
_VALID_ALLOCATION_TYPES: frozenset[str] = frozenset(
    {"static", "dhcp", "slaac", "vip", "loopback", "gateway"}
)
_VALID_VLAN_STATUSES: frozenset[str] = frozenset({"active", "reserved", "deprecated"})

# Allowed operational status transitions (decommissioned requires explicit reactivation or force)
ALLOWED_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    DeviceStatus.UNKNOWN.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.PROVISIONING.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.UP.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.DOWN.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.DEGRADED.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.WARNING.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.CRITICAL.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.MAINTENANCE.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.UNREACHABLE.value: frozenset(s.value for s in DeviceStatus),
    DeviceStatus.DECOMMISSIONED.value: frozenset(
        {
            DeviceStatus.DECOMMISSIONED.value,
            DeviceStatus.PROVISIONING.value,
            DeviceStatus.MAINTENANCE.value,
        }
    ),
}

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$"
)


# ---------------------------------------------------------------------------
# Structured Return Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceStatusTransition:
    """Result record returned after transitioning a device's operational status."""

    device_id: str
    hostname: str
    previous_status: str
    new_status: str
    changed: bool
    event_published: bool
    reason: str | None = None
    transitioned_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "changed": self.changed,
            "event_published": self.event_published,
            "reason": self.reason,
            "transitioned_at": self.transitioned_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Normalization Helpers
# ---------------------------------------------------------------------------


def normalize_device_status(raw: str | DeviceStatus | None) -> str:
    """Resolve status strings or schema aliases into a canonical :class:`DeviceStatus` value."""
    if raw is None:
        return DeviceStatus.UNKNOWN.value
    if isinstance(raw, DeviceStatus):
        return raw.value
    cleaned = str(raw).strip().lower()
    if not cleaned:
        return DeviceStatus.UNKNOWN.value
    if cleaned in _STATUS_ALIASES:
        return _STATUS_ALIASES[cleaned]
    try:
        return DeviceStatus(cleaned).value
    except ValueError as exc:
        valid = [s.value for s in DeviceStatus]
        raise ValidationError(
            f"Unsupported device status {raw!r}",
            details={"status": raw, "allowed": valid},
        ) from exc


def normalize_device_type(raw: str | DeviceType | None) -> str:
    """Resolve device type strings or aliases into a canonical :class:`DeviceType` value."""
    if raw is None:
        return DeviceType.UNKNOWN.value
    if isinstance(raw, DeviceType):
        return raw.value
    cleaned = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    if not cleaned:
        return DeviceType.UNKNOWN.value
    if cleaned in _DEVICE_TYPE_ALIASES:
        return _DEVICE_TYPE_ALIASES[cleaned]
    try:
        return DeviceType(cleaned).value
    except ValueError as exc:
        valid = [t.value for t in DeviceType]
        raise ValidationError(
            f"Unsupported device_type {raw!r}",
            details={"device_type": raw, "allowed": valid},
        ) from exc


def normalize_device_vendor(raw: str | DeviceVendor | None) -> str:
    """Resolve vendor names or aliases into a canonical :class:`DeviceVendor` value."""
    if raw is None:
        return DeviceVendor.UNKNOWN.value
    if isinstance(raw, DeviceVendor):
        return raw.value
    cleaned = str(raw).strip().lower()
    if not cleaned:
        return DeviceVendor.UNKNOWN.value
    underscored = cleaned.replace("-", "_").replace(" ", "_")
    try:
        return DeviceVendor(underscored).value
    except ValueError:
        pass
    for keyword, enum_member in _OUI_VENDOR_KEYWORDS:
        if keyword in cleaned:
            return enum_member.value
    return DeviceVendor.GENERIC.value


def normalize_interface_type(raw: str | InterfaceType | None) -> str:
    """Resolve interface type names or aliases into a canonical :class:`InterfaceType` value."""
    if raw is None:
        return InterfaceType.ETHERNET.value
    if isinstance(raw, InterfaceType):
        return raw.value
    cleaned = str(raw).strip().lower().replace(" ", "_")
    if not cleaned:
        return InterfaceType.ETHERNET.value
    if cleaned in _INTERFACE_TYPE_ALIASES:
        return _INTERFACE_TYPE_ALIASES[cleaned]
    try:
        return InterfaceType(cleaned).value
    except ValueError:
        return InterfaceType.OTHER.value


def infer_vendor_from_mac(mac_address: str | None) -> tuple[str, str | None]:
    """Infer a canonical :class:`DeviceVendor` value and raw IEEE OUI vendor name from a MAC.

    Returns ``(canonical_vendor, raw_oui_vendor_name)``.
    """
    if not mac_address or not is_valid_mac(mac_address):
        return DeviceVendor.UNKNOWN.value, None
    raw_oui = lookup_oui_vendor(mac_address)
    if not raw_oui or raw_oui in {"Broadcast", "Locally Administered"}:
        return DeviceVendor.UNKNOWN.value, raw_oui
    lowered = raw_oui.lower()
    for keyword, vendor_enum in _OUI_VENDOR_KEYWORDS:
        if keyword in lowered:
            return vendor_enum.value, raw_oui
    return DeviceVendor.GENERIC.value, raw_oui


def normalize_tags(raw: Iterable[str] | Mapping[str, Any] | str | None) -> list[str]:
    """Normalize tags from a list, key-value map, or delimited string into unique strings."""
    if raw is None:
        return []
    items: list[str] = []
    if isinstance(raw, str):
        for part in re.split(r"[,;|]", raw):
            cleaned = part.strip()
            if cleaned:
                items.append(cleaned)
    elif isinstance(raw, Mapping):
        for k, v in raw.items():
            key = str(k).strip()
            if not key:
                continue
            val = "" if v is None else str(v).strip()
            items.append(f"{key}:{val}" if val else key)
    else:
        for entry in raw:
            cleaned = str(entry).strip()
            if cleaned:
                items.append(cleaned)
    return list(dict.fromkeys(items))


def _coerce_mapping(data: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Accept either a plain mapping or a Pydantic v2 BaseModel instance."""
    if isinstance(data, Mapping):
        return dict(data)
    model_dump = getattr(data, "model_dump", None)
    if callable(model_dump):
        return dict(model_dump(exclude_unset=True))
    raise ValidationError(f"Expected mapping or schema object, got {type(data).__name__}")


def _validate_hostname(hostname: str) -> str:
    cleaned = hostname.strip()
    if not cleaned or len(cleaned) > 255 or not _HOSTNAME_RE.match(cleaned):
        raise ValidationError(
            f"Invalid hostname {hostname!r}",
            details={"hostname": hostname},
        )
    return cleaned


# ---------------------------------------------------------------------------
# InventoryService
# ---------------------------------------------------------------------------


class InventoryService:
    """Production CMDB, IPAM, and infrastructure inventory service.

    All mutations flush to the supplied SQLAlchemy ``Session`` without forcing an
    unconditional commit unless the caller commits (or uses a request-scoped
    unit-of-work), ensuring safe transactional composition across services and
    bulk import pipelines.
    """

    def __init__(
        self,
        db: Session,
        *,
        event_bus: EventBus | None = None,
    ) -> None:
        self.db = db
        self.event_bus = event_bus or get_event_bus()
        self.orgs = OrganizationRepository(db)
        self.sites = SiteRepository(db)
        self.racks = RackRepository(db)
        self.credentials = CredentialRepository(db)
        self.devices = DeviceRepository(db)
        self.interfaces = InterfaceRepository(db)
        self.subnets = SubnetRepository(db)
        self.vlans = VlanRepository(db)
        self.groups = DeviceGroupRepository(db)
        self.allocations: BaseRepository[IpAllocation] = BaseRepository(db, model=IpAllocation)
        self.audit_logs = AuditLogRepository(db)

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _publish_event(self, event: Event) -> bool:
        """Publish a domain event synchronously without failing the calling DB transaction."""
        try:
            self.event_bus.publish_sync(event)
            return True
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.warning("Failed to publish inventory event %s: %s", event.topic, exc)
            return False

    def _record_audit(
        self,
        *,
        org_id: str,
        action: AuditAction | str,
        resource_type: str,
        resource_id: str | None = None,
        summary: str | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        before_state: Mapping[str, Any] | None = None,
        after_state: Mapping[str, Any] | None = None,
    ) -> None:
        """Persist an audit log entry when an organization exists."""
        act_str = action.value if isinstance(action, AuditAction) else str(action)
        try:
            self.audit_logs.record(
                org_id=org_id,
                action=act_str,
                resource_type=resource_type,
                resource_id=resource_id,
                summary=summary,
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                before_state=before_state,
                after_state=after_state,
                flush=False,
            )
        except Exception as exc:  # pragma: no cover - audit should never abort inventory writes
            logger.debug("Skipping audit log for %s/%s: %s", resource_type, resource_id, exc)

    def _check_device_quota(self, org_id: str, *, additional: int = 1) -> dict[str, int]:
        """Enforce organization ``max_devices`` license quota prior to device creation."""
        org = self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError(
                f"Organization '{org_id}' was not found",
                details={"org_id": org_id},
            )
        if not org.is_active:
            raise ValidationError(
                f"Organization '{org.slug}' is inactive and cannot onboard new devices",
                details={"org_id": org_id},
            )
        current_count = self.devices.count(org_id=org_id)
        max_devices = int(org.max_devices or 1000)
        if current_count + additional > max_devices:
            raise ConflictError(
                f"Organization device quota exceeded ({current_count}/{max_devices})",
                error_code="DEVICE_QUOTA_EXCEEDED",
                details={
                    "org_id": org_id,
                    "current_devices": current_count,
                    "max_devices": max_devices,
                    "requested_additional": additional,
                },
            )
        return {
            "current": current_count,
            "max_devices": max_devices,
            "remaining": max(0, max_devices - current_count),
        }

    # -----------------------------------------------------------------------
    # Sites CRUD + Capacity & Health Rollup
    # -----------------------------------------------------------------------

    def create_site(
        self,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> Site:
        """Create a new physical site, data center, POP, or cloud region."""
        raw = _coerce_mapping(data)
        name = str(raw.get("name") or "").strip()
        if len(name) < 2:
            raise ValidationError("Site name must be at least 2 characters long")

        raw_code = raw.get("code") or raw.get("site_code") or raw.get("slug")
        if not raw_code:
            # Derive clean code from name
            derived = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()[:32]
            raw_code = derived or "SITE"
        code = str(raw_code).strip().upper()

        if self.sites.get_by_code(code, org_id=org_id) is not None:
            raise ConflictError(
                f"Site with code '{code}' already exists in this organization",
                details={"code": code, "org_id": org_id},
            )

        lat = raw.get("latitude")
        lon = raw.get("longitude")
        if (lat is None) != (lon is None):
            raise ValidationError("Both 'latitude' and 'longitude' must be provided together")
        if lat is not None and not (-90.0 <= float(lat) <= 90.0):
            raise ValidationError("Latitude must be between -90.0 and 90.0")
        if lon is not None and not (-180.0 <= float(lon) <= 180.0):
            raise ValidationError("Longitude must be between -180.0 and 180.0")

        tier_val = raw.get("tier") or "standard"
        if hasattr(tier_val, "value"):
            tier_val = tier_val.value

        metadata = dict(raw.get("metadata_json") or {})
        if raw.get("description") and "description" not in metadata:
            metadata["description"] = raw["description"]
        if raw.get("contact_phone") and "contact_phone" not in metadata:
            metadata["contact_phone"] = raw["contact_phone"]
        if raw.get("tags") and "tags" not in metadata:
            metadata["tags"] = dict(raw["tags"]) if isinstance(raw["tags"], Mapping) else normalize_tags(raw["tags"])

        payload: dict[str, Any] = {
            "name": name,
            "code": code,
            "region": raw.get("region"),
            "country": raw.get("country") or raw.get("country_code"),
            "city": raw.get("city"),
            "address": raw.get("address"),
            "timezone": raw.get("timezone") or raw.get("timezone_name") or "UTC",
            "latitude": float(lat) if lat is not None else None,
            "longitude": float(lon) if lon is not None else None,
            "contact_name": raw.get("contact_name"),
            "contact_email": raw.get("contact_email"),
            "tier": str(tier_val),
            "metadata_json": metadata,
        }

        site = self.sites.create(payload, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="site",
            resource_id=site.id,
            summary=f"Created site '{site.name}' ({site.code})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            after_state=site.to_summary_dict(),
        )
        return site

    def get_site(self, site_id: str, org_id: str) -> Site:
        """Fetch an active site by ID within an organization."""
        return self.sites.get_by_id_or_raise(site_id, org_id=org_id)

    def get_site_by_code(self, code: str, org_id: str) -> Site | None:
        """Lookup a site by its case-insensitive facility code."""
        return self.sites.get_by_code(code, org_id=org_id)

    def list_sites(
        self,
        org_id: str,
        *,
        query: str | None = None,
        region: str | None = None,
        tier: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Site]:
        """Search and paginate sites belonging to an organization."""
        return self.sites.search(
            query=query,
            region=region,
            tier=tier,
            org_id=org_id,
            page=page,
            page_size=page_size,
        )

    def update_site(
        self,
        site_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> Site:
        """Apply partial updates to a site with uniqueness and coordinate validation."""
        site = self.sites.get_by_id_or_raise(site_id, org_id=org_id)
        before = site.to_summary_dict()
        raw = _coerce_mapping(data)

        patch: dict[str, Any] = {}
        if "name" in raw and raw["name"] is not None:
            name = str(raw["name"]).strip()
            if len(name) < 2:
                raise ValidationError("Site name must be at least 2 characters long")
            patch["name"] = name

        new_code = raw.get("code") or raw.get("site_code")
        if new_code is not None:
            cleaned_code = str(new_code).strip().upper()
            existing = self.sites.get_by_code(cleaned_code, org_id=org_id)
            if existing is not None and existing.id != site.id:
                raise ConflictError(
                    f"Site code '{cleaned_code}' is already in use",
                    details={"code": cleaned_code},
                )
            patch["code"] = cleaned_code

        for field_name in ("region", "city", "address", "contact_name", "contact_email"):
            if field_name in raw:
                patch[field_name] = raw[field_name]
        if "country" in raw or "country_code" in raw:
            patch["country"] = raw.get("country", raw.get("country_code"))
        if "timezone" in raw or "timezone_name" in raw:
            tz = raw.get("timezone", raw.get("timezone_name"))
            if tz is not None:
                patch["timezone"] = str(tz)
        if "tier" in raw and raw["tier"] is not None:
            tier_val = raw["tier"]
            patch["tier"] = tier_val.value if hasattr(tier_val, "value") else str(tier_val)

        if "latitude" in raw or "longitude" in raw:
            lat = raw.get("latitude", site.latitude)
            lon = raw.get("longitude", site.longitude)
            if (lat is None) != (lon is None):
                raise ValidationError("Both 'latitude' and 'longitude' must be provided together")
            if lat is not None and not (-90.0 <= float(lat) <= 90.0):
                raise ValidationError("Latitude must be between -90.0 and 90.0")
            if lon is not None and not (-180.0 <= float(lon) <= 180.0):
                raise ValidationError("Longitude must be between -180.0 and 180.0")
            patch["latitude"] = float(lat) if lat is not None else None
            patch["longitude"] = float(lon) if lon is not None else None

        if "metadata_json" in raw and isinstance(raw["metadata_json"], Mapping):
            merged_meta = dict(site.metadata_json or {})
            merged_meta.update(raw["metadata_json"])
            patch["metadata_json"] = merged_meta

        updated = self.sites.update(site, patch, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.UPDATE,
            resource_type="site",
            resource_id=updated.id,
            summary=f"Updated site '{updated.name}' ({updated.code})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            before_state=before,
            after_state=updated.to_summary_dict(),
        )
        return updated

    def delete_site(
        self,
        site_id: str,
        org_id: str,
        *,
        force: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> Site:
        """Soft-delete a site, blocking if active devices or racks remain unless ``force=True``."""
        site = self.sites.get_by_id_or_raise(site_id, org_id=org_id)
        attached_devices = self.devices.count(filters={"site_id": site_id}, org_id=org_id)
        attached_racks = self.racks.count(filters={"site_id": site_id}, org_id=org_id)

        if (attached_devices > 0 or attached_racks > 0) and not force:
            raise ConflictError(
                f"Cannot delete site '{site.code}' with {attached_devices} devices and {attached_racks} racks",
                details={
                    "site_id": site_id,
                    "attached_devices": attached_devices,
                    "attached_racks": attached_racks,
                },
            )

        if force:
            for dev in self.devices.list_by_site(site_id, org_id=org_id):
                self.devices.update(dev, {"site_id": None, "rack_id": None}, org_id=org_id)
            for rack in self.racks.list_by_site(site_id, org_id=org_id):
                self.racks.soft_delete(rack, org_id=org_id)

        deleted = self.sites.soft_delete(site, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.DELETE,
            resource_type="site",
            resource_id=site.id,
            summary=f"Soft-deleted site '{site.name}' ({site.code})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
        )
        return deleted

    def get_site_health_rollup(self, site_id: str, org_id: str) -> dict[str, Any]:
        """Compute device health breakdown, rack capacity utilization, and IPAM metrics for a site."""
        site = self.sites.get_by_id_or_raise(site_id, org_id=org_id)
        site_devices = self.devices.list_by_site(site_id, org_id=org_id)
        status_counts: Counter[str] = Counter()
        type_counts: Counter[str] = Counter()
        vendor_counts: Counter[str] = Counter()

        for dev in site_devices:
            status_counts[dev.status] += 1
            type_counts[dev.device_type] += 1
            vendor_counts[dev.vendor] += 1

        total_devices = len(site_devices)
        up_count = status_counts.get(DeviceStatus.UP.value, 0)
        problem_count = sum(
            status_counts.get(st, 0)
            for st in (
                DeviceStatus.DOWN.value,
                DeviceStatus.DEGRADED.value,
                DeviceStatus.WARNING.value,
                DeviceStatus.CRITICAL.value,
                DeviceStatus.UNREACHABLE.value,
            )
        )
        maintenance_count = status_counts.get(DeviceStatus.MAINTENANCE.value, 0)
        evaluable = max(0, total_devices - maintenance_count)
        health_score_pct = round((up_count / evaluable) * 100.0, 2) if evaluable > 0 else 100.0

        # Rack capacity rollup
        rack_summaries = self.get_rack_utilization_summary(org_id, site_id=site_id)
        total_u = sum(r["total_u"] for r in rack_summaries)
        used_u = sum(r["used_u"] for r in rack_summaries)
        rack_util_pct = round((used_u / total_u) * 100.0, 2) if total_u > 0 else 0.0
        total_power_watts = sum(r["power_capacity_watts"] or 0 for r in rack_summaries)

        # Subnet & VLAN counts
        site_subnets = self.subnets.list_by_site(site_id, org_id=org_id)
        avg_subnet_util = (
            round(sum(s.utilization_pct for s in site_subnets) / len(site_subnets), 2)
            if site_subnets
            else 0.0
        )
        vlan_count = self.vlans.count(filters={"site_id": site_id}, org_id=org_id)

        if total_devices == 0:
            health_status = "unknown"
        elif status_counts.get(DeviceStatus.DOWN.value, 0) > 0 or status_counts.get(DeviceStatus.CRITICAL.value, 0) > 0:
            health_status = "critical"
        elif problem_count > 0:
            health_status = "degraded"
        else:
            health_status = "healthy"

        return {
            "site": site.to_summary_dict(),
            "health_status": health_status,
            "health_score_pct": health_score_pct,
            "devices": {
                "total": total_devices,
                "up": up_count,
                "problem": problem_count,
                "maintenance": maintenance_count,
                "by_status": dict(status_counts),
                "by_type": dict(type_counts),
                "by_vendor": dict(vendor_counts),
            },
            "racks": {
                "count": len(rack_summaries),
                "total_u": total_u,
                "used_u": used_u,
                "available_u": max(0, total_u - used_u),
                "utilization_pct": rack_util_pct,
                "total_power_capacity_watts": total_power_watts,
                "details": rack_summaries,
            },
            "ipam": {
                "subnet_count": len(site_subnets),
                "avg_subnet_utilization_pct": avg_subnet_util,
                "vlan_count": vlan_count,
            },
        }

    def list_sites_with_health(self, org_id: str) -> list[dict[str, Any]]:
        """Return capacity and health rollups for all active sites in an organization."""
        all_sites = self.sites.list(org_id=org_id)
        return [self.get_site_health_rollup(site.id, org_id) for site in all_sites]

    # -----------------------------------------------------------------------
    # Racks CRUD + U-Position Overlap / Collision Validation
    # -----------------------------------------------------------------------

    def create_rack(
        self,
        org_id: str,
        site_id: str,
        data: Mapping[str, Any] | Any,
        *,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> Rack:
        """Create a physical rack inside a verified tenant site."""
        self.sites.get_by_id_or_raise(site_id, org_id=org_id)
        raw = _coerce_mapping(data)

        name = str(raw.get("name") or "").strip()
        if not name:
            raise ValidationError("Rack name must not be empty")

        if self.racks.get_by_name_in_site(site_id, name, org_id=org_id) is not None:
            raise ConflictError(
                f"Rack '{name}' already exists in site '{site_id}'",
                details={"site_id": site_id, "name": name},
            )

        total_u = int(raw.get("total_u") or raw.get("u_height") or 42)
        if not (1 <= total_u <= 100):
            raise ValidationError("Rack total_u must be between 1 and 100", details={"total_u": total_u})

        power_watts = raw.get("power_capacity_watts")
        if power_watts is not None and int(power_watts) < 0:
            raise ValidationError("Rack power_capacity_watts must be non-negative")

        payload: dict[str, Any] = {
            "site_id": site_id,
            "name": name,
            "aisle": raw.get("aisle") or raw.get("facility_id"),
            "row": raw.get("row") or raw.get("row_label"),
            "total_u": total_u,
            "power_capacity_watts": int(power_watts) if power_watts is not None else None,
            "cooling_zone": raw.get("cooling_zone"),
            "notes": raw.get("notes") or raw.get("description"),
        }
        rack = self.racks.create(payload, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="rack",
            resource_id=rack.id,
            summary=f"Created rack '{rack.name}' ({rack.total_u}U) in site {site_id}",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
        )
        return rack

    def get_rack(self, rack_id: str, org_id: str) -> Rack:
        """Fetch an active rack by ID within an organization."""
        return self.racks.get_by_id_or_raise(rack_id, org_id=org_id)

    def list_racks(self, org_id: str, *, site_id: str | None = None) -> list[Rack]:
        """List active racks in an organization, optionally filtered by site."""
        if site_id is not None:
            return self.racks.list_by_site(site_id, org_id=org_id)
        return self.racks.list(org_id=org_id)

    def update_rack(
        self,
        rack_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> Rack:
        """Update rack metadata while preventing U-height reduction below mounted devices."""
        rack = self.racks.get_by_id_or_raise(rack_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        if "name" in raw and raw["name"] is not None:
            new_name = str(raw["name"]).strip()
            if not new_name:
                raise ValidationError("Rack name must not be empty")
            existing = self.racks.get_by_name_in_site(rack.site_id, new_name, org_id=org_id)
            if existing is not None and existing.id != rack.id:
                raise ConflictError(
                    f"Rack '{new_name}' already exists in site '{rack.site_id}'",
                    details={"site_id": rack.site_id, "name": new_name},
                )
            patch["name"] = new_name

        new_total_u = raw.get("total_u", raw.get("u_height"))
        if new_total_u is not None:
            new_total_u_int = int(new_total_u)
            if not (1 <= new_total_u_int <= 100):
                raise ValidationError("Rack total_u must be between 1 and 100")
            mounted = self.devices.list(filters={"rack_id": rack.id}, org_id=org_id)
            highest_used_u = 0
            for dev in mounted:
                if dev.rack_unit_start is not None:
                    top_u = dev.rack_unit_start + (dev.rack_unit_height or 1) - 1
                    highest_used_u = max(highest_used_u, top_u)
            if new_total_u_int < highest_used_u:
                raise ConflictError(
                    f"Cannot shrink rack '{rack.name}' to {new_total_u_int}U; "
                    f"mounted equipment occupies up to U{highest_used_u}",
                    details={
                        "rack_id": rack.id,
                        "requested_total_u": new_total_u_int,
                        "highest_occupied_u": highest_used_u,
                    },
                )
            patch["total_u"] = new_total_u_int

        if "aisle" in raw or "facility_id" in raw:
            patch["aisle"] = raw.get("aisle", raw.get("facility_id"))
        if "row" in raw or "row_label" in raw:
            patch["row"] = raw.get("row", raw.get("row_label"))
        if "power_capacity_watts" in raw:
            pw = raw["power_capacity_watts"]
            if pw is not None and int(pw) < 0:
                raise ValidationError("power_capacity_watts must be non-negative")
            patch["power_capacity_watts"] = int(pw) if pw is not None else None
        if "cooling_zone" in raw:
            patch["cooling_zone"] = raw["cooling_zone"]
        if "notes" in raw or "description" in raw:
            patch["notes"] = raw.get("notes", raw.get("description"))

        return self.racks.update(rack, patch, org_id=org_id)

    def delete_rack(
        self,
        rack_id: str,
        org_id: str,
        *,
        detach_devices: bool = False,
    ) -> Rack:
        """Soft-delete a rack, rejecting if devices are still mounted unless ``detach_devices=True``."""
        rack = self.racks.get_by_id_or_raise(rack_id, org_id=org_id)
        mounted = self.devices.list(filters={"rack_id": rack_id}, org_id=org_id)
        if mounted and not detach_devices:
            raise ConflictError(
                f"Cannot delete rack '{rack.name}' while {len(mounted)} device(s) are mounted",
                details={"rack_id": rack_id, "mounted_device_count": len(mounted)},
            )
        if detach_devices:
            for dev in mounted:
                self.devices.update(
                    dev,
                    {"rack_id": None, "rack_unit_start": None},
                    org_id=org_id,
                )
        return self.racks.soft_delete(rack, org_id=org_id)

    def validate_rack_placement(
        self,
        rack_id: str,
        org_id: str,
        unit_start: int,
        unit_height: int = 1,
        *,
        exclude_device_id: str | None = None,
    ) -> None:
        """Validate that a device spanning ``[unit_start, unit_start + unit_height - 1]`` fits without collision.

        Raises:
            ValidationError: If ``unit_start`` or ``unit_height`` is out of rack bounds.
            ConflictError: If any requested rack unit is already occupied by another device.
        """
        rack = self.racks.get_by_id_or_raise(rack_id, org_id=org_id)
        total_u = int(rack.total_u or 42)
        if unit_start < 1 or unit_height < 1:
            raise ValidationError(
                "Rack unit_start and unit_height must be positive integers",
                details={"rack_id": rack_id, "unit_start": unit_start, "unit_height": unit_height},
            )
        unit_end = unit_start + unit_height - 1
        if unit_end > total_u:
            raise ValidationError(
                f"Device placement U{unit_start}..U{unit_end} exceeds rack '{rack.name}' height ({total_u}U)",
                details={
                    "rack_id": rack_id,
                    "rack_name": rack.name,
                    "total_u": total_u,
                    "unit_start": unit_start,
                    "unit_end": unit_end,
                },
            )

        requested_slots = set(range(unit_start, unit_end + 1))
        mounted_devices = self.devices.list(filters={"rack_id": rack_id}, org_id=org_id)
        collisions: list[dict[str, Any]] = []
        for dev in mounted_devices:
            if dev.id == exclude_device_id or dev.rack_unit_start is None:
                continue
            dev_height = int(dev.rack_unit_height or 1)
            dev_slots = set(range(dev.rack_unit_start, dev.rack_unit_start + dev_height))
            overlap = sorted(requested_slots & dev_slots)
            if overlap:
                collisions.append(
                    {
                        "device_id": dev.id,
                        "hostname": dev.hostname,
                        "occupied_units": sorted(dev_slots),
                        "overlapping_units": overlap,
                    }
                )

        if collisions:
            conflict_names = ", ".join(c["hostname"] for c in collisions)
            raise ConflictError(
                f"Rack U-position collision in '{rack.name}' at U{unit_start}..U{unit_end} "
                f"with: {conflict_names}",
                error_code="RACK_UNIT_COLLISION",
                details={
                    "rack_id": rack_id,
                    "rack_name": rack.name,
                    "requested_start": unit_start,
                    "requested_end": unit_end,
                    "collisions": collisions,
                },
            )

    def get_rack_elevation(self, rack_id: str, org_id: str) -> dict[str, Any]:
        """Build a complete U-by-U elevation map and free-space inventory for a rack."""
        rack = self.racks.get_by_id_or_raise(rack_id, org_id=org_id)
        total_u = int(rack.total_u or 42)
        mounted = self.devices.list(filters={"rack_id": rack_id}, org_id=org_id)

        slots: dict[int, dict[str, Any] | None] = {u: None for u in range(1, total_u + 1)}
        unpositioned: list[dict[str, Any]] = []
        mounted_summaries: list[dict[str, Any]] = []

        for dev in mounted:
            height = int(dev.rack_unit_height or 1)
            if dev.rack_unit_start is None:
                unpositioned.append(dev.to_summary_dict())
                continue
            end_u = dev.rack_unit_start + height - 1
            entry = {
                "device_id": dev.id,
                "hostname": dev.hostname,
                "device_type": dev.device_type,
                "vendor": dev.vendor,
                "model": dev.model,
                "status": dev.status,
                "unit_start": dev.rack_unit_start,
                "unit_height": height,
                "unit_end": end_u,
            }
            mounted_summaries.append(entry)
            for u in range(dev.rack_unit_start, min(end_u, total_u) + 1):
                slots[u] = entry

        used_u = sum(1 for v in slots.values() if v is not None)

        # Compute contiguous free spans
        free_spans: list[dict[str, int]] = []
        span_start: int | None = None
        for u in range(1, total_u + 1):
            if slots[u] is None:
                if span_start is None:
                    span_start = u
            elif span_start is not None:
                free_spans.append({"start_u": span_start, "end_u": u - 1, "height_u": u - span_start})
                span_start = None
        if span_start is not None:
            free_spans.append({"start_u": span_start, "end_u": total_u, "height_u": total_u - span_start + 1})

        return {
            "rack_id": rack.id,
            "site_id": rack.site_id,
            "name": rack.name,
            "aisle": rack.aisle,
            "row": rack.row,
            "total_u": total_u,
            "used_u": used_u,
            "available_u": total_u - used_u,
            "utilization_pct": round((used_u / total_u) * 100.0, 2) if total_u > 0 else 0.0,
            "power_capacity_watts": rack.power_capacity_watts,
            "cooling_zone": rack.cooling_zone,
            "mounted_devices": sorted(mounted_summaries, key=lambda d: d["unit_start"]),
            "unpositioned_devices": unpositioned,
            "free_spans": free_spans,
            "slots": slots,
        }

    def find_next_available_rack_slot(
        self,
        rack_id: str,
        org_id: str,
        unit_height: int = 1,
        *,
        from_bottom: bool = True,
    ) -> int | None:
        """Return the first contiguous starting U slot that accommodates ``unit_height``, or ``None``."""
        if unit_height < 1:
            raise ValidationError("unit_height must be >= 1")
        elevation = self.get_rack_elevation(rack_id, org_id)
        spans = elevation["free_spans"]
        ordered = spans if from_bottom else list(reversed(spans))
        for span in ordered:
            if span["height_u"] >= unit_height:
                return span["start_u"] if from_bottom else span["end_u"] - unit_height + 1
        return None

    def get_rack_utilization_summary(
        self,
        org_id: str,
        *,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compute accurate per-rack U utilization and device counts."""
        racks = self.list_racks(org_id, site_id=site_id)
        results: list[dict[str, Any]] = []
        for rack in racks:
            total_u = int(rack.total_u or 42)
            mounted = self.devices.list(filters={"rack_id": rack.id}, org_id=org_id)
            occupied: set[int] = set()
            for dev in mounted:
                if dev.rack_unit_start is not None:
                    h = int(dev.rack_unit_height or 1)
                    for u in range(dev.rack_unit_start, min(dev.rack_unit_start + h, total_u + 1)):
                        occupied.add(u)
            used_u = len(occupied)
            results.append(
                {
                    "rack_id": rack.id,
                    "site_id": rack.site_id,
                    "name": rack.name,
                    "aisle": rack.aisle,
                    "row": rack.row,
                    "total_u": total_u,
                    "used_u": used_u,
                    "available_u": max(0, total_u - used_u),
                    "utilization_pct": round((used_u / total_u) * 100.0, 2) if total_u > 0 else 0.0,
                    "power_capacity_watts": rack.power_capacity_watts,
                    "device_count": len(mounted),
                }
            )
        return results

    # -----------------------------------------------------------------------
    # Devices CRUD, Quota, Normalization, OUI Inference, Status & Analytics
    # -----------------------------------------------------------------------

    def create_device(
        self,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        check_quota: bool = True,
        emit_event: bool = True,
    ) -> Device:
        """Onboard a managed device with quota check, IP/MAC normalization, OUI inference, and rack validation."""
        if check_quota:
            self._check_device_quota(org_id, additional=1)

        raw = _coerce_mapping(data)
        hostname_raw = raw.get("hostname") or raw.get("name")
        if not hostname_raw:
            raise ValidationError("Device 'hostname' is required")
        hostname = _validate_hostname(str(hostname_raw))

        if self.devices.get_by_hostname(hostname, org_id=org_id) is not None:
            raise ConflictError(
                f"Device with hostname '{hostname}' already exists in this organization",
                details={"hostname": hostname, "org_id": org_id},
            )

        mgmt_ip_raw = raw.get("management_ip") or raw.get("ip_address")
        if not mgmt_ip_raw:
            raise ValidationError("Device 'management_ip' is required")
        management_ip = normalize_ip(str(mgmt_ip_raw))

        # Secondary IPs normalization
        raw_sec_ips = raw.get("secondary_ips_json") or raw.get("secondary_ips") or []
        secondary_ips: list[str] = []
        for sec in raw_sec_ips:
            if sec and str(sec).strip():
                norm_sec = normalize_ip(str(sec))
                if norm_sec != management_ip and norm_sec not in secondary_ips:
                    secondary_ips.append(norm_sec)

        # MAC normalization & OUI auto-vendor inference
        mac_raw = raw.get("mac_address")
        mac_address: str | None = None
        oui_raw_vendor: str | None = None
        if mac_raw is not None and str(mac_raw).strip():
            mac_address = format_mac(str(mac_raw), style="colon", uppercase=False)

        raw_vendor = raw.get("vendor")
        if raw_vendor and str(raw_vendor).strip().lower() not in {"", "unknown"}:
            vendor = normalize_device_vendor(raw_vendor)
        elif mac_address is not None:
            vendor, oui_raw_vendor = infer_vendor_from_mac(mac_address)
        else:
            vendor = DeviceVendor.UNKNOWN.value

        device_type = normalize_device_type(raw.get("device_type"))
        status = normalize_device_status(raw.get("status", DeviceStatus.UNKNOWN.value))

        # Validate foreign references within tenant scope
        site_id = raw.get("site_id")
        if site_id is not None:
            self.sites.get_by_id_or_raise(str(site_id), org_id=org_id)

        rack_id = raw.get("rack_id")
        rack_unit_start = raw.get("rack_unit_start", raw.get("rack_u_position"))
        rack_unit_height = raw.get("rack_unit_height", raw.get("rack_u_height", 1))
        if rack_unit_height is not None:
            rack_unit_height = int(rack_unit_height)
            if rack_unit_height < 1:
                raise ValidationError("rack_unit_height must be >= 1")

        if rack_id is not None:
            rack = self.racks.get_by_id_or_raise(str(rack_id), org_id=org_id)
            if site_id is None:
                site_id = rack.site_id
            elif str(site_id) != rack.site_id:
                raise ValidationError(
                    f"Rack '{rack.name}' belongs to site '{rack.site_id}', not '{site_id}'",
                    details={"rack_id": rack_id, "rack_site_id": rack.site_id, "site_id": site_id},
                )
            if rack_unit_start is not None:
                self.validate_rack_placement(
                    rack.id,
                    org_id,
                    int(rack_unit_start),
                    rack_unit_height or 1,
                )

        cred_id = raw.get("credential_profile_id")
        if cred_id is not None:
            self.credentials.get_by_id_or_raise(str(cred_id), org_id=org_id)

        polling_interval = int(
            raw.get("polling_interval_seconds") or raw.get("poll_interval_seconds") or 60
        )
        if polling_interval < 5:
            raise ValidationError("polling_interval_seconds must be >= 5")

        tags = normalize_tags(raw.get("tags_json") if "tags_json" in raw else raw.get("tags"))
        custom_fields = dict(raw.get("custom_fields_json") or raw.get("custom_fields") or {})
        if oui_raw_vendor and "oui_vendor" not in custom_fields:
            custom_fields["oui_vendor"] = oui_raw_vendor
        if raw.get("notes") and "notes" not in custom_fields:
            custom_fields["notes"] = raw["notes"]
        if raw.get("device_role") and "device_role" not in custom_fields:
            role_v = raw["device_role"]
            custom_fields["device_role"] = role_v.value if hasattr(role_v, "value") else str(role_v)

        payload: dict[str, Any] = {
            "site_id": site_id,
            "rack_id": rack_id,
            "credential_profile_id": cred_id,
            "hostname": hostname,
            "fqdn": raw.get("fqdn"),
            "management_ip": management_ip,
            "secondary_ips_json": secondary_ips,
            "mac_address": mac_address,
            "device_type": device_type,
            "vendor": vendor,
            "model": raw.get("model"),
            "os_version": raw.get("os_version"),
            "serial_number": raw.get("serial_number"),
            "asset_tag": raw.get("asset_tag"),
            "rack_unit_start": int(rack_unit_start) if rack_unit_start is not None else None,
            "rack_unit_height": rack_unit_height,
            "status": status,
            "polling_enabled": bool(raw.get("polling_enabled", True)),
            "snmp_enabled": bool(raw.get("snmp_enabled", True)),
            "icmp_enabled": bool(raw.get("icmp_enabled", True)),
            "polling_interval_seconds": polling_interval,
            "tags_json": tags,
            "custom_fields_json": custom_fields,
            "sys_descr": raw.get("sys_descr") or raw.get("sys_description"),
            "sys_object_id": raw.get("sys_object_id"),
            "sys_location": raw.get("sys_location"),
            "sys_contact": raw.get("sys_contact"),
            "uptime_seconds": raw.get("uptime_seconds"),
            "last_seen_at": raw.get("last_seen_at"),
            "last_polled_at": raw.get("last_polled_at"),
        }

        device = self.devices.create(payload, org_id=org_id)

        # Optional static group assignment
        group_ids = raw.get("group_ids") or []
        for gid in group_ids:
            grp = self.groups.get_by_id_or_raise(str(gid), org_id=org_id)
            if not grp.is_dynamic:
                self.groups.add_member(grp.id, device.id, org_id=org_id)

        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="device",
            resource_id=device.id,
            summary=f"Created device '{device.hostname}' ({device.management_ip})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            after_state=device.to_summary_dict(),
        )

        if emit_event:
            self._publish_event(
                device_discovered_event(
                    device_id=device.id,
                    hostname=device.hostname,
                    ip_address=device.management_ip,
                    vendor=device.vendor,
                    device_type=device.device_type,
                    org_id=org_id,
                    discovery_method="cmdb",
                )
            )
        return device

    def get_device(self, device_id: str, org_id: str) -> Device:
        """Fetch an active device by ID within an organization."""
        return self.devices.get_by_id_or_raise(device_id, org_id=org_id)

    def get_device_by_hostname(self, hostname: str, org_id: str) -> Device | None:
        """Lookup an active device by case-insensitive hostname."""
        return self.devices.get_by_hostname(hostname, org_id=org_id)

    def get_device_by_ip(self, ip_address: str, org_id: str) -> Device | None:
        """Lookup an active device by its normalized management IP address."""
        normalized = normalize_ip(ip_address)
        return self.devices.get_by_ip(normalized, org_id=org_id)

    def get_device_detail(self, device_id: str, org_id: str) -> dict[str, Any]:
        """Return an expanded CMDB view embedding site, rack, redacted credentials, interfaces, and groups."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        site_info = None
        if device.site_id:
            site = self.sites.get_by_id(device.site_id, org_id=org_id)
            site_info = site.to_summary_dict() if site else None

        rack_info = None
        if device.rack_id:
            rack = self.racks.get_by_id(device.rack_id, org_id=org_id)
            if rack:
                rack_info = {
                    "id": rack.id,
                    "name": rack.name,
                    "site_id": rack.site_id,
                    "total_u": rack.total_u,
                    "aisle": rack.aisle,
                    "row": rack.row,
                }

        cred_info = None
        if device.credential_profile_id:
            cred = self.credentials.get_by_id(device.credential_profile_id, org_id=org_id)
            cred_info = cred.to_redacted_dict() if cred else None

        ifaces = self.interfaces.list_by_device(device.id, org_id=org_id)
        static_groups = self.groups.list_groups_for_device(device.id, org_id=org_id)
        # Include dynamic groups matching this device
        dynamic_groups = [
            g for g in self.groups.list(filters={"group_type": "dynamic"}, org_id=org_id)
            if self._device_matches_filter(device, g.dynamic_filter_json)
        ]
        all_group_ids = list(dict.fromkeys([g.id for g in static_groups] + [g.id for g in dynamic_groups]))
        ip_allocs = self.allocations.list(filters={"device_id": device.id}, org_id=org_id)

        return {
            "id": device.id,
            "org_id": device.org_id,
            "hostname": device.hostname,
            "fqdn": device.fqdn,
            "management_ip": device.management_ip,
            "secondary_ips": list(device.secondary_ips_json or []),
            "mac_address": device.mac_address,
            "device_type": device.device_type,
            "vendor": device.vendor,
            "model": device.model,
            "os_version": device.os_version,
            "serial_number": device.serial_number,
            "asset_tag": device.asset_tag,
            "rack_unit_start": device.rack_unit_start,
            "rack_unit_height": device.rack_unit_height,
            "status": device.status,
            "polling_enabled": device.polling_enabled,
            "snmp_enabled": device.snmp_enabled,
            "icmp_enabled": device.icmp_enabled,
            "polling_interval_seconds": device.polling_interval_seconds,
            "tags": list(device.tags_json or []),
            "custom_fields": dict(device.custom_fields_json or {}),
            "sys_descr": device.sys_descr,
            "sys_object_id": device.sys_object_id,
            "sys_location": device.sys_location,
            "sys_contact": device.sys_contact,
            "uptime_seconds": device.uptime_seconds,
            "uptime_human": device.uptime_human,
            "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
            "last_polled_at": device.last_polled_at.isoformat() if device.last_polled_at else None,
            "site": site_info,
            "rack": rack_info,
            "credential_profile": cred_info,
            "interface_count": len(ifaces),
            "interfaces": [
                {
                    "id": iface.id,
                    "if_index": iface.if_index,
                    "name": iface.name,
                    "alias": iface.alias,
                    "interface_type": iface.interface_type,
                    "ip_address": iface.ip_address,
                    "mac_address": iface.mac_address,
                    "speed_mbps": iface.speed_mbps,
                    "admin_status": iface.admin_status,
                    "oper_status": iface.oper_status,
                    "is_uplink": iface.is_uplink,
                    "utilization_in_pct": iface.utilization_in_pct,
                    "utilization_out_pct": iface.utilization_out_pct,
                }
                for iface in ifaces
            ],
            "group_ids": all_group_ids,
            "ip_allocations": [
                {
                    "id": a.id,
                    "subnet_id": a.subnet_id,
                    "ip_address": a.ip_address,
                    "allocation_type": a.allocation_type,
                    "status": a.status,
                }
                for a in ip_allocs
            ],
        }

    def search_devices(
        self,
        org_id: str,
        *,
        query: str | None = None,
        status: str | Sequence[str] | None = None,
        device_type: str | Sequence[str] | None = None,
        vendor: str | None = None,
        site_id: str | None = None,
        rack_id: str | None = None,
        tag: str | None = None,
        group_id: str | None = None,
        snmp_enabled: bool | None = None,
        icmp_enabled: bool | None = None,
        polling_enabled: bool | None = None,
        order_by: Sequence[str | SortSpec] | str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Device]:
        """Search, filter, sort, and paginate managed devices within an organization."""
        norm_status: str | list[str] | None = None
        if isinstance(status, str):
            norm_status = normalize_device_status(status)
        elif status is not None:
            norm_status = [normalize_device_status(s) for s in status]

        norm_type: str | list[str] | None = None
        if isinstance(device_type, str):
            norm_type = normalize_device_type(device_type)
        elif device_type is not None:
            norm_type = [normalize_device_type(t) for t in device_type]

        # If group_id refers to a dynamic group, resolve matching IDs dynamically
        if group_id is not None:
            grp = self.groups.get_by_id(group_id, org_id=org_id)
            if grp is not None and grp.is_dynamic:
                matched_devices = self.evaluate_dynamic_group(grp.id, org_id)
                filtered = self._filter_device_list_in_memory(
                    matched_devices,
                    query=query,
                    status=norm_status,
                    device_type=norm_type,
                    vendor=vendor,
                    site_id=site_id,
                    rack_id=rack_id,
                    tag=tag,
                    snmp_enabled=snmp_enabled,
                    icmp_enabled=icmp_enabled,
                    polling_enabled=polling_enabled,
                )
                total = len(filtered)
                total_pages = (total + page_size - 1) // page_size if total > 0 else 0
                start = (page - 1) * page_size
                page_items = filtered[start : start + page_size]
                return PageResult(
                    items=page_items,
                    total=total,
                    page=page,
                    page_size=page_size,
                    total_pages=total_pages,
                    has_next=page < total_pages,
                    has_prev=page > 1 and total_pages > 0,
                )

        result = self.devices.search(
            query=query,
            status=norm_status,
            device_type=norm_type,
            vendor=vendor,
            site_id=site_id,
            rack_id=rack_id,
            tag=tag,
            snmp_enabled=snmp_enabled,
            icmp_enabled=icmp_enabled,
            group_id=group_id,
            order_by=order_by,
            page=page,
            page_size=page_size,
            org_id=org_id,
        )

        if polling_enabled is not None:
            filtered_items = [d for d in result.items if d.polling_enabled is polling_enabled]
            # Re-query accurately if polling_enabled filter was requested
            all_matching = self.devices.search(
                query=query,
                status=norm_status,
                device_type=norm_type,
                vendor=vendor,
                site_id=site_id,
                rack_id=rack_id,
                tag=tag,
                snmp_enabled=snmp_enabled,
                icmp_enabled=icmp_enabled,
                group_id=group_id,
                order_by=order_by,
                page=1,
                page_size=max(result.total, 1),
                org_id=org_id,
            ).items
            filtered_all = [d for d in all_matching if d.polling_enabled is polling_enabled]
            total = len(filtered_all)
            total_pages = (total + page_size - 1) // page_size if total > 0 else 0
            start = (page - 1) * page_size
            filtered_items = filtered_all[start : start + page_size]
            return PageResult(
                items=filtered_items,
                total=total,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                has_next=page < total_pages,
                has_prev=page > 1 and total_pages > 0,
            )

        return result

    def _filter_device_list_in_memory(
        self,
        devices: Sequence[Device],
        *,
        query: str | None = None,
        status: str | Sequence[str] | None = None,
        device_type: str | Sequence[str] | None = None,
        vendor: str | None = None,
        site_id: str | None = None,
        rack_id: str | None = None,
        tag: str | None = None,
        snmp_enabled: bool | None = None,
        icmp_enabled: bool | None = None,
        polling_enabled: bool | None = None,
    ) -> list[Device]:
        out: list[Device] = []
        q_lower = query.strip().lower() if query else None
        status_set = {status} if isinstance(status, str) else (set(status) if status else None)
        type_set = {device_type} if isinstance(device_type, str) else (set(device_type) if device_type else None)
        vendor_lower = vendor.strip().lower() if vendor else None
        tag_lower = tag.strip().lower() if tag else None

        for dev in devices:
            if status_set and dev.status not in status_set:
                continue
            if type_set and dev.device_type not in type_set:
                continue
            if vendor_lower and vendor_lower not in (dev.vendor or "").lower():
                continue
            if site_id is not None and dev.site_id != site_id:
                continue
            if rack_id is not None and dev.rack_id != rack_id:
                continue
            if snmp_enabled is not None and dev.snmp_enabled is not snmp_enabled:
                continue
            if icmp_enabled is not None and dev.icmp_enabled is not icmp_enabled:
                continue
            if polling_enabled is not None and dev.polling_enabled is not polling_enabled:
                continue
            if tag_lower and not any(tag_lower in t.lower() for t in (dev.tags_json or [])):
                continue
            if q_lower:
                haystack = " ".join(
                    str(v)
                    for v in (
                        dev.hostname,
                        dev.fqdn,
                        dev.management_ip,
                        dev.vendor,
                        dev.model,
                        dev.serial_number,
                        dev.os_version,
                        " ".join(dev.tags_json or []),
                    )
                    if v
                ).lower()
                if q_lower not in haystack:
                    continue
            out.append(dev)
        out.sort(key=lambda d: d.hostname.lower())
        return out

    def update_device(
        self,
        device_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        emit_event: bool = True,
    ) -> Device:
        """Apply partial updates to a device, re-validating IP/MAC, rack placement, and status."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        before = device.to_summary_dict()
        raw = _coerce_mapping(data)

        patch: dict[str, Any] = {}
        requested_status: str | None = None

        if "hostname" in raw and raw["hostname"] is not None:
            new_hostname = _validate_hostname(str(raw["hostname"]))
            existing = self.devices.get_by_hostname(new_hostname, org_id=org_id)
            if existing is not None and existing.id != device.id:
                raise ConflictError(
                    f"Hostname '{new_hostname}' is already assigned to another device",
                    details={"hostname": new_hostname},
                )
            patch["hostname"] = new_hostname

        if "management_ip" in raw and raw["management_ip"] is not None:
            patch["management_ip"] = normalize_ip(str(raw["management_ip"]))

        if "secondary_ips_json" in raw or "secondary_ips" in raw:
            raw_sec = raw.get("secondary_ips_json", raw.get("secondary_ips")) or []
            mgmt = patch.get("management_ip", device.management_ip)
            cleaned_sec: list[str] = []
            for sec in raw_sec:
                if sec and str(sec).strip():
                    norm_sec = normalize_ip(str(sec))
                    if norm_sec != mgmt and norm_sec not in cleaned_sec:
                        cleaned_sec.append(norm_sec)
            patch["secondary_ips_json"] = cleaned_sec

        if "mac_address" in raw:
            mac_raw = raw["mac_address"]
            if mac_raw is None or not str(mac_raw).strip():
                patch["mac_address"] = None
            else:
                norm_mac = format_mac(str(mac_raw), style="colon", uppercase=False)
                patch["mac_address"] = norm_mac
                if "vendor" not in raw and device.vendor in {DeviceVendor.UNKNOWN.value, DeviceVendor.GENERIC.value}:
                    inferred, raw_oui = infer_vendor_from_mac(norm_mac)
                    if inferred != DeviceVendor.UNKNOWN.value:
                        patch["vendor"] = inferred
                        cf = dict(device.custom_fields_json or {})
                        if raw_oui:
                            cf["oui_vendor"] = raw_oui
                        patch["custom_fields_json"] = cf

        if "vendor" in raw and raw["vendor"] is not None:
            patch["vendor"] = normalize_device_vendor(raw["vendor"])

        if "device_type" in raw and raw["device_type"] is not None:
            patch["device_type"] = normalize_device_type(raw["device_type"])

        if "status" in raw and raw["status"] is not None:
            requested_status = normalize_device_status(raw["status"])

        # Validate site/rack/placement coherence
        effective_site_id = raw["site_id"] if "site_id" in raw else device.site_id
        effective_rack_id = raw["rack_id"] if "rack_id" in raw else device.rack_id
        effective_u_start = (
            raw.get("rack_unit_start", raw.get("rack_u_position"))
            if ("rack_unit_start" in raw or "rack_u_position" in raw)
            else device.rack_unit_start
        )
        effective_u_height = (
            raw.get("rack_unit_height", raw.get("rack_u_height"))
            if ("rack_unit_height" in raw or "rack_u_height" in raw)
            else (device.rack_unit_height or 1)
        )

        if "site_id" in raw and effective_site_id is not None:
            self.sites.get_by_id_or_raise(str(effective_site_id), org_id=org_id)
            patch["site_id"] = effective_site_id
        elif "site_id" in raw:
            patch["site_id"] = None

        if any(k in raw for k in ("rack_id", "rack_unit_start", "rack_u_position", "rack_unit_height", "rack_u_height")):
            if effective_rack_id is not None:
                rack = self.racks.get_by_id_or_raise(str(effective_rack_id), org_id=org_id)
                if effective_site_id is not None and str(effective_site_id) != rack.site_id:
                    raise ValidationError(
                        f"Rack '{rack.name}' belongs to site '{rack.site_id}', not '{effective_site_id}'"
                    )
                if effective_site_id is None:
                    patch["site_id"] = rack.site_id
                if effective_u_start is not None:
                    self.validate_rack_placement(
                        rack.id,
                        org_id,
                        int(effective_u_start),
                        int(effective_u_height or 1),
                        exclude_device_id=device.id,
                    )
            if "rack_id" in raw:
                patch["rack_id"] = effective_rack_id
            if "rack_unit_start" in raw or "rack_u_position" in raw:
                patch["rack_unit_start"] = int(effective_u_start) if effective_u_start is not None else None
            if "rack_unit_height" in raw or "rack_u_height" in raw:
                if effective_u_height is not None and int(effective_u_height) < 1:
                    raise ValidationError("rack_unit_height must be >= 1")
                patch["rack_unit_height"] = int(effective_u_height) if effective_u_height is not None else 1

        if "credential_profile_id" in raw:
            cred_id = raw["credential_profile_id"]
            if cred_id is not None:
                self.credentials.get_by_id_or_raise(str(cred_id), org_id=org_id)
            patch["credential_profile_id"] = cred_id

        direct_fields = (
            "fqdn",
            "model",
            "os_version",
            "serial_number",
            "asset_tag",
            "polling_enabled",
            "snmp_enabled",
            "icmp_enabled",
            "sys_descr",
            "sys_object_id",
            "sys_location",
            "sys_contact",
            "uptime_seconds",
        )
        for fld in direct_fields:
            if fld in raw:
                patch[fld] = raw[fld]

        if "polling_interval_seconds" in raw or "poll_interval_seconds" in raw:
            interval = int(raw.get("polling_interval_seconds", raw.get("poll_interval_seconds")))
            if interval < 5:
                raise ValidationError("polling_interval_seconds must be >= 5")
            patch["polling_interval_seconds"] = interval

        if "tags_json" in raw or "tags" in raw:
            tag_src = raw["tags_json"] if "tags_json" in raw else raw["tags"]
            if tag_src is not None:
                patch["tags_json"] = normalize_tags(tag_src)

        if "custom_fields_json" in raw or "custom_fields" in raw:
            cf_src = raw.get("custom_fields_json", raw.get("custom_fields"))
            if isinstance(cf_src, Mapping):
                merged_cf = dict(patch.get("custom_fields_json") or device.custom_fields_json or {})
                merged_cf.update(cf_src)
                patch["custom_fields_json"] = merged_cf

        changed_fields = sorted(patch.keys())
        updated = self.devices.update(device, patch, org_id=org_id) if patch else device

        if requested_status is not None and requested_status != updated.status:
            self.transition_device_status(
                updated.id,
                org_id,
                requested_status,
                reason="inventory_update",
                source="netpulse.inventory",
            )
            changed_fields = sorted(set(changed_fields) | {"status"})

        if changed_fields:
            self._record_audit(
                org_id=org_id,
                action=AuditAction.UPDATE,
                resource_type="device",
                resource_id=updated.id,
                summary=f"Updated device '{updated.hostname}': {', '.join(changed_fields)}",
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                before_state=before,
                after_state=updated.to_summary_dict(),
            )
            if emit_event:
                self._publish_event(
                    device_updated_event(
                        device_id=updated.id,
                        changed_fields=changed_fields,
                        updated_by=actor_email or actor_user_id,
                        org_id=org_id,
                    )
                )

        return updated

    def transition_device_status(
        self,
        device_id: str,
        org_id: str,
        new_status: str | DeviceStatus,
        *,
        reason: str | None = None,
        uptime_seconds: int | None = None,
        force: bool = False,
        source: str = "netpulse.inventory",
    ) -> DeviceStatusTransition:
        """Transition a device's operational status and publish ``device.status.changed`` on EventBus."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        previous = device.status
        target = normalize_device_status(new_status)

        if not force:
            allowed = ALLOWED_STATUS_TRANSITIONS.get(previous, frozenset())
            if target not in allowed:
                raise ValidationError(
                    f"Invalid device status transition from '{previous}' to '{target}' "
                    "(use force=True to override)",
                    details={
                        "device_id": device.id,
                        "previous_status": previous,
                        "requested_status": target,
                        "allowed_targets": sorted(allowed),
                    },
                )

        now = utcnow()
        device.mark_polled(status=target, uptime_seconds=uptime_seconds, now=now)
        self.db.add(device)
        self.db.flush()

        changed = previous != target
        published = False
        if changed:
            evt = device_status_changed_event(
                device_id=device.id,
                hostname=device.hostname,
                previous_status=previous,
                new_status=target,
                reason=reason,
                org_id=org_id,
            )
            if source != "netpulse.collector":
                evt = Event(
                    topic=evt.topic,
                    payload=evt.payload,
                    source=source,
                    org_id=org_id,
                    severity=evt.severity,
                )
            published = self._publish_event(evt)

        return DeviceStatusTransition(
            device_id=device.id,
            hostname=device.hostname,
            previous_status=previous,
            new_status=target,
            changed=changed,
            event_published=published,
            reason=reason,
            transitioned_at=now,
        )

    def delete_device(
        self,
        device_id: str,
        org_id: str,
        *,
        hard_delete: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> bool:
        """Soft-delete (default) or permanently delete a device and publish a lifecycle event."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        hostname = device.hostname
        mgmt_ip = device.management_ip

        if hard_delete:
            self.devices.delete(device, org_id=org_id)
        else:
            self.devices.soft_delete(device, org_id=org_id)

        self._record_audit(
            org_id=org_id,
            action=AuditAction.DELETE,
            resource_type="device",
            resource_id=device_id,
            summary=f"{'Hard' if hard_delete else 'Soft'}-deleted device '{hostname}'",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
        )
        self._publish_event(
            Event(
                topic="device.deleted",
                source="netpulse.inventory",
                org_id=org_id,
                severity=EventSeverity.INFO,
                payload={
                    "device_id": device_id,
                    "hostname": hostname,
                    "management_ip": mgmt_ip,
                    "hard_delete": hard_delete,
                },
            )
        )
        return True

    def restore_device(self, device_id: str, org_id: str) -> Device:
        """Restore a soft-deleted device after verifying organization quota."""
        self._check_device_quota(org_id, additional=1)
        return self.devices.restore(device_id, org_id=org_id)

    # --- Tag Management ---

    def add_device_tags(self, device_id: str, org_id: str, tags: Iterable[str] | str) -> Device:
        """Idempotently attach one or more tags to a device."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        for tag in normalize_tags(tags):
            device.add_tag(tag)
        self.db.add(device)
        self.db.flush()
        return device

    def remove_device_tags(self, device_id: str, org_id: str, tags: Iterable[str] | str) -> Device:
        """Detach one or more tags from a device."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        for tag in normalize_tags(tags):
            device.remove_tag(tag)
        self.db.add(device)
        self.db.flush()
        return device

    def set_device_tags(self, device_id: str, org_id: str, tags: Iterable[str] | Mapping[str, Any] | str) -> Device:
        """Replace a device's entire tag list with normalized unique tags."""
        device = self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        device.tags_json = normalize_tags(tags)
        self.db.add(device)
        self.db.flush()
        return device

    def list_org_tags(self, org_id: str) -> dict[str, int]:
        """Return a frequency map of all tags used across active devices in an organization."""
        counts: Counter[str] = Counter()
        for dev in self.devices.list(org_id=org_id):
            for tag in dev.tags_json or []:
                counts[tag] += 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    # --- Fleet Summary Statistics ---

    def get_fleet_summary(
        self,
        org_id: str,
        *,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute fleet-wide summary statistics by status, vendor, device_type, and site."""
        if site_id is not None:
            devices = self.devices.list_by_site(site_id, org_id=org_id)
        else:
            devices = self.devices.list(org_id=org_id)

        by_status: Counter[str] = Counter()
        by_vendor: Counter[str] = Counter()
        by_device_type: Counter[str] = Counter()
        by_site_counts: Counter[str] = Counter()
        polling_enabled_count = 0
        snmp_enabled_count = 0
        stale_count = 0

        for dev in devices:
            by_status[dev.status] += 1
            by_vendor[dev.vendor] += 1
            by_device_type[dev.device_type] += 1
            by_site_counts[dev.site_id or "unassigned"] += 1
            if dev.polling_enabled:
                polling_enabled_count += 1
                if dev.is_stale():
                    stale_count += 1
            if dev.snmp_enabled:
                snmp_enabled_count += 1

        sites_by_id = {s.id: s for s in self.sites.list(org_id=org_id)}
        by_site_detail: list[dict[str, Any]] = []
        for sid, cnt in by_site_counts.items():
            site = sites_by_id.get(sid)
            by_site_detail.append(
                {
                    "site_id": None if sid == "unassigned" else sid,
                    "site_code": site.code if site else "UNASSIGNED",
                    "site_name": site.name if site else "Unassigned",
                    "device_count": cnt,
                }
            )
        by_site_detail.sort(key=lambda item: (-item["device_count"], item["site_name"]))

        total = len(devices)
        healthy = by_status.get(DeviceStatus.UP.value, 0)
        maintenance = by_status.get(DeviceStatus.MAINTENANCE.value, 0)
        problem = sum(
            by_status.get(st, 0)
            for st in (
                DeviceStatus.DOWN.value,
                DeviceStatus.DEGRADED.value,
                DeviceStatus.WARNING.value,
                DeviceStatus.CRITICAL.value,
                DeviceStatus.UNREACHABLE.value,
            )
        )
        evaluable = max(0, total - maintenance)
        availability_pct = round((healthy / evaluable) * 100.0, 2) if evaluable > 0 else 100.0

        org = self.orgs.get_by_id(org_id)
        max_devices = int(org.max_devices) if org and org.max_devices else 1000
        org_total = self.devices.count(org_id=org_id) if site_id is not None else total

        return {
            "org_id": org_id,
            "site_id": site_id,
            "total_devices": total,
            "healthy_devices": healthy,
            "problem_devices": problem,
            "maintenance_devices": maintenance,
            "availability_pct": availability_pct,
            "polling_enabled_count": polling_enabled_count,
            "snmp_enabled_count": snmp_enabled_count,
            "stale_device_count": stale_count,
            "by_status": dict(by_status),
            "by_vendor": dict(by_vendor),
            "by_device_type": dict(by_device_type),
            "by_site": dict(by_site_counts),
            "by_site_detail": by_site_detail,
            "quota": {
                "used": org_total,
                "max_devices": max_devices,
                "remaining": max(0, max_devices - org_total),
                "utilization_pct": round((org_total / max_devices) * 100.0, 2) if max_devices > 0 else 0.0,
            },
        }

    # -----------------------------------------------------------------------
    # DeviceInterfaces CRUD, Bulk Sync, Utilization & Uplinks
    # -----------------------------------------------------------------------

    def create_interface(
        self,
        org_id: str,
        device_id: str,
        data: Mapping[str, Any] | Any,
    ) -> DeviceInterface:
        """Create a physical or logical network interface on a managed device."""
        self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        raw = _coerce_mapping(data)

        name = str(raw.get("name") or "").strip()
        if not name:
            raise ValidationError("Interface 'name' must not be empty")

        if_index = raw.get("if_index")
        if if_index is None:
            # Auto-assign next sequential if_index
            existing_ifs = self.interfaces.list_by_device(device_id, org_id=org_id)
            if_index = max((i.if_index for i in existing_ifs), default=0) + 1
        else:
            if_index = int(if_index)
            if if_index < 0:
                raise ValidationError("Interface 'if_index' must be >= 0")
            if self.interfaces.get_by_device_and_index(device_id, if_index, org_id=org_id) is not None:
                raise ConflictError(
                    f"Interface with if_index {if_index} already exists on device '{device_id}'",
                    details={"device_id": device_id, "if_index": if_index},
                )

        ip_raw = raw.get("ip_address")
        if ip_raw is None and raw.get("ip_addresses"):
            ip_list = raw["ip_addresses"]
            ip_raw = ip_list[0] if ip_list else None
        ip_address = normalize_ip(str(ip_raw)) if ip_raw and str(ip_raw).strip() else None

        mac_raw = raw.get("mac_address")
        mac_address = format_mac(str(mac_raw)) if mac_raw and str(mac_raw).strip() else None

        vlan_id = raw.get("vlan_id")
        if vlan_id is not None and not (1 <= int(vlan_id) <= 4094):
            raise ValidationError("Interface vlan_id must be between 1 and 4094")

        mtu = raw.get("mtu", 1500)
        if mtu is not None and int(mtu) < 68:
            raise ValidationError("Interface mtu must be >= 68")

        speed_mbps = raw.get("speed_mbps")
        if speed_mbps is not None and int(speed_mbps) < 0:
            raise ValidationError("Interface speed_mbps must be >= 0")

        admin_status = raw.get("admin_status", InterfaceStatus.UP.value)
        if hasattr(admin_status, "value"):
            admin_status = admin_status.value
        oper_status = raw.get("oper_status", InterfaceStatus.UNKNOWN.value)
        if hasattr(oper_status, "value"):
            oper_status = oper_status.value
        duplex = raw.get("duplex", DuplexMode.UNKNOWN.value)
        if hasattr(duplex, "value"):
            duplex = duplex.value

        payload: dict[str, Any] = {
            "device_id": device_id,
            "if_index": if_index,
            "name": name,
            "alias": raw.get("alias"),
            "description": raw.get("description"),
            "mac_address": mac_address,
            "ip_address": ip_address,
            "subnet_mask": raw.get("subnet_mask"),
            "vlan_id": int(vlan_id) if vlan_id is not None else None,
            "interface_type": normalize_interface_type(raw.get("interface_type")),
            "speed_mbps": int(speed_mbps) if speed_mbps is not None else None,
            "mtu": int(mtu) if mtu is not None else 1500,
            "admin_status": str(admin_status).lower(),
            "oper_status": str(oper_status).lower(),
            "duplex": str(duplex).lower(),
            "is_monitored": bool(raw.get("is_monitored", True)),
            "is_uplink": bool(raw.get("is_uplink", False)),
            "in_octets_last": raw.get("in_octets_last"),
            "out_octets_last": raw.get("out_octets_last"),
            "in_errors_last": raw.get("in_errors_last"),
            "out_errors_last": raw.get("out_errors_last"),
            "utilization_in_pct": float(raw.get("utilization_in_pct", 0.0)),
            "utilization_out_pct": float(raw.get("utilization_out_pct", 0.0)),
        }
        return self.interfaces.create(payload, org_id=org_id)

    def get_interface(self, interface_id: str, org_id: str) -> DeviceInterface:
        """Fetch an interface by ID within tenant scope."""
        return self.interfaces.get_by_id_or_raise(interface_id, org_id=org_id)

    def list_device_interfaces(
        self,
        org_id: str,
        device_id: str,
        *,
        oper_status: str | None = None,
        admin_status: str | None = None,
        uplinks_only: bool = False,
    ) -> list[DeviceInterface]:
        """List interfaces belonging to a device with optional status and uplink filters."""
        self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        ifaces = self.interfaces.list_by_device(
            device_id,
            oper_status=oper_status,
            admin_status=admin_status,
            org_id=org_id,
        )
        if uplinks_only:
            return [i for i in ifaces if i.is_uplink]
        return ifaces

    def update_interface(
        self,
        interface_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> DeviceInterface:
        """Update attributes of an existing device interface."""
        iface = self.interfaces.get_by_id_or_raise(interface_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        for fld in ("name", "alias", "description", "subnet_mask", "is_monitored", "is_uplink"):
            if fld in raw:
                patch[fld] = raw[fld]

        if "interface_type" in raw and raw["interface_type"] is not None:
            patch["interface_type"] = normalize_interface_type(raw["interface_type"])
        if "mac_address" in raw:
            patch["mac_address"] = (
                format_mac(str(raw["mac_address"]))
                if raw["mac_address"] and str(raw["mac_address"]).strip()
                else None
            )
        if "ip_address" in raw or "ip_addresses" in raw:
            ip_val = raw.get("ip_address")
            if ip_val is None and raw.get("ip_addresses"):
                ip_val = raw["ip_addresses"][0] if raw["ip_addresses"] else None
            patch["ip_address"] = normalize_ip(str(ip_val)) if ip_val and str(ip_val).strip() else None
        if "vlan_id" in raw:
            vid = raw["vlan_id"]
            if vid is not None and not (1 <= int(vid) <= 4094):
                raise ValidationError("vlan_id must be between 1 and 4094")
            patch["vlan_id"] = int(vid) if vid is not None else None
        if "speed_mbps" in raw:
            spd = raw["speed_mbps"]
            if spd is not None and int(spd) < 0:
                raise ValidationError("speed_mbps must be >= 0")
            patch["speed_mbps"] = int(spd) if spd is not None else None
        if "mtu" in raw:
            mtu = raw["mtu"]
            if mtu is not None and int(mtu) < 68:
                raise ValidationError("mtu must be >= 68")
            patch["mtu"] = int(mtu) if mtu is not None else None

        for enum_field in ("admin_status", "oper_status", "duplex"):
            if enum_field in raw and raw[enum_field] is not None:
                val = raw[enum_field]
                patch[enum_field] = (val.value if hasattr(val, "value") else str(val)).lower()

        return self.interfaces.update(iface, patch, org_id=org_id)

    def delete_interface(self, interface_id: str, org_id: str) -> bool:
        """Permanently delete a device interface."""
        iface = self.interfaces.get_by_id_or_raise(interface_id, org_id=org_id)
        return self.interfaces.delete(iface, org_id=org_id)

    def update_interface_counters(
        self,
        interface_id: str,
        org_id: str,
        *,
        in_octets: int,
        out_octets: int,
        interval_seconds: float,
        in_errors: int | None = None,
        out_errors: int | None = None,
        counter_bits: Literal[32, 64] = 64,
        oper_status: str | None = None,
    ) -> dict[str, Any]:
        """Update SNMP octet/error counters and recalculate ingress/egress utilization."""
        iface = self.interfaces.get_by_id_or_raise(interface_id, org_id=org_id)
        if in_octets < 0 or out_octets < 0:
            raise ValidationError("Octet counters must be non-negative")

        in_bps, out_bps = iface.update_counters(
            in_octets=in_octets,
            out_octets=out_octets,
            interval_seconds=interval_seconds,
            in_errors=in_errors,
            out_errors=out_errors,
            counter_bits=counter_bits,
        )
        if oper_status is not None:
            iface.oper_status = str(oper_status).lower()

        self.db.add(iface)
        self.db.flush()

        return {
            "interface_id": iface.id,
            "device_id": iface.device_id,
            "name": iface.name,
            "in_bps": round(in_bps, 2),
            "out_bps": round(out_bps, 2),
            "utilization_in_pct": iface.utilization_in_pct,
            "utilization_out_pct": iface.utilization_out_pct,
            "max_utilization_pct": iface.max_utilization_pct,
            "oper_status": iface.oper_status,
        }

    def calculate_interface_utilization(
        self,
        interface_id: str,
        org_id: str,
        *,
        in_octets_delta: int,
        out_octets_delta: int,
        interval_seconds: float,
    ) -> dict[str, float]:
        """Pure utilization calculation helper for an interface given octet deltas and interval."""
        iface = self.interfaces.get_by_id_or_raise(interface_id, org_id=org_id)
        speed_bps = float(iface.speed_mbps or 0) * 1_000_000.0
        util_in = calculate_utilization_pct(in_octets_delta, interval_seconds, speed_bps)
        util_out = calculate_utilization_pct(out_octets_delta, interval_seconds, speed_bps)
        in_bps = (max(0, in_octets_delta) * 8.0) / interval_seconds if interval_seconds > 0 else 0.0
        out_bps = (max(0, out_octets_delta) * 8.0) / interval_seconds if interval_seconds > 0 else 0.0
        return {
            "in_bps": round(in_bps, 2),
            "out_bps": round(out_bps, 2),
            "utilization_in_pct": util_in,
            "utilization_out_pct": util_out,
            "max_utilization_pct": max(util_in, util_out),
        }

    def bulk_sync_interfaces(
        self,
        org_id: str,
        device_id: str,
        interfaces_payload: Sequence[Mapping[str, Any]],
        *,
        prune_missing: bool = False,
        interval_seconds: float | None = None,
        counter_bits: Literal[32, 64] = 64,
    ) -> dict[str, Any]:
        """Idempotently synchronize a device's interface table from SNMP or API discovery."""
        self.devices.get_by_id_or_raise(device_id, org_id=org_id)
        existing_list = self.interfaces.list_by_device(device_id, org_id=org_id)
        by_index: dict[int, DeviceInterface] = {i.if_index: i for i in existing_list}
        by_name: dict[str, DeviceInterface] = {i.name.lower(): i for i in existing_list}

        created_count = 0
        updated_count = 0
        pruned_count = 0
        seen_ids: set[str] = set()
        next_auto_idx = max(by_index.keys(), default=0) + 1

        for item in interfaces_payload:
            raw = _coerce_mapping(item)
            name = str(raw.get("name") or "").strip()
            if not name:
                continue

            if_index = raw.get("if_index")
            target: DeviceInterface | None = None
            if if_index is not None:
                target = by_index.get(int(if_index))
            if target is None:
                target = by_name.get(name.lower())

            if target is None:
                create_data = dict(raw)
                if create_data.get("if_index") is None:
                    create_data["if_index"] = next_auto_idx
                    next_auto_idx += 1
                created = self.create_interface(org_id, device_id, create_data)
                by_index[created.if_index] = created
                by_name[created.name.lower()] = created
                seen_ids.add(created.id)
                created_count += 1
            else:
                update_data = {
                    k: v
                    for k, v in raw.items()
                    if k
                    not in {
                        "if_index",
                        "device_id",
                        "in_octets",
                        "out_octets",
                        "in_errors",
                        "out_errors",
                    }
                }
                if update_data:
                    self.update_interface(target.id, org_id, update_data)

                in_oct = raw.get("in_octets", raw.get("in_octets_last"))
                out_oct = raw.get("out_octets", raw.get("out_octets_last"))
                if in_oct is not None and out_oct is not None:
                    target.update_counters(
                        in_octets=int(in_oct),
                        out_octets=int(out_oct),
                        interval_seconds=float(interval_seconds or 60.0),
                        in_errors=raw.get("in_errors", raw.get("in_errors_last")),
                        out_errors=raw.get("out_errors", raw.get("out_errors_last")),
                        counter_bits=counter_bits,
                    )
                    self.db.add(target)
                seen_ids.add(target.id)
                updated_count += 1

        if prune_missing:
            for existing in existing_list:
                if existing.id not in seen_ids:
                    self.interfaces.delete(existing, org_id=org_id, flush=False)
                    pruned_count += 1

        self.db.flush()
        return {
            "device_id": device_id,
            "created_count": created_count,
            "updated_count": updated_count,
            "pruned_count": pruned_count,
            "total_interfaces": len(seen_ids) if prune_missing else len(existing_list) + created_count,
        }

    def list_uplinks(
        self,
        org_id: str,
        *,
        device_id: str | None = None,
        site_id: str | None = None,
        down_only: bool = False,
    ) -> list[DeviceInterface]:
        """List uplink interfaces across the organization, a site, or a single device."""
        if down_only and device_id is None and site_id is None:
            return self.interfaces.list_down_uplinks(org_id=org_id)

        filters: dict[str, Any] = {"is_uplink": True}
        if device_id is not None:
            self.devices.get_by_id_or_raise(device_id, org_id=org_id)
            filters["device_id"] = device_id
        elif site_id is not None:
            site_device_ids = [d.id for d in self.devices.list_by_site(site_id, org_id=org_id)]
            if not site_device_ids:
                return []
            filters["device_id__in"] = site_device_ids

        uplinks = self.interfaces.list(filters=filters, org_id=org_id)
        if down_only:
            uplinks = [
                u
                for u in uplinks
                if u.admin_status == InterfaceStatus.UP.value and u.oper_status != InterfaceStatus.UP.value
            ]
        return uplinks

    # -----------------------------------------------------------------------
    # IPAM: Subnets CRUD, CIDR Validation, Overlap Detection & Calculator
    # -----------------------------------------------------------------------

    def calculate_subnet_details(
        self,
        cidr: str,
        *,
        child_prefix_delta: int = 1,
    ) -> dict[str, Any]:
        """Calculate complete IPv4/IPv6 subnet geometry using ``network_utils`` and schema helpers."""
        info = calculate_subnet(cidr, strict=False)
        schema_resp = SubnetCalculationResponse.from_cidr(info.cidr, child_prefix_delta=child_prefix_delta)
        payload = schema_resp.model_dump()
        payload.update(
            {
                "scope": info.scope,
                "is_rfc1918": info.is_rfc1918,
                "binary_netmask": info.binary_netmask,
            }
        )
        return payload

    def split_subnet_cidr(
        self,
        cidr: str,
        *,
        new_prefix: int | None = None,
        count: int | None = None,
    ) -> list[str]:
        """Split a CIDR into equal-sized child subnets."""
        return split_subnet(cidr, new_prefix=new_prefix, count=count)

    def detect_subnet_overlaps(
        self,
        org_id: str,
        cidr: str,
        *,
        site_id: str | None = None,
        exclude_subnet_id: str | None = None,
        scope: Literal["org", "site"] = "org",
    ) -> list[Subnet]:
        """Find existing subnets in the org (or site) whose address space overlaps ``cidr``."""
        normalized_net = str(parse_network(cidr, strict=False))
        if scope == "site" and site_id is not None:
            candidates = self.subnets.list_by_site(site_id, org_id=org_id)
        else:
            candidates = self.subnets.list(org_id=org_id)

        overlapping: list[Subnet] = []
        for sub in candidates:
            if exclude_subnet_id is not None and sub.id == exclude_subnet_id:
                continue
            if cidrs_overlap(normalized_net, sub.cidr):
                overlapping.append(sub)
        return overlapping

    def create_subnet(
        self,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        allow_overlap: bool = False,
        overlap_scope: Literal["org", "site"] = "org",
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> Subnet:
        """Create a managed IPAM subnet with CIDR validation, gateway check, and overlap protection."""
        raw = _coerce_mapping(data)
        raw_cidr = raw.get("cidr")
        if not raw_cidr or not is_valid_cidr(str(raw_cidr), strict=False):
            raise ValidationError(f"Invalid CIDR block: {raw_cidr!r}", details={"cidr": raw_cidr})
        normalized_cidr = str(parse_network(str(raw_cidr), strict=False))

        name = str(raw.get("name") or "").strip()
        if not name:
            raise ValidationError("Subnet 'name' must not be empty")

        site_id = raw.get("site_id")
        if site_id is not None:
            self.sites.get_by_id_or_raise(str(site_id), org_id=org_id)

        if self.subnets.get_by_cidr(normalized_cidr, org_id=org_id) is not None:
            raise ConflictError(
                f"Subnet '{normalized_cidr}' already exists in this organization",
                details={"cidr": normalized_cidr},
            )

        if not allow_overlap:
            overlaps = self.detect_subnet_overlaps(
                org_id,
                normalized_cidr,
                site_id=site_id,
                scope=overlap_scope,
            )
            if overlaps:
                raise ConflictError(
                    f"Subnet '{normalized_cidr}' overlaps existing subnet(s): "
                    + ", ".join(s.cidr for s in overlaps),
                    error_code="SUBNET_OVERLAP",
                    details={
                        "cidr": normalized_cidr,
                        "overlapping_subnets": [
                            {"id": s.id, "cidr": s.cidr, "name": s.name, "site_id": s.site_id}
                            for s in overlaps
                        ],
                    },
                )

        gateway_ip = raw.get("gateway_ip")
        if gateway_ip is not None and str(gateway_ip).strip():
            gateway_ip = normalize_ip(str(gateway_ip))
            if not ip_in_cidr(gateway_ip, normalized_cidr):
                raise ValidationError(
                    f"Gateway IP '{gateway_ip}' is outside subnet '{normalized_cidr}'",
                    details={"gateway_ip": gateway_ip, "cidr": normalized_cidr},
                )
        else:
            gateway_ip = None

        vlan_number = raw.get("vlan_number")
        if vlan_number is not None:
            vlan_number = int(vlan_number)
            if not (1 <= vlan_number <= 4094):
                raise ValidationError("vlan_number must be between 1 and 4094")

        raw_dns = raw.get("dns_servers_json") or raw.get("dns_servers") or []
        dns_servers = [normalize_ip(str(ip)) for ip in raw_dns if ip and str(ip).strip()]

        payload: dict[str, Any] = {
            "site_id": site_id,
            "cidr": normalized_cidr,
            "name": name,
            "description": raw.get("description"),
            "gateway_ip": gateway_ip,
            "vlan_number": vlan_number,
            "dns_servers_json": dns_servers,
            "dhcp_enabled": bool(raw.get("dhcp_enabled", False)),
            "utilization_pct": 0.0,
            "scan_enabled": bool(raw.get("scan_enabled", True)),
        }
        subnet = self.subnets.create(payload, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="subnet",
            resource_id=subnet.id,
            summary=f"Created subnet {subnet.cidr} ({subnet.name})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
        )
        return subnet

    def get_subnet(self, subnet_id: str, org_id: str) -> Subnet:
        """Fetch an active subnet by ID within tenant scope."""
        return self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)

    def list_subnets(
        self,
        org_id: str,
        *,
        site_id: str | None = None,
        vlan_number: int | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Subnet]:
        """List and paginate managed subnets with optional site, VLAN, and search filters."""
        filters: dict[str, Any] = {}
        if site_id is not None:
            filters["site_id"] = site_id
        if vlan_number is not None:
            filters["vlan_number"] = vlan_number

        if not query:
            return self.subnets.paginate(
                page=page,
                page_size=page_size,
                filters=filters,
                org_id=org_id,
            )

        all_subs = self.subnets.list(filters=filters, org_id=org_id)
        q = query.strip().lower()
        matched = [
            s
            for s in all_subs
            if q in s.cidr.lower()
            or q in s.name.lower()
            or (s.description and q in s.description.lower())
        ]
        total = len(matched)
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        start = (page - 1) * page_size
        return PageResult(
            items=matched[start : start + page_size],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def update_subnet(
        self,
        subnet_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
        *,
        allow_overlap: bool = False,
    ) -> Subnet:
        """Update subnet attributes with gateway containment and optional CIDR overlap checks."""
        subnet = self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        effective_cidr = subnet.cidr
        if "cidr" in raw and raw["cidr"] is not None:
            new_cidr = str(parse_network(str(raw["cidr"]), strict=False))
            if new_cidr != subnet.cidr:
                existing = self.subnets.get_by_cidr(new_cidr, org_id=org_id)
                if existing is not None and existing.id != subnet.id:
                    raise ConflictError(f"Subnet '{new_cidr}' already exists")
                if not allow_overlap:
                    overlaps = self.detect_subnet_overlaps(
                        org_id,
                        new_cidr,
                        site_id=raw.get("site_id", subnet.site_id),
                        exclude_subnet_id=subnet.id,
                    )
                    if overlaps:
                        raise ConflictError(
                            f"Updated CIDR '{new_cidr}' overlaps existing subnet(s): "
                            + ", ".join(s.cidr for s in overlaps),
                            error_code="SUBNET_OVERLAP",
                        )
                patch["cidr"] = new_cidr
                effective_cidr = new_cidr

        if "site_id" in raw:
            if raw["site_id"] is not None:
                self.sites.get_by_id_or_raise(str(raw["site_id"]), org_id=org_id)
            patch["site_id"] = raw["site_id"]

        if "name" in raw and raw["name"] is not None:
            name = str(raw["name"]).strip()
            if not name:
                raise ValidationError("Subnet name must not be empty")
            patch["name"] = name

        if "description" in raw:
            patch["description"] = raw["description"]

        if "gateway_ip" in raw:
            gw = raw["gateway_ip"]
            if gw is None or not str(gw).strip():
                patch["gateway_ip"] = None
            else:
                norm_gw = normalize_ip(str(gw))
                if not ip_in_cidr(norm_gw, effective_cidr):
                    raise ValidationError(
                        f"Gateway IP '{norm_gw}' is outside subnet '{effective_cidr}'"
                    )
                patch["gateway_ip"] = norm_gw
        elif "cidr" in patch and subnet.gateway_ip and not ip_in_cidr(subnet.gateway_ip, effective_cidr):
            raise ValidationError(
                f"Existing gateway '{subnet.gateway_ip}' is outside new CIDR '{effective_cidr}'"
            )

        if "vlan_number" in raw:
            vid = raw["vlan_number"]
            if vid is not None and not (1 <= int(vid) <= 4094):
                raise ValidationError("vlan_number must be between 1 and 4094")
            patch["vlan_number"] = int(vid) if vid is not None else None

        if "dns_servers_json" in raw or "dns_servers" in raw:
            raw_dns = raw.get("dns_servers_json", raw.get("dns_servers")) or []
            patch["dns_servers_json"] = [normalize_ip(str(ip)) for ip in raw_dns if ip and str(ip).strip()]

        for bool_fld in ("dhcp_enabled", "scan_enabled"):
            if bool_fld in raw and raw[bool_fld] is not None:
                patch[bool_fld] = bool(raw[bool_fld])

        updated = self.subnets.update(subnet, patch, org_id=org_id)
        if "cidr" in patch:
            self.recalculate_subnet_utilization(updated.id, org_id)
        return updated

    def delete_subnet(
        self,
        subnet_id: str,
        org_id: str,
        *,
        force: bool = False,
    ) -> Subnet:
        """Soft-delete a subnet, blocking if active IP allocations exist unless ``force=True``."""
        subnet = self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)
        allocs = self.allocations.list(filters={"subnet_id": subnet_id}, org_id=org_id)
        active_allocs = [a for a in allocs if a.status in _ACTIVE_ALLOCATION_STATUSES]
        if active_allocs and not force:
            raise ConflictError(
                f"Cannot delete subnet '{subnet.cidr}' with {len(active_allocs)} active IP allocation(s)",
                details={"subnet_id": subnet_id, "active_allocations": len(active_allocs)},
            )
        return self.subnets.soft_delete(subnet, org_id=org_id)

    def recalculate_subnet_utilization(self, subnet_id: str, org_id: str) -> dict[str, Any]:
        """Recalculate and persist ``Subnet.utilization_pct`` from active IP allocations."""
        subnet = self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)
        allocs = self.allocations.list(filters={"subnet_id": subnet_id}, org_id=org_id)
        active_count = sum(1 for a in allocs if (a.status or "active").lower() in _ACTIVE_ALLOCATION_STATUSES)
        total_usable = subnet.total_usable_hosts
        pct = subnet.recalculate_utilization(active_count)
        self.db.add(subnet)
        self.db.flush()
        return {
            "subnet_id": subnet.id,
            "cidr": subnet.cidr,
            "total_usable": total_usable,
            "allocated": active_count,
            "total_records": len(allocs),
            "available": max(0, total_usable - active_count),
            "utilization_pct": pct,
        }

    def get_ipam_summary(self, org_id: str, *, site_id: str | None = None) -> dict[str, Any]:
        """Return organization-wide or site-scoped IPAM capacity and utilization summary."""
        subs = self.subnets.list_by_site(site_id, org_id=org_id) if site_id else self.subnets.list(org_id=org_id)
        total_usable = 0
        total_allocated = 0
        high_util: list[dict[str, Any]] = []

        for sub in subs:
            usable = sub.total_usable_hosts
            alloc_cnt = self.allocations.count(filters={"subnet_id": sub.id}, org_id=org_id)
            total_usable += usable
            total_allocated += alloc_cnt
            if sub.utilization_pct >= 80.0:
                high_util.append(
                    {
                        "subnet_id": sub.id,
                        "cidr": sub.cidr,
                        "name": sub.name,
                        "utilization_pct": sub.utilization_pct,
                    }
                )

        overall_pct = round((total_allocated / total_usable) * 100.0, 2) if total_usable > 0 else 0.0
        vlan_filters: dict[str, Any] = {"site_id": site_id} if site_id else {}
        vlan_count = self.vlans.count(filters=vlan_filters or None, org_id=org_id)
        return {
            "subnet_count": len(subs),
            "vlan_count": vlan_count,
            "total_usable_ips": total_usable,
            "total_allocated_ips": total_allocated,
            "overall_utilization_pct": overall_pct,
            "high_utilization_subnets": sorted(high_util, key=lambda x: -x["utilization_pct"]),
        }

    # -----------------------------------------------------------------------
    # VLANs CRUD + Per-Site Uniqueness Validation
    # -----------------------------------------------------------------------

    def _find_conflicting_vlan(
        self,
        org_id: str,
        vlan_id_num: int,
        site_id: str | None,
        *,
        exclude_id: str | None = None,
    ) -> Vlan | None:
        """Check uniqueness of ``(org_id, site_id, vlan_id_num)`` including ``site_id IS NULL``."""
        stmt = select(Vlan).where(
            Vlan.org_id == org_id,
            Vlan.vlan_id_num == vlan_id_num,
            Vlan.site_id.is_(None) if site_id is None else Vlan.site_id == site_id,
        )
        if exclude_id is not None:
            stmt = stmt.where(Vlan.id != exclude_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def create_vlan(self, org_id: str, data: Mapping[str, Any] | Any) -> Vlan:
        """Create an IEEE 802.1Q VLAN enforcing uniqueness per site within an organization."""
        raw = _coerce_mapping(data)
        vid_raw = raw.get("vlan_id_num", raw.get("vlan_id"))
        if vid_raw is None:
            raise ValidationError("VLAN 'vlan_id_num' (1..4094) is required")
        vlan_id_num = int(vid_raw)
        if not (1 <= vlan_id_num <= 4094):
            raise ValidationError("VLAN ID must be between 1 and 4094", details={"vlan_id_num": vlan_id_num})

        name = str(raw.get("name") or "").strip()
        if not name:
            raise ValidationError("VLAN 'name' must not be empty")

        site_id = raw.get("site_id")
        if site_id is not None:
            self.sites.get_by_id_or_raise(str(site_id), org_id=org_id)

        if self._find_conflicting_vlan(org_id, vlan_id_num, site_id) is not None:
            scope_desc = f"site '{site_id}'" if site_id else "global org scope"
            raise ConflictError(
                f"VLAN {vlan_id_num} already exists in {scope_desc}",
                details={"vlan_id_num": vlan_id_num, "site_id": site_id},
            )

        status_raw = raw.get("status", "active")
        status = (status_raw.value if hasattr(status_raw, "value") else str(status_raw)).strip().lower()
        if status not in _VALID_VLAN_STATUSES:
            raise ValidationError(
                f"Invalid VLAN status {status!r}",
                details={"allowed": sorted(_VALID_VLAN_STATUSES)},
            )

        subnet_cidr = raw.get("subnet_cidr")
        if subnet_cidr is not None and str(subnet_cidr).strip():
            subnet_cidr = str(parse_network(str(subnet_cidr), strict=False))
        else:
            subnet_cidr = None

        payload: dict[str, Any] = {
            "site_id": site_id,
            "vlan_id_num": vlan_id_num,
            "name": name,
            "description": raw.get("description"),
            "status": status,
            "subnet_cidr": subnet_cidr,
        }
        return self.vlans.create(payload, org_id=org_id)

    def get_vlan(self, vlan_id: str, org_id: str) -> Vlan:
        """Fetch a VLAN record by UUID within tenant scope."""
        return self.vlans.get_by_id_or_raise(vlan_id, org_id=org_id)

    def list_vlans(
        self,
        org_id: str,
        *,
        site_id: str | None = None,
        status: str | None = None,
        min_vid: int | None = None,
        max_vid: int | None = None,
    ) -> list[Vlan]:
        """List VLANs with optional site, status, and 802.1Q ID range filters."""
        filters: dict[str, Any] = {}
        if site_id is not None:
            filters["site_id"] = site_id
        if status is not None:
            filters["status"] = status.strip().lower()
        if min_vid is not None:
            filters["vlan_id_num__gte"] = int(min_vid)
        if max_vid is not None:
            filters["vlan_id_num__lte"] = int(max_vid)
        return self.vlans.list(filters=filters or None, org_id=org_id)

    def update_vlan(
        self,
        vlan_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> Vlan:
        """Update a VLAN while preserving per-site 802.1Q ID uniqueness."""
        vlan = self.vlans.get_by_id_or_raise(vlan_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        new_vid = raw.get("vlan_id_num", raw.get("vlan_id"))
        effective_vid = int(new_vid) if new_vid is not None else vlan.vlan_id_num
        if not (1 <= effective_vid <= 4094):
            raise ValidationError("VLAN ID must be between 1 and 4094")

        effective_site_id = raw["site_id"] if "site_id" in raw else vlan.site_id
        if "site_id" in raw and effective_site_id is not None:
            self.sites.get_by_id_or_raise(str(effective_site_id), org_id=org_id)

        if effective_vid != vlan.vlan_id_num or effective_site_id != vlan.site_id:
            if self._find_conflicting_vlan(org_id, effective_vid, effective_site_id, exclude_id=vlan.id) is not None:
                raise ConflictError(
                    f"VLAN {effective_vid} already exists in target site scope",
                    details={"vlan_id_num": effective_vid, "site_id": effective_site_id},
                )
            patch["vlan_id_num"] = effective_vid
            patch["site_id"] = effective_site_id

        if "name" in raw and raw["name"] is not None:
            name = str(raw["name"]).strip()
            if not name:
                raise ValidationError("VLAN name must not be empty")
            patch["name"] = name
        if "description" in raw:
            patch["description"] = raw["description"]
        if "status" in raw and raw["status"] is not None:
            st = (raw["status"].value if hasattr(raw["status"], "value") else str(raw["status"])).strip().lower()
            if st not in _VALID_VLAN_STATUSES:
                raise ValidationError(f"Invalid VLAN status {st!r}")
            patch["status"] = st
        if "subnet_cidr" in raw:
            sc = raw["subnet_cidr"]
            patch["subnet_cidr"] = str(parse_network(str(sc), strict=False)) if sc and str(sc).strip() else None

        return self.vlans.update(vlan, patch, org_id=org_id)

    def delete_vlan(self, vlan_id: str, org_id: str) -> bool:
        """Delete a VLAN definition by UUID."""
        vlan = self.vlans.get_by_id_or_raise(vlan_id, org_id=org_id)
        return self.vlans.delete(vlan, org_id=org_id)

    # -----------------------------------------------------------------------
    # IP Allocations CRUD, Conflict Detection & Next-Available-IP Allocator
    # -----------------------------------------------------------------------

    def create_ip_allocation(
        self,
        org_id: str,
        subnet_id: str,
        data: Mapping[str, Any] | Any,
        *,
        allow_network_or_broadcast: bool = False,
    ) -> IpAllocation:
        """Allocate or reserve a specific IP address inside a subnet with conflict checks."""
        subnet = self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)
        raw = _coerce_mapping(data)

        ip_raw = raw.get("ip_address")
        if not ip_raw or not is_valid_ip(str(ip_raw)):
            raise ValidationError(f"Invalid IP address: {ip_raw!r}", details={"ip_address": ip_raw})
        addr = parse_ip(str(ip_raw))
        ip_str = str(addr)
        network = subnet.network

        if addr.version != network.version or addr not in network:
            raise ValidationError(
                f"IP address '{ip_str}' does not belong to subnet '{subnet.cidr}'",
                details={"ip_address": ip_str, "cidr": subnet.cidr},
            )

        if (
            not allow_network_or_broadcast
            and isinstance(network, ipaddress.IPv4Network)
            and network.prefixlen < 31
            and addr in (network.network_address, network.broadcast_address)
        ):
            raise ValidationError(
                f"IP address '{ip_str}' is the network or broadcast address of '{subnet.cidr}'",
                details={"ip_address": ip_str, "cidr": subnet.cidr},
            )

        # Conflict check inside subnet
        existing = self.allocations.get_one_by(
            filters={"subnet_id": subnet_id, "ip_address": ip_str},
            org_id=org_id,
        )
        if existing is not None:
            raise ConflictError(
                f"IP address '{ip_str}' is already allocated in subnet '{subnet.cidr}'",
                error_code="IP_ALLOCATION_CONFLICT",
                details={
                    "ip_address": ip_str,
                    "subnet_id": subnet_id,
                    "existing_allocation_id": existing.id,
                },
            )

        device_id = raw.get("device_id")
        if device_id is not None:
            self.devices.get_by_id_or_raise(str(device_id), org_id=org_id)

        mac_raw = raw.get("mac_address")
        mac_address = format_mac(str(mac_raw)) if mac_raw and str(mac_raw).strip() else None

        alloc_type_raw = raw.get("allocation_type", "static")
        alloc_type = (
            alloc_type_raw.value if hasattr(alloc_type_raw, "value") else str(alloc_type_raw)
        ).strip().lower()
        if alloc_type not in _VALID_ALLOCATION_TYPES:
            raise ValidationError(
                f"Invalid allocation_type {alloc_type!r}",
                details={"allowed": sorted(_VALID_ALLOCATION_TYPES)},
            )

        status_raw = raw.get("status", "active")
        status = (status_raw.value if hasattr(status_raw, "value") else str(status_raw)).strip().lower()
        if status not in _VALID_ALLOCATION_STATUSES:
            raise ValidationError(
                f"Invalid allocation status {status!r}",
                details={"allowed": sorted(_VALID_ALLOCATION_STATUSES)},
            )

        payload: dict[str, Any] = {
            "subnet_id": subnet_id,
            "device_id": device_id,
            "ip_address": ip_str,
            "mac_address": mac_address,
            "hostname": raw.get("hostname"),
            "allocation_type": alloc_type,
            "status": status,
            "last_seen_at": raw.get("last_seen_at") or utcnow(),
        }
        allocation = self.allocations.create(payload, org_id=org_id)
        self.recalculate_subnet_utilization(subnet_id, org_id)
        return allocation

    def get_ip_allocation(self, allocation_id: str, org_id: str) -> IpAllocation:
        """Fetch an IP allocation by ID within tenant scope."""
        return self.allocations.get_by_id_or_raise(allocation_id, org_id=org_id)

    def get_ip_allocation_by_ip(self, ip_address: str, org_id: str) -> IpAllocation | None:
        """Lookup an IP allocation by exact normalized IP address."""
        return self.allocations.get_one_by(filters={"ip_address": normalize_ip(ip_address)}, org_id=org_id)

    def list_ip_allocations(
        self,
        org_id: str,
        *,
        subnet_id: str | None = None,
        device_id: str | None = None,
        status: str | None = None,
        allocation_type: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> PageResult[IpAllocation]:
        """List and paginate IP allocations with optional subnet, device, and status filters."""
        filters: dict[str, Any] = {}
        if subnet_id is not None:
            filters["subnet_id"] = subnet_id
        if device_id is not None:
            filters["device_id"] = device_id
        if status is not None:
            filters["status"] = status.strip().lower()
        if allocation_type is not None:
            filters["allocation_type"] = allocation_type.strip().lower()
        return self.allocations.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            order_by="ip_address",
            org_id=org_id,
        )

    def update_ip_allocation(
        self,
        allocation_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> IpAllocation:
        """Update an IP allocation record and recalculate parent subnet utilization."""
        alloc = self.allocations.get_by_id_or_raise(allocation_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        if "device_id" in raw:
            if raw["device_id"] is not None:
                self.devices.get_by_id_or_raise(str(raw["device_id"]), org_id=org_id)
            patch["device_id"] = raw["device_id"]
        if "mac_address" in raw:
            mac = raw["mac_address"]
            patch["mac_address"] = format_mac(str(mac)) if mac and str(mac).strip() else None
        if "hostname" in raw:
            patch["hostname"] = raw["hostname"]
        if "allocation_type" in raw and raw["allocation_type"] is not None:
            at = (
                raw["allocation_type"].value
                if hasattr(raw["allocation_type"], "value")
                else str(raw["allocation_type"])
            ).strip().lower()
            if at not in _VALID_ALLOCATION_TYPES:
                raise ValidationError(f"Invalid allocation_type {at!r}")
            patch["allocation_type"] = at
        if "status" in raw and raw["status"] is not None:
            st = (raw["status"].value if hasattr(raw["status"], "value") else str(raw["status"])).strip().lower()
            if st not in _VALID_ALLOCATION_STATUSES:
                raise ValidationError(f"Invalid status {st!r}")
            patch["status"] = st
        if "last_seen_at" in raw:
            patch["last_seen_at"] = raw["last_seen_at"]

        updated = self.allocations.update(alloc, patch, org_id=org_id)
        self.recalculate_subnet_utilization(updated.subnet_id, org_id)
        return updated

    def release_ip_allocation(self, allocation_id_or_ip: str, org_id: str) -> bool:
        """Release (delete) an IP allocation by UUID or IP address and update subnet utilization."""
        alloc = self.allocations.get_by_id(allocation_id_or_ip, org_id=org_id)
        if alloc is None and is_valid_ip(allocation_id_or_ip):
            alloc = self.get_ip_allocation_by_ip(allocation_id_or_ip, org_id)
        if alloc is None:
            return False
        subnet_id = alloc.subnet_id
        deleted = self.allocations.delete(alloc, org_id=org_id)
        if deleted:
            self.recalculate_subnet_utilization(subnet_id, org_id)
        return deleted

    def allocate_next_free_ip(
        self,
        org_id: str,
        subnet_id: str,
        *,
        hostname: str | None = None,
        device_id: str | None = None,
        mac_address: str | None = None,
        allocation_type: str = "static",
        status: str = "active",
        skip_gateway: bool = True,
        start_ip: str | None = None,
        end_ip: str | None = None,
        max_scan_hosts: int = 65_536,
    ) -> IpAllocation:
        """Find and allocate the lowest available usable IP address in ``subnet_id``.

        Automatically skips:
        - Network and broadcast addresses (for IPv4 prefix < /31)
        - Subnet ``gateway_ip`` (when ``skip_gateway=True``)
        - All existing :class:`IpAllocation` entries in the subnet
        - Any active :class:`Device` ``management_ip`` already occupying an address in the subnet
        """
        subnet = self.subnets.get_by_id_or_raise(subnet_id, org_id=org_id)
        network = subnet.network

        # Build occupied IP set
        occupied: set[str] = {
            a.ip_address for a in self.allocations.list(filters={"subnet_id": subnet_id}, org_id=org_id)
        }
        if skip_gateway and subnet.gateway_ip:
            occupied.add(subnet.gateway_ip)

        # Also avoid colliding with existing managed device management IPs in the org
        stmt = select(Device.management_ip).where(
            Device.org_id == org_id,
            Device.is_deleted.is_(False),
        )
        for dev_ip in self.db.execute(stmt).scalars().all():
            if subnet.contains_ip(dev_ip):
                occupied.add(dev_ip)

        lower_bound = parse_ip(start_ip) if start_ip else None
        upper_bound = parse_ip(end_ip) if end_ip else None
        if lower_bound is not None and lower_bound not in network:
            raise ValidationError(f"start_ip '{start_ip}' is outside subnet '{subnet.cidr}'")
        if upper_bound is not None and upper_bound not in network:
            raise ValidationError(f"end_ip '{end_ip}' is outside subnet '{subnet.cidr}'")
        if lower_bound is not None and upper_bound is not None and int(lower_bound) > int(upper_bound):
            raise ValidationError("start_ip must be <= end_ip")

        # Determine candidate iterator (safe for large IPv6 subnets via max_scan_hosts bound)
        if isinstance(network, ipaddress.IPv4Network):
            if network.prefixlen in (31, 32):
                first_int = int(network.network_address)
                last_int = int(network.broadcast_address)
            else:
                first_int = int(network.network_address) + 1
                last_int = int(network.broadcast_address) - 1
            if lower_bound is not None:
                first_int = max(first_int, int(lower_bound))
            if upper_bound is not None:
                last_int = min(last_int, int(upper_bound))

            scanned = 0
            chosen_ip: str | None = None
            for ip_int in range(first_int, last_int + 1):
                if scanned >= max_scan_hosts:
                    break
                scanned += 1
                candidate = str(ipaddress.IPv4Address(ip_int))
                if candidate not in occupied:
                    chosen_ip = candidate
                    break
        else:
            first_int = int(network.network_address) + (1 if network.prefixlen < 127 else 0)
            last_int = int(network.broadcast_address)
            if lower_bound is not None:
                first_int = max(first_int, int(lower_bound))
            if upper_bound is not None:
                last_int = min(last_int, int(upper_bound))

            scanned = 0
            chosen_ip = None
            for ip_int in range(first_int, last_int + 1):
                if scanned >= max_scan_hosts:
                    break
                scanned += 1
                candidate = str(ipaddress.IPv6Address(ip_int))
                if candidate not in occupied:
                    chosen_ip = candidate
                    break

        if chosen_ip is None:
            raise ConflictError(
                f"No available IP addresses remaining in subnet '{subnet.cidr}'",
                error_code="SUBNET_EXHAUSTED",
                details={
                    "subnet_id": subnet_id,
                    "cidr": subnet.cidr,
                    "occupied_count": len(occupied),
                },
            )

        return self.create_ip_allocation(
            org_id,
            subnet_id,
            {
                "ip_address": chosen_ip,
                "hostname": hostname,
                "device_id": device_id,
                "mac_address": mac_address,
                "allocation_type": allocation_type,
                "status": status,
            },
            allow_network_or_broadcast=network.prefixlen >= (31 if network.version == 4 else 127),
        )

    def detect_ip_conflicts(
        self,
        org_id: str,
        *,
        subnet_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Detect IP conflicts: duplicate active allocations, explicit conflict status, or MAC mismatches."""
        filters = {"subnet_id": subnet_id} if subnet_id else None
        allocs = self.allocations.list(filters=filters, org_id=org_id)
        conflicts: list[dict[str, Any]] = []

        by_ip: dict[str, list[IpAllocation]] = {}
        for alloc in allocs:
            by_ip.setdefault(alloc.ip_address, []).append(alloc)
            if (alloc.status or "").lower() == "conflict":
                conflicts.append(
                    {
                        "type": "flagged_conflict",
                        "ip_address": alloc.ip_address,
                        "subnet_id": alloc.subnet_id,
                        "allocation_id": alloc.id,
                        "mac_address": alloc.mac_address,
                    }
                )

        for ip_addr, records in by_ip.items():
            if len(records) > 1:
                conflicts.append(
                    {
                        "type": "duplicate_ip",
                        "ip_address": ip_addr,
                        "allocation_ids": [r.id for r in records],
                        "subnet_ids": list(dict.fromkeys(r.subnet_id for r in records)),
                    }
                )

        # Cross-check allocations against managed devices with differing MACs
        devices_by_ip = {d.management_ip: d for d in self.devices.list(org_id=org_id)}
        for alloc in allocs:
            dev = devices_by_ip.get(alloc.ip_address)
            if dev and dev.mac_address and alloc.mac_address and dev.mac_address != alloc.mac_address:
                conflicts.append(
                    {
                        "type": "mac_mismatch",
                        "ip_address": alloc.ip_address,
                        "allocation_id": alloc.id,
                        "allocation_mac": alloc.mac_address,
                        "device_id": dev.id,
                        "device_hostname": dev.hostname,
                        "device_mac": dev.mac_address,
                    }
                )

        return conflicts

    # -----------------------------------------------------------------------
    # DeviceGroups CRUD, Static Membership & Dynamic Filter Evaluation Engine
    # -----------------------------------------------------------------------

    def _validate_dynamic_filter(self, filter_spec: Mapping[str, Any]) -> dict[str, Any]:
        """Validate dynamic group filter definition and normalize structure."""
        if not isinstance(filter_spec, Mapping) or not filter_spec:
            raise ValidationError("Dynamic device groups require a non-empty dynamic_filter_json")

        cleaned = dict(filter_spec)
        if "match_mode" in cleaned:
            mode = str(cleaned["match_mode"]).strip().lower()
            if mode not in {"all", "any"}:
                raise ValidationError("dynamic_filter_json.match_mode must be 'all' or 'any'")
            cleaned["match_mode"] = mode

        if "ip_cidr" in cleaned and cleaned["ip_cidr"] is not None:
            cidrs = cleaned["ip_cidr"] if isinstance(cleaned["ip_cidr"], list) else [cleaned["ip_cidr"]]
            for c in cidrs:
                if not is_valid_cidr(str(c)):
                    raise ValidationError(f"Invalid CIDR in dynamic filter: {c!r}")

        if "rules" in cleaned:
            rules = cleaned["rules"]
            if not isinstance(rules, list):
                raise ValidationError("dynamic_filter_json.rules must be a list of rule objects")
            valid_ops = {
                "eq",
                "ne",
                "in",
                "not_in",
                "contains",
                "icontains",
                "startswith",
                "endswith",
                "regex",
                "glob",
                "gt",
                "gte",
                "lt",
                "lte",
            }
            for idx, rule in enumerate(rules):
                if not isinstance(rule, Mapping) or "field" not in rule:
                    raise ValidationError(f"Dynamic filter rule at index {idx} must include 'field'")
                op = str(rule.get("operator", "eq")).strip().lower()
                if op not in valid_ops:
                    raise ValidationError(
                        f"Unsupported dynamic filter operator {op!r} at rule {idx}",
                        details={"allowed_operators": sorted(valid_ops)},
                    )
        return cleaned

    def create_device_group(
        self,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> DeviceGroup:
        """Create a static or dynamic device group."""
        raw = _coerce_mapping(data)
        name = str(raw.get("name") or "").strip()
        if len(name) < 2:
            raise ValidationError("DeviceGroup name must be at least 2 characters long")

        if self.groups.get_by_name(name, org_id=org_id) is not None:
            raise ConflictError(
                f"DeviceGroup '{name}' already exists in this organization",
                details={"name": name},
            )

        group_type = str(raw.get("group_type") or ("dynamic" if raw.get("is_dynamic") else "static")).strip().lower()
        if group_type not in {"static", "dynamic"}:
            raise ValidationError("group_type must be 'static' or 'dynamic'")

        dynamic_filter = raw.get("dynamic_filter_json")
        if dynamic_filter is None and raw.get("filter_rules"):
            # Convert KeyValueFilter list from schema into structured rules payload
            converted_rules = []
            for r in raw["filter_rules"]:
                converted_rules.append(
                    r.model_dump() if hasattr(r, "model_dump") else dict(r)
                )
            dynamic_filter = {"match_mode": "all", "rules": converted_rules}

        if group_type == "dynamic":
            dynamic_filter = self._validate_dynamic_filter(dynamic_filter or {})
        else:
            dynamic_filter = dict(dynamic_filter or {})

        color = str(raw.get("color") or "#3b82f6").strip().lower()
        if not re.match(r"^#[0-9a-f]{6}$", color):
            raise ValidationError(f"Group color must be a #RRGGBB hex string, got {color!r}")

        group = self.groups.create(
            {
                "name": name,
                "description": raw.get("description"),
                "group_type": group_type,
                "dynamic_filter_json": dynamic_filter,
                "color": color,
            },
            org_id=org_id,
        )

        initial_device_ids = raw.get("device_ids") or []
        if group_type == "static" and initial_device_ids:
            self.add_group_members(group.id, org_id, initial_device_ids)

        return group

    def get_device_group(self, group_id: str, org_id: str) -> DeviceGroup:
        """Fetch an active device group by ID within tenant scope."""
        return self.groups.get_by_id_or_raise(group_id, org_id=org_id)

    def list_device_groups(
        self,
        org_id: str,
        *,
        group_type: str | None = None,
    ) -> list[DeviceGroup]:
        """List device groups in an organization, optionally filtered by static/dynamic type."""
        filters = {"group_type": group_type.lower()} if group_type else None
        return self.groups.list(filters=filters, org_id=org_id)

    def update_device_group(
        self,
        group_id: str,
        org_id: str,
        data: Mapping[str, Any] | Any,
    ) -> DeviceGroup:
        """Update a device group's metadata, type, or dynamic filter specification."""
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        raw = _coerce_mapping(data)
        patch: dict[str, Any] = {}

        if "name" in raw and raw["name"] is not None:
            new_name = str(raw["name"]).strip()
            if len(new_name) < 2:
                raise ValidationError("DeviceGroup name must be at least 2 characters long")
            existing = self.groups.get_by_name(new_name, org_id=org_id)
            if existing is not None and existing.id != group.id:
                raise ConflictError(f"DeviceGroup '{new_name}' already exists")
            patch["name"] = new_name

        if "description" in raw:
            patch["description"] = raw["description"]

        if "color" in raw and raw["color"] is not None:
            color = str(raw["color"]).strip().lower()
            if not re.match(r"^#[0-9a-f]{6}$", color):
                raise ValidationError(f"Group color must be a #RRGGBB hex string, got {color!r}")
            patch["color"] = color

        effective_type = group.group_type
        if "group_type" in raw and raw["group_type"] is not None:
            effective_type = str(raw["group_type"]).strip().lower()
            if effective_type not in {"static", "dynamic"}:
                raise ValidationError("group_type must be 'static' or 'dynamic'")
            patch["group_type"] = effective_type
        elif "is_dynamic" in raw and raw["is_dynamic"] is not None:
            effective_type = "dynamic" if raw["is_dynamic"] else "static"
            patch["group_type"] = effective_type

        if "dynamic_filter_json" in raw and raw["dynamic_filter_json"] is not None:
            flt = raw["dynamic_filter_json"]
            patch["dynamic_filter_json"] = (
                self._validate_dynamic_filter(flt) if effective_type == "dynamic" else dict(flt)
            )
        elif "filter_rules" in raw and raw["filter_rules"] is not None:
            rules = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in raw["filter_rules"]]
            flt = {"match_mode": "all", "rules": rules}
            patch["dynamic_filter_json"] = (
                self._validate_dynamic_filter(flt) if effective_type == "dynamic" else flt
            )
        elif effective_type == "dynamic" and not group.dynamic_filter_json:
            raise ValidationError("Switching group to 'dynamic' requires dynamic_filter_json")

        return self.groups.update(group, patch, org_id=org_id)

    def delete_device_group(self, group_id: str, org_id: str) -> DeviceGroup:
        """Soft-delete a device group."""
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        return self.groups.soft_delete(group, org_id=org_id)

    def add_group_members(
        self,
        group_id: str,
        org_id: str,
        device_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Add one or more verified tenant devices to a static device group."""
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        if group.is_dynamic:
            raise ValidationError(
                f"Cannot manually add static members to dynamic group '{group.name}'"
            )

        unique_ids = list(dict.fromkeys(str(did) for did in device_ids))
        found_devices = self.devices.get_many_by_ids(unique_ids, org_id=org_id)
        found_ids = {d.id for d in found_devices}
        missing = [did for did in unique_ids if did not in found_ids]
        if missing:
            raise NotFoundError(
                f"One or more devices were not found in organization: {', '.join(missing)}",
                details={"missing_device_ids": missing},
            )

        added_count = self.groups.add_members(group.id, unique_ids, org_id=org_id)
        total_members = len(self.groups.list_member_device_ids(group.id, org_id=org_id))
        return {
            "group_id": group.id,
            "added_count": added_count,
            "total_members": total_members,
        }

    def remove_group_members(
        self,
        group_id: str,
        org_id: str,
        device_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Remove one or more devices from a static device group."""
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        if group.is_dynamic:
            raise ValidationError(
                f"Cannot manually remove static members from dynamic group '{group.name}'"
            )
        removed_count = 0
        for did in dict.fromkeys(str(d) for d in device_ids):
            if self.groups.remove_member(group.id, did, org_id=org_id):
                removed_count += 1
        total_members = len(self.groups.list_member_device_ids(group.id, org_id=org_id))
        return {
            "group_id": group.id,
            "removed_count": removed_count,
            "total_members": total_members,
        }

    def _evaluate_rule(self, device: Device, rule: Mapping[str, Any]) -> bool:
        """Evaluate a single structured rule ``{field, operator, value}`` against a device."""
        field_name = str(rule.get("field") or rule.get("key") or "").strip()
        op = str(rule.get("operator") or "eq").strip().lower()
        expected = rule.get("value")

        # Resolve field value (supporting custom_fields.<key> and tags)
        if field_name.startswith("custom_fields."):
            cf_key = field_name.split(".", 1)[1]
            actual: Any = (device.custom_fields_json or {}).get(cf_key)
        elif field_name == "tags":
            actual = list(device.tags_json or [])
        else:
            actual = getattr(device, field_name, None)

        if op == "eq":
            if isinstance(actual, list):
                return expected in actual
            return actual == expected
        if op == "ne":
            if isinstance(actual, list):
                return expected not in actual
            return actual != expected
        if op == "in":
            seq = expected if isinstance(expected, (list, tuple, set)) else [expected]
            if isinstance(actual, list):
                return bool(set(actual) & set(seq))
            return actual in seq
        if op == "not_in":
            seq = expected if isinstance(expected, (list, tuple, set)) else [expected]
            if isinstance(actual, list):
                return not bool(set(actual) & set(seq))
            return actual not in seq
        if op in {"contains", "icontains"}:
            if actual is None:
                return False
            if isinstance(actual, list):
                needle = str(expected).lower() if op == "icontains" else str(expected)
                return any(
                    (needle in str(item).lower()) if op == "icontains" else (needle in str(item))
                    for item in actual
                )
            if op == "icontains":
                return str(expected).lower() in str(actual).lower()
            return str(expected) in str(actual)
        if op == "startswith":
            return actual is not None and str(actual).lower().startswith(str(expected).lower())
        if op == "endswith":
            return actual is not None and str(actual).lower().endswith(str(expected).lower())
        if op == "glob":
            return actual is not None and fnmatch.fnmatchcase(str(actual), str(expected))
        if op == "regex":
            if actual is None:
                return False
            try:
                return re.search(str(expected), str(actual)) is not None
            except re.error:
                return False
        if op in {"gt", "gte", "lt", "lte"}:
            if actual is None or expected is None:
                return False
            try:
                a_num, e_num = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            if op == "gt":
                return a_num > e_num
            if op == "gte":
                return a_num >= e_num
            if op == "lt":
                return a_num < e_num
            return a_num <= e_num
        return False

    def _device_matches_filter(self, device: Device, flt: Mapping[str, Any] | None) -> bool:
        """Evaluate a full dynamic group filter dictionary against a single device."""
        if not isinstance(flt, Mapping) or not flt:
            return False

        match_mode = str(flt.get("match_mode", "all")).strip().lower()
        checks: list[bool] = []

        # Standard attribute filters (scalar or list of allowed values)
        for attr in ("device_type", "vendor", "status", "site_id", "rack_id"):
            if attr in flt and flt[attr] is not None:
                expected = flt[attr]
                actual = getattr(device, attr, None)
                if isinstance(expected, (list, tuple, set)):
                    checks.append(actual in expected)
                else:
                    checks.append(actual == expected)

        for bool_attr in ("polling_enabled", "snmp_enabled", "icmp_enabled"):
            if bool_attr in flt and flt[bool_attr] is not None:
                checks.append(bool(getattr(device, bool_attr, False)) is bool(flt[bool_attr]))

        # Glob pattern filters
        for pattern_key, dev_attr in (
            ("hostname_pattern", "hostname"),
            ("model_pattern", "model"),
            ("os_version_pattern", "os_version"),
        ):
            pat = flt.get(pattern_key)
            if pat:
                val = getattr(device, dev_attr, None) or ""
                checks.append(fnmatch.fnmatchcase(str(val), str(pat)))

        # Tag filters: tags (AND / all required) & tags_any (OR / any required)
        if flt.get("tags"):
            req = flt["tags"]
            req_set = {req} if isinstance(req, str) else set(req)
            checks.append(req_set.issubset(set(device.tags_json or [])))

        if flt.get("tags_any"):
            any_tags = flt["tags_any"]
            any_set = {any_tags} if isinstance(any_tags, str) else set(any_tags)
            checks.append(bool(any_set & set(device.tags_json or [])))

        # CIDR containment filter
        if flt.get("ip_cidr"):
            cidrs = flt["ip_cidr"] if isinstance(flt["ip_cidr"], list) else [flt["ip_cidr"]]
            checks.append(any(ip_in_cidr(device.management_ip, str(c)) for c in cidrs))

        # Custom field exact matches
        if isinstance(flt.get("custom_fields"), Mapping):
            dev_cf = device.custom_fields_json or {}
            for k, v in flt["custom_fields"].items():
                checks.append(dev_cf.get(k) == v)

        # Structured rules list
        if isinstance(flt.get("rules"), list):
            for rule in flt["rules"]:
                if isinstance(rule, Mapping):
                    checks.append(self._evaluate_rule(device, rule))

        if not checks:
            return False
        return any(checks) if match_mode == "any" else all(checks)

    def evaluate_dynamic_group(
        self,
        group_id: str,
        org_id: str,
        *,
        sync_members: bool = False,
    ) -> list[Device]:
        """Evaluate a dynamic group's filter expression across all org devices.

        When ``sync_members=True``, synchronizes ``device_group_members`` rows to
        cache the evaluated membership set.
        """
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        if not group.is_dynamic:
            return self.groups.list_members(group.id, org_id=org_id)

        all_devices = self.devices.list(org_id=org_id)
        matched = [
            dev for dev in all_devices if self._device_matches_filter(dev, group.dynamic_filter_json)
        ]

        if sync_members:
            desired_ids = {d.id for d in matched}
            current_ids = set(self.groups.list_member_device_ids(group.id, org_id=org_id))
            to_add = sorted(desired_ids - current_ids)
            to_remove = sorted(current_ids - desired_ids)
            if to_add:
                self.groups.add_members(group.id, to_add, org_id=org_id)
            for rid in to_remove:
                self.groups.remove_member(group.id, rid, org_id=org_id)

        return matched

    def get_group_members(self, group_id: str, org_id: str) -> list[Device]:
        """Return effective member devices for either a static or dynamic device group."""
        group = self.groups.get_by_id_or_raise(group_id, org_id=org_id)
        if group.is_dynamic:
            return self.evaluate_dynamic_group(group.id, org_id)
        return self.groups.list_members(group.id, org_id=org_id)

    def list_device_groups_with_counts(self, org_id: str) -> list[dict[str, Any]]:
        """List all device groups annotated with effective member and healthy device counts."""
        groups = self.groups.list(org_id=org_id)
        results: list[dict[str, Any]] = []
        for grp in groups:
            members = self.get_group_members(grp.id, org_id)
            up_count = sum(1 for d in members if d.status == DeviceStatus.UP.value)
            results.append(
                {
                    "id": grp.id,
                    "org_id": grp.org_id,
                    "name": grp.name,
                    "description": grp.description,
                    "group_type": grp.group_type,
                    "dynamic_filter_json": dict(grp.dynamic_filter_json or {}),
                    "color": grp.color,
                    "member_count": len(members),
                    "up_count": up_count,
                    "device_ids": [d.id for d in members],
                }
            )
        return results


__all__ = [
    "ALLOWED_STATUS_TRANSITIONS",
    "DeviceStatusTransition",
    "InventoryService",
    "infer_vendor_from_mac",
    "normalize_device_status",
    "normalize_device_type",
    "normalize_device_vendor",
    "normalize_interface_type",
    "normalize_tags",
]
