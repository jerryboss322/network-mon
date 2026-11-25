"""CMDB, network inventory, IPAM, and device grouping ORM models.

Models the physical, logical, and credential hierarchy managed by NetPulse:
- :class:`Site`: Physical data centers, POPs, campuses, or cloud regions.
- :class:`Rack`: Equipment cabinets inside a site with U-height and power budgets.
- :class:`CredentialProfile`: Vault-encrypted SNMP/SSH/API polling credentials.
- :class:`Device`: Managed routers, switches, firewalls, servers, and appliances.
- :class:`DeviceInterface`: L1/L2/L3 interfaces with SNMP counter and utilization tracking.
- :class:`Subnet`: IPAM IPv4/IPv6 CIDR prefixes with utilization and scan controls.
- :class:`Vlan`: Layer-2 VLAN catalog scoped to sites and organizations.
- :class:`IpAllocation`: Individual IP address leases, static assignments, and ARP records.
- :class:`DeviceGroup`: Static or dynamic tag/filter-driven operational device groups.
- :class:`DeviceGroupMember`: Association table linking devices to groups.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    utcnow,
)
from app.models.enums import (
    CredentialType,
    DeviceStatus,
    DeviceType,
    DeviceVendor,
    DuplexMode,
    InterfaceStatus,
    InterfaceType,
    SnmpVersion,
)
# Ensure Organization table is registered in Base.metadata when inventory is imported directly.
from app.models.identity import Organization  # noqa: F401

_HEX_STRIP_RE = re.compile(r"[^0-9a-fA-F]")
_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_SITE_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _as_utc(dt: datetime | None) -> datetime | None:
    """Normalize naive timestamps to timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_mac_address(raw: str | None) -> str | None:
    """Normalize a MAC address in colon, hyphen, Cisco dot, or bare hex notation.

    Returns canonical lowercase colon-delimited format (``aa:bb:cc:dd:ee:ff``),
    or ``None`` if *raw* is ``None`` or blank.
    """
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    hex_digits = _HEX_STRIP_RE.sub("", stripped).lower()
    if len(hex_digits) != 12:
        raise ValueError(f"Invalid MAC address {raw!r}: expected 12 hexadecimal digits")
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))


def normalize_ip_address(raw: str | None) -> str | None:
    """Validate and canonicalize an IPv4 or IPv6 address string."""
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    return str(ipaddress.ip_address(stripped))


class Site(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Physical location, data center, POP, branch office, or cloud region."""

    __tablename__ = "sites"
    __table_args__ = (
        UniqueConstraint("org_id", "code", name="uq_sites_org_code"),
        CheckConstraint(
            "latitude IS NULL OR (latitude >= -90.0 AND latitude <= 90.0)",
            name="site_latitude_range",
        ),
        CheckConstraint(
            "longitude IS NULL OR (longitude >= -180.0 AND longitude <= 180.0)",
            name="site_longitude_range",
        ),
        Index("ix_sites_org_region", "org_id", "region"),
        Index("ix_sites_org_tier", "org_id", "tier"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    address: Mapped[str | None] = mapped_column(String(512), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    contact_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tier: Mapped[str] = mapped_column(String(32), default="standard", nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    racks: Mapped[list[Rack]] = relationship(
        "Rack",
        back_populates="site",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    devices: Mapped[list[Device]] = relationship(
        "Device",
        back_populates="site",
    )
    subnets: Mapped[list[Subnet]] = relationship(
        "Subnet",
        back_populates="site",
    )
    vlans: Mapped[list[Vlan]] = relationship(
        "Vlan",
        back_populates="site",
    )

    @validates("code")
    def _validate_code(self, _key: str, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned or not _SITE_CODE_RE.match(cleaned):
            raise ValueError(f"Invalid site code {value!r}")
        return cleaned

    @validates("latitude")
    def _validate_latitude(self, _key: str, value: float | None) -> float | None:
        if value is not None and not (-90.0 <= value <= 90.0):
            raise ValueError(f"Latitude must be between -90 and 90, got {value}")
        return value

    @validates("longitude")
    def _validate_longitude(self, _key: str, value: float | None) -> float | None:
        if value is not None and not (-180.0 <= value <= 180.0):
            raise ValueError(f"Longitude must be between -180 and 180, got {value}")
        return value

    @property
    def has_coordinates(self) -> bool:
        """Return ``True`` if both latitude and longitude are populated."""
        return self.latitude is not None and self.longitude is not None

    @property
    def coordinates(self) -> tuple[float, float] | None:
        """Return ``(latitude, longitude)`` if available."""
        if not self.has_coordinates:
            return None
        return (float(self.latitude), float(self.longitude))  # type: ignore[arg-type]

    def distance_km_to(self, other: Site) -> float | None:
        """Calculate great-circle Haversine distance in kilometers to *other*."""
        if not self.has_coordinates or not other.has_coordinates:
            return None
        lat1 = math.radians(float(self.latitude))  # type: ignore[arg-type]
        lon1 = math.radians(float(self.longitude))  # type: ignore[arg-type]
        lat2 = math.radians(float(other.latitude))  # type: ignore[arg-type]
        lon2 = math.radians(float(other.longitude))  # type: ignore[arg-type]
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat / 2.0) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2.0) ** 2
        return 6371.0088 * 2.0 * math.asin(min(1.0, math.sqrt(a)))

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a concise JSON-serializable summary for topology maps and lists."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "code": self.code,
            "region": self.region,
            "country": self.country,
            "city": self.city,
            "timezone": self.timezone,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "tier": self.tier,
        }

    def __repr__(self) -> str:
        return f"<Site id={self.id!r} code={self.code!r} name={self.name!r}>"


class Rack(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Physical equipment rack inside a :class:`Site`."""

    __tablename__ = "racks"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_racks_site_name"),
        CheckConstraint("total_u >= 1 AND total_u <= 100", name="rack_total_u_range"),
        CheckConstraint(
            "power_capacity_watts IS NULL OR power_capacity_watts >= 0",
            name="rack_power_non_negative",
        ),
        Index("ix_racks_org_site", "org_id", "site_id"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("sites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    aisle: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row: Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_u: Mapped[int] = mapped_column(Integer, default=42, nullable=False)
    power_capacity_watts: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cooling_zone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    site: Mapped[Site] = relationship("Site", back_populates="racks")
    devices: Mapped[list[Device]] = relationship("Device", back_populates="rack")

    @validates("total_u")
    def _validate_total_u(self, _key: str, value: int) -> int:
        if not (1 <= value <= 100):
            raise ValueError(f"Rack total_u must be between 1 and 100, got {value}")
        return value

    def occupied_unit_slots(self) -> set[int]:
        """Return the set of occupied rack-unit indices across active mounted devices."""
        occupied: set[int] = set()
        for dev in self.devices:
            if dev.is_deleted or dev.rack_unit_start is None:
                continue
            height = dev.rack_unit_height or 1
            for unit in range(dev.rack_unit_start, dev.rack_unit_start + height):
                occupied.add(unit)
        return occupied

    def can_fit_device(
        self,
        unit_start: int,
        unit_height: int = 1,
        *,
        exclude_device_id: str | None = None,
    ) -> bool:
        """Return ``True`` if a device of *unit_height* fits at *unit_start* without collision."""
        total = self.total_u if self.total_u is not None else 42
        if unit_start < 1 or unit_height < 1:
            return False
        if unit_start + unit_height - 1 > total:
            return False
        requested = set(range(unit_start, unit_start + unit_height))
        for dev in self.devices:
            if dev.is_deleted or dev.id == exclude_device_id or dev.rack_unit_start is None:
                continue
            height = dev.rack_unit_height or 1
            existing = set(range(dev.rack_unit_start, dev.rack_unit_start + height))
            if requested & existing:
                return False
        return True

    def utilization_pct(self) -> float:
        """Compute percentage of rack units currently occupied."""
        total = self.total_u if self.total_u is not None else 42
        if total <= 0:
            return 0.0
        used = len(self.occupied_unit_slots())
        return round(min(100.0, (used / total) * 100.0), 2)

    def __repr__(self) -> str:
        return f"<Rack id={self.id!r} site_id={self.site_id!r} name={self.name!r} total_u={self.total_u}>"


class CredentialProfile(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Encrypted polling and management credential bundle reusable across devices."""

    __tablename__ = "credential_profiles"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_credential_profiles_org_name"),
        CheckConstraint("port >= 1 AND port <= 65535", name="credential_port_range"),
        CheckConstraint("timeout_seconds > 0", name="credential_timeout_positive"),
        CheckConstraint("retries >= 0 AND retries <= 10", name="credential_retries_range"),
        Index("ix_credential_profiles_org_type", "org_id", "credential_type"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_type: Mapped[str] = mapped_column(
        String(32),
        default=CredentialType.SNMP_V2C.value,
        nullable=False,
        index=True,
    )
    snmp_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=161, nullable=False)
    timeout_seconds: Mapped[float] = mapped_column(Float, default=3.0, nullable=False)
    retries: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    devices: Mapped[list[Device]] = relationship(
        "Device",
        back_populates="credential_profile",
    )

    @validates("credential_type")
    def _validate_credential_type(self, _key: str, value: str | CredentialType) -> str:
        if isinstance(value, CredentialType):
            return value.value
        return CredentialType(value.strip().lower()).value

    @validates("snmp_version")
    def _validate_snmp_version(self, _key: str, value: str | SnmpVersion | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, SnmpVersion):
            return value.value
        cleaned = value.strip().lower()
        if not cleaned:
            return None
        return SnmpVersion(cleaned).value

    @validates("port")
    def _validate_port(self, _key: str, value: int) -> int:
        if not (1 <= value <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {value}")
        return value

    @property
    def is_snmp(self) -> bool:
        """Return ``True`` if this profile represents an SNMP credential."""
        return self.credential_type in {
            CredentialType.SNMP_V1.value,
            CredentialType.SNMP_V2C.value,
            CredentialType.SNMP_V3.value,
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        """Serialize credential metadata without exposing ``encrypted_payload``."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "credential_type": self.credential_type,
            "snmp_version": self.snmp_version,
            "port": self.port,
            "timeout_seconds": self.timeout_seconds,
            "retries": self.retries,
            "is_default": self.is_default,
            "has_secret": bool(self.encrypted_payload),
        }

    def __repr__(self) -> str:
        return (
            f"<CredentialProfile id={self.id!r} name={self.name!r} "
            f"type={self.credential_type!r} port={self.port}>"
        )


class Device(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Primary CMDB managed network device, server, firewall, or appliance."""

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("org_id", "hostname", name="uq_devices_org_hostname"),
        CheckConstraint("polling_interval_seconds >= 5", name="device_polling_interval_min"),
        CheckConstraint(
            "rack_unit_start IS NULL OR rack_unit_start >= 1",
            name="device_rack_u_start_min",
        ),
        CheckConstraint(
            "rack_unit_height IS NULL OR rack_unit_height >= 1",
            name="device_rack_u_height_min",
        ),
        CheckConstraint(
            "uptime_seconds IS NULL OR uptime_seconds >= 0",
            name="device_uptime_non_negative",
        ),
        Index("ix_devices_org_status", "org_id", "status"),
        Index("ix_devices_org_site_status", "org_id", "site_id", "status"),
        Index("ix_devices_org_ip", "org_id", "management_ip"),
        Index("ix_devices_org_type_vendor", "org_id", "device_type", "vendor"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("sites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rack_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("racks.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    credential_profile_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("credential_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    management_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    secondary_ips_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    device_type: Mapped[str] = mapped_column(
        String(32),
        default=DeviceType.UNKNOWN.value,
        nullable=False,
        index=True,
    )
    vendor: Mapped[str] = mapped_column(
        String(32),
        default=DeviceVendor.UNKNOWN.value,
        nullable=False,
        index=True,
    )
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    asset_tag: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    rack_unit_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rack_unit_height: Mapped[int | None] = mapped_column(Integer, default=1, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32),
        default=DeviceStatus.UNKNOWN.value,
        nullable=False,
        index=True,
    )
    polling_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    snmp_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    icmp_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    polling_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    tags_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    custom_fields_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    sys_descr: Mapped[str | None] = mapped_column(Text, nullable=True)
    sys_object_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sys_location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sys_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    last_polled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    site: Mapped[Site | None] = relationship("Site", back_populates="devices")
    rack: Mapped[Rack | None] = relationship("Rack", back_populates="devices")
    credential_profile: Mapped[CredentialProfile | None] = relationship(
        "CredentialProfile",
        back_populates="devices",
    )
    interfaces: Mapped[list[DeviceInterface]] = relationship(
        "DeviceInterface",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    ip_allocations: Mapped[list[IpAllocation]] = relationship(
        "IpAllocation",
        back_populates="device",
    )
    group_memberships: Mapped[list[DeviceGroupMember]] = relationship(
        "DeviceGroupMember",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("management_ip")
    def _validate_management_ip(self, _key: str, value: str) -> str:
        normalized = normalize_ip_address(value)
        if normalized is None:
            raise ValueError("Device management_ip must not be empty")
        return normalized

    @validates("mac_address")
    def _validate_mac(self, _key: str, value: str | None) -> str | None:
        return normalize_mac_address(value)

    @validates("device_type")
    def _validate_device_type(self, _key: str, value: str | DeviceType) -> str:
        if isinstance(value, DeviceType):
            return value.value
        return DeviceType(value.strip().lower()).value

    @validates("vendor")
    def _validate_vendor(self, _key: str, value: str | DeviceVendor) -> str:
        if isinstance(value, DeviceVendor):
            return value.value
        return DeviceVendor(value.strip().lower()).value

    @validates("status")
    def _validate_status(self, _key: str, value: str | DeviceStatus) -> str:
        if isinstance(value, DeviceStatus):
            return value.value
        return DeviceStatus(value.strip().lower()).value

    @property
    def is_up(self) -> bool:
        """Return ``True`` if the device is currently reported ``up``."""
        return self.status == DeviceStatus.UP.value

    @property
    def is_in_maintenance(self) -> bool:
        """Return ``True`` if the device is placed in maintenance mode."""
        return self.status == DeviceStatus.MAINTENANCE.value

    @property
    def all_ips(self) -> list[str]:
        """Return the deduplicated list of management and secondary IP addresses."""
        ips = [self.management_ip]
        for extra in self.secondary_ips_json or []:
            if extra and extra not in ips:
                ips.append(extra)
        return ips

    @property
    def uptime_human(self) -> str | None:
        """Format ``uptime_seconds`` as a human-readable ``Xd Xh Xm`` string."""
        if self.uptime_seconds is None:
            return None
        total = int(self.uptime_seconds)
        days, rem = divmod(total, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m {seconds}s"

    def is_stale(self, *, multiplier: float = 3.0, now: datetime | None = None) -> bool:
        """Return ``True`` when an active device has missed *multiplier* poll cycles."""
        polling_enabled = True if self.polling_enabled is None else self.polling_enabled
        if not polling_enabled:
            return False
        last = _as_utc(self.last_polled_at)
        if last is None:
            return True
        reference = _as_utc(now) or utcnow()
        interval = self.polling_interval_seconds if self.polling_interval_seconds is not None else 60
        max_age = timedelta(seconds=max(5, interval) * multiplier)
        return (reference - last) > max_age

    def has_tag(self, tag: str) -> bool:
        """Return ``True`` if *tag* is attached to ``tags_json``."""
        return tag in (self.tags_json or [])

    def add_tag(self, tag: str) -> None:
        """Attach *tag* idempotently using copy-on-write list replacement."""
        cleaned = tag.strip()
        if not cleaned:
            return
        current = list(self.tags_json or [])
        if cleaned not in current:
            current.append(cleaned)
            self.tags_json = current

    def remove_tag(self, tag: str) -> None:
        """Detach *tag* if present."""
        current = list(self.tags_json or [])
        if tag in current:
            current.remove(tag)
            self.tags_json = current

    def mark_polled(
        self,
        *,
        status: DeviceStatus | str,
        uptime_seconds: int | None = None,
        now: datetime | None = None,
    ) -> None:
        """Update status and polling/reachability timestamps after a collector cycle."""
        reference = _as_utc(now) or utcnow()
        resolved = status.value if isinstance(status, DeviceStatus) else DeviceStatus(status).value
        self.status = resolved
        self.last_polled_at = reference
        if resolved in {
            DeviceStatus.UP.value,
            DeviceStatus.DEGRADED.value,
            DeviceStatus.WARNING.value,
        }:
            self.last_seen_at = reference
        if uptime_seconds is not None and uptime_seconds >= 0:
            self.uptime_seconds = uptime_seconds

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a concise representation for inventory tables and topology nodes."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "site_id": self.site_id,
            "hostname": self.hostname,
            "management_ip": self.management_ip,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "model": self.model,
            "status": self.status,
            "tags": list(self.tags_json or []),
            "uptime_seconds": self.uptime_seconds,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Device id={self.id!r} hostname={self.hostname!r} "
            f"ip={self.management_ip!r} status={self.status!r}>"
        )


class DeviceInterface(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Physical or logical interface belonging to a :class:`Device`."""

    __tablename__ = "device_interfaces"
    __table_args__ = (
        UniqueConstraint("device_id", "if_index", name="uq_device_interfaces_device_if_index"),
        CheckConstraint("if_index >= 0", name="interface_if_index_non_negative"),
        CheckConstraint(
            "speed_mbps IS NULL OR speed_mbps >= 0",
            name="interface_speed_non_negative",
        ),
        CheckConstraint("mtu IS NULL OR mtu >= 68", name="interface_mtu_min"),
        CheckConstraint(
            "vlan_id IS NULL OR (vlan_id >= 1 AND vlan_id <= 4094)",
            name="interface_vlan_range",
        ),
        Index("ix_device_interfaces_org_device", "org_id", "device_id"),
        Index("ix_device_interfaces_device_name", "device_id", "name"),
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
    if_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    alias: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    subnet_mask: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    interface_type: Mapped[str] = mapped_column(
        String(32),
        default=InterfaceType.ETHERNET.value,
        nullable=False,
    )
    speed_mbps: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, default=1500, nullable=True)
    admin_status: Mapped[str] = mapped_column(
        String(32),
        default=InterfaceStatus.UP.value,
        nullable=False,
    )
    oper_status: Mapped[str] = mapped_column(
        String(32),
        default=InterfaceStatus.UNKNOWN.value,
        nullable=False,
        index=True,
    )
    duplex: Mapped[str] = mapped_column(
        String(16),
        default=DuplexMode.UNKNOWN.value,
        nullable=False,
    )
    is_monitored: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_uplink: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    in_octets_last: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    out_octets_last: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    in_errors_last: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    out_errors_last: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    utilization_in_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    utilization_out_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Relationships
    device: Mapped[Device] = relationship("Device", back_populates="interfaces")

    @validates("mac_address")
    def _validate_mac(self, _key: str, value: str | None) -> str | None:
        return normalize_mac_address(value)

    @validates("ip_address")
    def _validate_ip(self, _key: str, value: str | None) -> str | None:
        return normalize_ip_address(value)

    @validates("admin_status", "oper_status")
    def _validate_status(self, _key: str, value: str | InterfaceStatus) -> str:
        if isinstance(value, InterfaceStatus):
            return value.value
        return InterfaceStatus(value.strip().lower()).value

    @validates("duplex")
    def _validate_duplex(self, _key: str, value: str | DuplexMode) -> str:
        if isinstance(value, DuplexMode):
            return value.value
        return DuplexMode(value.strip().lower()).value

    @property
    def is_up(self) -> bool:
        """Return ``True`` if both admin and operational status are ``up``."""
        admin = self.admin_status or InterfaceStatus.UP.value
        return (
            admin == InterfaceStatus.UP.value
            and self.oper_status == InterfaceStatus.UP.value
        )

    @property
    def max_utilization_pct(self) -> float:
        """Return the higher of ingress and egress utilization percentages."""
        return max(self.utilization_in_pct or 0.0, self.utilization_out_pct or 0.0)

    @staticmethod
    def compute_counter_delta(
        previous: int | None,
        current: int,
        *,
        counter_bits: int = 64,
    ) -> int | None:
        """Compute non-negative counter delta handling 32-bit or 64-bit wrap-around."""
        if previous is None or current < 0:
            return None
        if current >= previous:
            return current - previous
        modulus = 1 << counter_bits
        # Guard against device reboot resetting counter near zero rather than true wrap
        if counter_bits == 64 and previous < (modulus // 2):
            return current
        return (modulus - previous) + current

    def update_counters(
        self,
        *,
        in_octets: int,
        out_octets: int,
        interval_seconds: float,
        in_errors: int | None = None,
        out_errors: int | None = None,
        counter_bits: int = 64,
    ) -> tuple[float, float]:
        """Update SNMP octet/error counters and recalculate ingress/egress utilization.

        Returns ``(in_bps, out_bps)`` computed over *interval_seconds*.
        """
        in_delta = self.compute_counter_delta(
            self.in_octets_last, in_octets, counter_bits=counter_bits
        )
        out_delta = self.compute_counter_delta(
            self.out_octets_last, out_octets, counter_bits=counter_bits
        )

        self.in_octets_last = in_octets
        self.out_octets_last = out_octets
        if in_errors is not None:
            self.in_errors_last = in_errors
        if out_errors is not None:
            self.out_errors_last = out_errors

        if interval_seconds <= 0 or in_delta is None or out_delta is None:
            return (0.0, 0.0)

        in_bps = (in_delta * 8.0) / interval_seconds
        out_bps = (out_delta * 8.0) / interval_seconds

        if self.speed_mbps and self.speed_mbps > 0:
            capacity_bps = self.speed_mbps * 1_000_000.0
            self.utilization_in_pct = round(min(100.0, (in_bps / capacity_bps) * 100.0), 2)
            self.utilization_out_pct = round(min(100.0, (out_bps / capacity_bps) * 100.0), 2)
        else:
            self.utilization_in_pct = 0.0
            self.utilization_out_pct = 0.0

        return (in_bps, out_bps)

    def __repr__(self) -> str:
        return (
            f"<DeviceInterface id={self.id!r} device_id={self.device_id!r} "
            f"name={self.name!r} oper={self.oper_status!r}>"
        )


class Subnet(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """IPAM subnet prefix tracked for utilization, gateway config, and discovery."""

    __tablename__ = "subnets"
    __table_args__ = (
        UniqueConstraint("org_id", "cidr", name="uq_subnets_org_cidr"),
        CheckConstraint(
            "vlan_number IS NULL OR (vlan_number >= 1 AND vlan_number <= 4094)",
            name="subnet_vlan_range",
        ),
        CheckConstraint(
            "utilization_pct >= 0.0 AND utilization_pct <= 100.0",
            name="subnet_utilization_range",
        ),
        Index("ix_subnets_org_site", "org_id", "site_id"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("sites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    cidr: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    gateway_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan_number: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    dns_servers_json: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    utilization_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    scan_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    site: Mapped[Site | None] = relationship("Site", back_populates="subnets")
    ip_allocations: Mapped[list[IpAllocation]] = relationship(
        "IpAllocation",
        back_populates="subnet",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("cidr")
    def _validate_cidr(self, _key: str, value: str) -> str:
        net = ipaddress.ip_network(value.strip(), strict=False)
        return str(net)

    @validates("gateway_ip")
    def _validate_gateway(self, _key: str, value: str | None) -> str | None:
        return normalize_ip_address(value)

    @validates("vlan_number")
    def _validate_vlan_number(self, _key: str, value: int | None) -> int | None:
        if value is not None and not (1 <= value <= 4094):
            raise ValueError(f"VLAN number must be between 1 and 4094, got {value}")
        return value

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Parse ``cidr`` into a stdlib :mod:`ipaddress` network object."""
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def total_usable_hosts(self) -> int:
        """Return usable host address count (handling /31, /32, and IPv6 prefixes)."""
        net = self.network
        if net.version == 4:
            if net.prefixlen == 32:
                return 1
            if net.prefixlen == 31:
                return 2
            return max(0, net.num_addresses - 2)
        return net.num_addresses

    def contains_ip(self, ip_str: str) -> bool:
        """Return ``True`` if *ip_str* falls inside this subnet's CIDR block."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False
        net = self.network
        return addr.version == net.version and addr in net

    def overlaps_cidr(self, other_cidr: str) -> bool:
        """Return ``True`` if *other_cidr* overlaps this subnet's address space."""
        other = ipaddress.ip_network(other_cidr.strip(), strict=False)
        net = self.network
        return other.version == net.version and net.overlaps(other)

    def recalculate_utilization(self, allocated_count: int) -> float:
        """Update and return ``utilization_pct`` from *allocated_count*."""
        usable = self.total_usable_hosts
        if usable <= 0:
            self.utilization_pct = 0.0
            return 0.0
        pct = min(100.0, max(0.0, (allocated_count / usable) * 100.0))
        self.utilization_pct = round(pct, 2)
        return self.utilization_pct

    def __repr__(self) -> str:
        return f"<Subnet id={self.id!r} cidr={self.cidr!r} name={self.name!r}>"


class Vlan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Layer-2 IEEE 802.1Q VLAN definition scoped to an organization and optional site."""

    __tablename__ = "vlans"
    __table_args__ = (
        UniqueConstraint("org_id", "site_id", "vlan_id_num", name="uq_vlans_org_site_num"),
        CheckConstraint(
            "vlan_id_num >= 1 AND vlan_id_num <= 4094",
            name="vlan_id_num_range",
        ),
        Index("ix_vlans_org_site", "org_id", "site_id"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("sites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    vlan_id_num: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    subnet_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Relationships
    site: Mapped[Site | None] = relationship("Site", back_populates="vlans")

    @validates("vlan_id_num")
    def _validate_vlan_id(self, _key: str, value: int) -> int:
        if not (1 <= value <= 4094):
            raise ValueError(f"IEEE 802.1Q VLAN ID must be in 1..4094, got {value}")
        return value

    @validates("subnet_cidr")
    def _validate_subnet_cidr(self, _key: str, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return str(ipaddress.ip_network(value.strip(), strict=False))

    @property
    def is_extended_range(self) -> bool:
        """Return ``True`` for extended-range VLANs (1006..4094)."""
        return 1006 <= self.vlan_id_num <= 4094

    @property
    def is_active(self) -> bool:
        """Return ``True`` if this VLAN is in ``active`` status."""
        return (self.status or "active").lower() == "active"

    def __repr__(self) -> str:
        return f"<Vlan id={self.id!r} vid={self.vlan_id_num} name={self.name!r}>"


class IpAllocation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual IP address assignment or discovered lease within a :class:`Subnet`."""

    __tablename__ = "ip_allocations"
    __table_args__ = (
        UniqueConstraint("subnet_id", "ip_address", name="uq_ip_allocations_subnet_ip"),
        Index("ix_ip_allocations_org_ip", "org_id", "ip_address"),
        Index("ix_ip_allocations_org_status", "org_id", "status"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subnet_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("subnets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    allocation_type: Mapped[str] = mapped_column(String(32), default="static", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    subnet: Mapped[Subnet] = relationship("Subnet", back_populates="ip_allocations")
    device: Mapped[Device | None] = relationship("Device", back_populates="ip_allocations")

    @validates("ip_address")
    def _validate_ip(self, _key: str, value: str) -> str:
        normalized = normalize_ip_address(value)
        if normalized is None:
            raise ValueError("IpAllocation ip_address must not be empty")
        return normalized

    @validates("mac_address")
    def _validate_mac(self, _key: str, value: str | None) -> str | None:
        return normalize_mac_address(value)

    @property
    def is_active(self) -> bool:
        """Return ``True`` when the allocation is currently active or reserved."""
        return (self.status or "active").lower() in {"active", "reserved", "dhcp"}

    def touch(self, now: datetime | None = None) -> None:
        """Stamp ``last_seen_at`` when an IP/MAC pair is observed on the wire."""
        self.last_seen_at = _as_utc(now) or utcnow()

    def __repr__(self) -> str:
        return (
            f"<IpAllocation id={self.id!r} ip={self.ip_address!r} "
            f"type={self.allocation_type!r} status={self.status!r}>"
        )


class DeviceGroup(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Logical device collection supporting both static membership and dynamic rules."""

    __tablename__ = "device_groups"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_device_groups_org_name"),
        Index("ix_device_groups_org_type", "org_id", "group_type"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    group_type: Mapped[str] = mapped_column(String(32), default="static", nullable=False)
    dynamic_filter_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    color: Mapped[str] = mapped_column(String(16), default="#3b82f6", nullable=False)

    # Relationships
    memberships: Mapped[list[DeviceGroupMember]] = relationship(
        "DeviceGroupMember",
        back_populates="group",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("group_type")
    def _validate_group_type(self, _key: str, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in {"static", "dynamic"}:
            raise ValueError(f"group_type must be 'static' or 'dynamic', got {value!r}")
        return cleaned

    @validates("color")
    def _validate_color(self, _key: str, value: str) -> str:
        cleaned = value.strip()
        if not _HEX_COLOR_RE.match(cleaned):
            raise ValueError(f"Group color must be a #RRGGBB hex string, got {value!r}")
        return cleaned.lower()

    @property
    def is_dynamic(self) -> bool:
        """Return ``True`` if membership is evaluated via ``dynamic_filter_json``."""
        return (self.group_type or "static") == "dynamic"

    def matches_device(self, device: Device) -> bool:
        """Evaluate ``dynamic_filter_json`` predicates against *device*.

        Supported filter keys: ``device_type``, ``vendor``, ``status``,
        ``site_id``, ``hostname_pattern``, and ``tags`` (all required tags).
        Each scalar filter accepts either a single string or a list of strings.
        """
        if not self.is_dynamic or not isinstance(self.dynamic_filter_json, dict):
            return False
        flt = self.dynamic_filter_json
        if not flt:
            return False

        for attr in ("device_type", "vendor", "status", "site_id"):
            if attr not in flt or flt[attr] is None:
                continue
            expected = flt[attr]
            actual = getattr(device, attr, None)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        hostname_pattern = flt.get("hostname_pattern")
        if hostname_pattern and not fnmatch.fnmatchcase(device.hostname, str(hostname_pattern)):
            return False

        required_tags = flt.get("tags")
        if required_tags:
            device_tags = set(device.tags_json or [])
            if isinstance(required_tags, str):
                required_set = {required_tags}
            else:
                required_set = set(required_tags)
            if not required_set.issubset(device_tags):
                return False

        return True

    def __repr__(self) -> str:
        return f"<DeviceGroup id={self.id!r} name={self.name!r} type={self.group_type!r}>"


class DeviceGroupMember(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Many-to-many membership join linking a :class:`DeviceGroup` and :class:`Device`."""

    __tablename__ = "device_group_members"
    __table_args__ = (
        UniqueConstraint(
            "group_id",
            "device_id",
            name="uq_device_group_members_group_device",
        ),
        Index("ix_device_group_members_device", "device_id", "group_id"),
    )

    group_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("device_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Relationships
    group: Mapped[DeviceGroup] = relationship("DeviceGroup", back_populates="memberships")
    device: Mapped[Device] = relationship("Device", back_populates="group_memberships")

    def __repr__(self) -> str:
        return f"<DeviceGroupMember group_id={self.group_id!r} device_id={self.device_id!r}>"


__all__ = [
    "CredentialProfile",
    "Device",
    "DeviceGroup",
    "DeviceGroupMember",
    "DeviceInterface",
    "IpAllocation",
    "Rack",
    "Site",
    "Subnet",
    "Vlan",
    "normalize_ip_address",
    "normalize_mac_address",
]
