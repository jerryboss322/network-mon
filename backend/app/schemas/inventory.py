"""Network inventory, IPAM, sites, racks, credentials, interfaces, and groups schemas.

Provides comprehensive Pydantic v2 contracts for:
- Physical infrastructure: `Site*`, `Rack*`
- Credential vault profiles: `CredentialProfileCreate/Update/Read` (strictly
  forbidding exposure of plaintext secrets, community strings, keys, or tokens
  in read schemas)
- Managed network devices: `DeviceCreate/Update/Read/Detail/Summary/Query`
- Network interfaces: `DeviceInterfaceCreate/Update/Read`
- IPAM: `SubnetCreate/Update/Read`, `SubnetCalculationResponse` (with exact
  IPv4/IPv6 CIDR math via stdlib `ipaddress`), `VlanCreate/Update/Read`,
  `IpAllocationCreate/Update/Read`
- Static & dynamic device grouping: `DeviceGroupCreate/Update/Read`
- Bulk device onboarding: `BulkDeviceImportRequest/Result`
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Self

from pydantic import Field, computed_field, field_validator, model_validator

from app.schemas.common import (
    BaseSchema,
    CIDRStr,
    EmailAddress,
    HostnameStr,
    IPAddressStr,
    KeyValueFilter,
    MACAddressStr,
    MetadataDict,
    SlugStr,
    SortOrder,
    TagMap,
    TenantEntityReadSchema,
    UTCDatetime,
)

# ---------------------------------------------------------------------------
# Inventory & IPAM Enums
# ---------------------------------------------------------------------------


class SiteTier(str, Enum):
    """Availability/criticality tier of a physical site or data center."""

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"
    TIER_4 = "tier_4"
    BRANCH = "branch"
    EDGE = "edge"
    CLOUD = "cloud"


class DeviceType(str, Enum):
    """Hardware or virtual form-factor classification of a managed device."""

    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    ACCESS_POINT = "access_point"
    WIRELESS_CONTROLLER = "wireless_controller"
    SERVER = "server"
    VIRTUAL_MACHINE = "virtual_machine"
    STORAGE = "storage"
    PDU = "pdu"
    UPS = "ups"
    OPTICAL_TRANSPONDER = "optical_transponder"
    EDGE_GATEWAY = "edge_gateway"
    OTHER = "other"


class DeviceRole(str, Enum):
    """Architectural role of a device in the network fabric."""

    CORE = "core"
    DISTRIBUTION = "distribution"
    ACCESS = "access"
    BORDER = "border"
    SPINE = "spine"
    LEAF = "leaf"
    DMZ = "dmz"
    WAN_EDGE = "wan_edge"
    MANAGEMENT = "management"
    COMPUTE = "compute"
    SECURITY = "security"
    LAB = "lab"


class DeviceStatus(str, Enum):
    """Current operational and reachability state of a device."""

    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    PROVISIONING = "provisioning"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


class CredentialType(str, Enum):
    """Supported device authentication and polling credential mechanisms."""

    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"
    SSH_PASSWORD = "ssh_password"
    SSH_KEY = "ssh_key"
    NETCONF = "netconf"
    RESTCONF = "restconf"
    API_TOKEN = "api_token"
    WINRM = "winrm"


class SnmpAuthProtocol(str, Enum):
    """SNMPv3 authentication hash protocols."""

    NONE = "none"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class SnmpPrivProtocol(str, Enum):
    """SNMPv3 privacy encryption protocols."""

    NONE = "none"
    DES = "des"
    AES128 = "aes128"
    AES192 = "aes192"
    AES256 = "aes256"


class InterfaceAdminStatus(str, Enum):
    """Administrative state of a network interface (IF-MIB ifAdminStatus)."""

    UP = "up"
    DOWN = "down"
    TESTING = "testing"


class InterfaceOperStatus(str, Enum):
    """Operational state of a network interface (IF-MIB ifOperStatus)."""

    UP = "up"
    DOWN = "down"
    TESTING = "testing"
    UNKNOWN = "unknown"
    DORMANT = "dormant"
    NOT_PRESENT = "not_present"
    LOWER_LAYER_DOWN = "lower_layer_down"


class InterfaceType(str, Enum):
    """Logical or physical interface media category."""

    ETHERNET = "ethernet"
    FIBER = "fiber"
    LAG = "lag"
    LOOPBACK = "loopback"
    VLAN_SVI = "vlan_svi"
    TUNNEL = "tunnel"
    WIRELESS = "wireless"
    MANAGEMENT = "management"
    SERIAL = "serial"
    VIRTUAL = "virtual"


class DuplexMode(str, Enum):
    """Ethernet duplex negotiation mode."""

    FULL = "full"
    HALF = "half"
    AUTO = "auto"
    UNKNOWN = "unknown"


class VlanStatus(str, Enum):
    """Operational lifecycle state of a VLAN definition."""

    ACTIVE = "active"
    RESERVED = "reserved"
    DEPRECATED = "deprecated"


class IpAllocationStatus(str, Enum):
    """Allocation state of an IP address inside IPAM."""

    ACTIVE = "active"
    RESERVED = "reserved"
    DHCP = "dhcp"
    DEPRECATED = "deprecated"
    CONFLICT = "conflict"


class IpAllocationType(str, Enum):
    """Assignment mechanism for an IP address record."""

    STATIC = "static"
    DHCP = "dhcp"
    SLAAC = "slaac"
    VIP = "vip"
    LOOPBACK = "loopback"
    GATEWAY = "gateway"


# ---------------------------------------------------------------------------
# Site & Rack Schemas
# ---------------------------------------------------------------------------


class SiteCreate(BaseSchema):
    """Request payload to register a physical site, PoP, or cloud region."""

    name: str = Field(..., min_length=2, max_length=120, description="Site display name.")
    slug: SlugStr = Field(..., description="Unique tenant-scoped site slug.")
    site_code: str | None = Field(
        default=None, max_length=24, description="Short IATA/facility code (e.g. 'IAD1')."
    )
    tier: SiteTier = Field(default=SiteTier.TIER_3)
    region: str | None = Field(default=None, max_length=80)
    country_code: str | None = Field(
        default=None,
        min_length=2,
        max_length=2,
        pattern=r"^[A-Za-z]{2}$",
        description="ISO 3166-1 alpha-2 country code.",
    )
    city: str | None = Field(default=None, max_length=80)
    address: str | None = Field(default=None, max_length=300)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    timezone_name: str = Field(default="UTC", max_length=64)
    contact_name: str | None = Field(default=None, max_length=120)
    contact_email: EmailAddress | None = None
    contact_phone: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=1000)
    tags: TagMap = Field(default_factory=dict)

    @field_validator("country_code")
    @classmethod
    def _upper_country(cls, value: str | None) -> str | None:
        return value.upper() if value else None

    @model_validator(mode="after")
    def _validate_coordinates_pair(self) -> Self:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("Both 'latitude' and 'longitude' must be provided together.")
        return self


class SiteUpdate(BaseSchema):
    """Partial update for a site record."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    site_code: str | None = Field(default=None, max_length=24)
    tier: SiteTier | None = None
    region: str | None = Field(default=None, max_length=80)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    city: str | None = Field(default=None, max_length=80)
    address: str | None = Field(default=None, max_length=300)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    timezone_name: str | None = Field(default=None, max_length=64)
    contact_name: str | None = Field(default=None, max_length=120)
    contact_email: EmailAddress | None = None
    contact_phone: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=1000)
    tags: TagMap | None = None


class SiteSummary(BaseSchema):
    """Compact site representation embedded in device or topology responses."""

    id: str
    name: str
    slug: str
    site_code: str | None = None
    tier: SiteTier = SiteTier.TIER_3
    region: str | None = None
    city: str | None = None


class SiteRead(TenantEntityReadSchema):
    """Full site representation including aggregated device/rack counts."""

    name: str
    slug: str
    site_code: str | None = None
    tier: SiteTier = SiteTier.TIER_3
    region: str | None = None
    country_code: str | None = None
    city: str | None = None
    address: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone_name: str = "UTC"
    contact_name: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    description: str | None = None
    tags: TagMap = Field(default_factory=dict)
    rack_count: int = Field(default=0, ge=0)
    device_count: int = Field(default=0, ge=0)
    devices_online: int = Field(default=0, ge=0)


class RackCreate(BaseSchema):
    """Request payload to create a physical cabinet/rack inside a site."""

    site_id: str = Field(..., description="Parent site UUID.")
    name: str = Field(..., min_length=1, max_length=80, description="Rack label (e.g. 'R04-A').")
    facility_id: str | None = Field(default=None, max_length=64)
    row_label: str | None = Field(default=None, max_length=32)
    u_height: int = Field(default=42, ge=1, le=60, description="Total rack height in rack units.")
    power_capacity_watts: int | None = Field(default=None, ge=100, le=200_000)
    cooling_btu: int | None = Field(default=None, ge=0)
    description: str | None = Field(default=None, max_length=500)
    tags: TagMap = Field(default_factory=dict)


class RackUpdate(BaseSchema):
    """Partial update for a rack record."""

    name: str | None = Field(default=None, min_length=1, max_length=80)
    facility_id: str | None = Field(default=None, max_length=64)
    row_label: str | None = Field(default=None, max_length=32)
    u_height: int | None = Field(default=None, ge=1, le=60)
    power_capacity_watts: int | None = Field(default=None, ge=100, le=200_000)
    cooling_btu: int | None = Field(default=None, ge=0)
    description: str | None = Field(default=None, max_length=500)
    tags: TagMap | None = None


class RackRead(TenantEntityReadSchema):
    """Full rack representation with capacity utilization metrics."""

    site_id: str
    name: str
    facility_id: str | None = None
    row_label: str | None = None
    u_height: int = 42
    used_u: int = Field(default=0, ge=0)
    power_capacity_watts: int | None = None
    power_draw_watts: int | None = Field(default=None, ge=0)
    cooling_btu: int | None = None
    description: str | None = None
    tags: TagMap = Field(default_factory=dict)
    device_count: int = Field(default=0, ge=0)

    @computed_field
    @property
    def u_utilization_pct(self) -> float:
        """Percentage of rack units currently occupied."""
        if self.u_height <= 0:
            return 0.0
        return round(min(100.0, (self.used_u / self.u_height) * 100.0), 2)


# ---------------------------------------------------------------------------
# Credential Profile Schemas (Write-only secrets, NEVER exposed in Read!)
# ---------------------------------------------------------------------------


class CredentialProfileCreate(BaseSchema):
    """Create a vault-encrypted credential profile for SNMP, SSH, NETCONF, or API polling.

    Secret fields are encrypted at rest before persistence and are NEVER returned
    by `CredentialProfileRead`.
    """

    name: str = Field(..., min_length=2, max_length=120)
    credential_type: CredentialType = Field(..., description="Protocol credential class.")
    description: str | None = Field(default=None, max_length=500)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512, repr=False)
    enable_secret: str | None = Field(default=None, max_length=512, repr=False)
    snmp_community: str | None = Field(default=None, max_length=256, repr=False)
    snmp_auth_protocol: SnmpAuthProtocol = Field(default=SnmpAuthProtocol.NONE)
    snmp_auth_password: str | None = Field(default=None, max_length=256, repr=False)
    snmp_priv_protocol: SnmpPrivProtocol = Field(default=SnmpPrivProtocol.NONE)
    snmp_priv_password: str | None = Field(default=None, max_length=256, repr=False)
    snmp_context_name: str | None = Field(default=None, max_length=128)
    ssh_private_key: str | None = Field(default=None, max_length=16_384, repr=False)
    ssh_passphrase: str | None = Field(default=None, max_length=256, repr=False)
    api_token: str | None = Field(default=None, max_length=2048, repr=False)
    default_port: int | None = Field(default=None, ge=1, le=65535)
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=120.0)
    retries: int = Field(default=2, ge=0, le=10)
    rotation_interval_days: int | None = Field(default=90, ge=1, le=3650)
    tags: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_credential_completeness(self) -> Self:
        ct = self.credential_type
        if ct == CredentialType.SNMP_V2C and not self.snmp_community:
            raise ValueError("SNMPv2c credential profiles require 'snmp_community'.")
        if ct == CredentialType.SNMP_V3:
            if not self.username:
                raise ValueError("SNMPv3 credential profiles require 'username'.")
            if self.snmp_auth_protocol != SnmpAuthProtocol.NONE and not self.snmp_auth_password:
                raise ValueError(
                    "SNMPv3 auth protocol requires 'snmp_auth_password'."
                )
            if self.snmp_priv_protocol != SnmpPrivProtocol.NONE:
                if self.snmp_auth_protocol == SnmpAuthProtocol.NONE:
                    raise ValueError(
                        "SNMPv3 privacy encryption requires an authentication protocol."
                    )
                if not self.snmp_priv_password:
                    raise ValueError("SNMPv3 privacy protocol requires 'snmp_priv_password'.")
        if ct == CredentialType.SSH_PASSWORD and (not self.username or not self.password):
            raise ValueError("SSH password profiles require both 'username' and 'password'.")
        if ct == CredentialType.SSH_KEY and (not self.username or not self.ssh_private_key):
            raise ValueError("SSH key profiles require both 'username' and 'ssh_private_key'.")
        if ct == CredentialType.API_TOKEN and not self.api_token:
            raise ValueError("API token profiles require 'api_token'.")
        return self


class CredentialProfileUpdate(BaseSchema):
    """Partial update for a credential profile; omitted secrets remain unchanged."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512, repr=False)
    enable_secret: str | None = Field(default=None, max_length=512, repr=False)
    snmp_community: str | None = Field(default=None, max_length=256, repr=False)
    snmp_auth_protocol: SnmpAuthProtocol | None = None
    snmp_auth_password: str | None = Field(default=None, max_length=256, repr=False)
    snmp_priv_protocol: SnmpPrivProtocol | None = None
    snmp_priv_password: str | None = Field(default=None, max_length=256, repr=False)
    snmp_context_name: str | None = Field(default=None, max_length=128)
    ssh_private_key: str | None = Field(default=None, max_length=16_384, repr=False)
    ssh_passphrase: str | None = Field(default=None, max_length=256, repr=False)
    api_token: str | None = Field(default=None, max_length=2048, repr=False)
    default_port: int | None = Field(default=None, ge=1, le=65535)
    timeout_seconds: float | None = Field(default=None, ge=0.5, le=120.0)
    retries: int | None = Field(default=None, ge=0, le=10)
    rotation_interval_days: int | None = Field(default=None, ge=1, le=3650)
    tags: TagMap | None = None


class CredentialProfileRead(TenantEntityReadSchema):
    """Redacted metadata view of a credential profile.

    Security invariant: NEVER exposes decrypted passwords, SNMP communities,
    SNMPv3 auth/priv passphrases, SSH private keys, API tokens, or raw ciphertext.
    """

    name: str
    credential_type: CredentialType
    description: str | None = None
    username: str | None = None
    snmp_auth_protocol: SnmpAuthProtocol = SnmpAuthProtocol.NONE
    snmp_priv_protocol: SnmpPrivProtocol = SnmpPrivProtocol.NONE
    snmp_context_name: str | None = None
    default_port: int | None = None
    timeout_seconds: float = 5.0
    retries: int = 2
    has_password: bool = Field(default=False, description="True if a password secret is stored.")
    has_enable_secret: bool = Field(default=False)
    has_snmp_community: bool = Field(default=False)
    has_snmp_auth_password: bool = Field(default=False)
    has_snmp_priv_password: bool = Field(default=False)
    has_ssh_private_key: bool = Field(default=False)
    has_api_token: bool = Field(default=False)
    secret_fingerprint: str | None = Field(
        default=None,
        description="Non-reversible short SHA-256 fingerprint for rotation verification.",
    )
    last_rotated_at: UTCDatetime | None = None
    rotation_interval_days: int | None = None
    attached_device_count: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Device Interface Schemas
# ---------------------------------------------------------------------------


class DeviceInterfaceCreate(BaseSchema):
    """Create or upsert a monitored network interface on a device."""

    device_id: str | None = Field(
        default=None, description="Owning device UUID (optional when provided via URL path)."
    )
    if_index: int | None = Field(default=None, ge=0, description="SNMP IF-MIB ifIndex.")
    name: str = Field(..., min_length=1, max_length=128, description="Interface name (e.g. 'Gi0/0/1').")
    alias: str | None = Field(default=None, max_length=255, description="ifAlias description.")
    interface_type: InterfaceType = Field(default=InterfaceType.ETHERNET)
    mac_address: MACAddressStr | None = None
    ip_addresses: list[IPAddressStr] = Field(default_factory=list)
    subnet_id: str | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    speed_mbps: int | None = Field(default=None, ge=0, le=10_000_000)
    mtu: int | None = Field(default=1500, ge=68, le=65535)
    duplex: DuplexMode = Field(default=DuplexMode.AUTO)
    admin_status: InterfaceAdminStatus = Field(default=InterfaceAdminStatus.UP)
    oper_status: InterfaceOperStatus = Field(default=InterfaceOperStatus.UP)
    is_monitored: bool = Field(default=True)
    is_uplink: bool = Field(default=False)
    tags: TagMap = Field(default_factory=dict)


class DeviceInterfaceUpdate(BaseSchema):
    """Partial update for a device interface."""

    alias: str | None = Field(default=None, max_length=255)
    interface_type: InterfaceType | None = None
    mac_address: MACAddressStr | None = None
    ip_addresses: list[IPAddressStr] | None = None
    subnet_id: str | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    speed_mbps: int | None = Field(default=None, ge=0, le=10_000_000)
    mtu: int | None = Field(default=None, ge=68, le=65535)
    duplex: DuplexMode | None = None
    admin_status: InterfaceAdminStatus | None = None
    oper_status: InterfaceOperStatus | None = None
    is_monitored: bool | None = None
    is_uplink: bool | None = None
    tags: TagMap | None = None


class DeviceInterfaceRead(TenantEntityReadSchema):
    """Full interface representation with latest utilization telemetry."""

    device_id: str
    if_index: int | None = None
    name: str
    alias: str | None = None
    interface_type: InterfaceType = InterfaceType.ETHERNET
    mac_address: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    subnet_id: str | None = None
    vlan_id: int | None = None
    speed_mbps: int | None = None
    mtu: int | None = 1500
    duplex: DuplexMode = DuplexMode.AUTO
    admin_status: InterfaceAdminStatus = InterfaceAdminStatus.UP
    oper_status: InterfaceOperStatus = InterfaceOperStatus.UNKNOWN
    is_monitored: bool = True
    is_uplink: bool = False
    in_bps: float | None = Field(default=None, ge=0.0)
    out_bps: float | None = Field(default=None, ge=0.0)
    in_errors: int = Field(default=0, ge=0)
    out_errors: int = Field(default=0, ge=0)
    in_discards: int = Field(default=0, ge=0)
    out_discards: int = Field(default=0, ge=0)
    utilization_in_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    utilization_out_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    last_flap_at: UTCDatetime | None = None
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Device Schemas
# ---------------------------------------------------------------------------


class DeviceCreate(BaseSchema):
    """Request payload to onboard a new managed network or infrastructure device."""

    name: str = Field(..., min_length=1, max_length=128, description="Unique display name.")
    hostname: HostnameStr = Field(..., description="DNS hostname or FQDN.")
    management_ip: IPAddressStr = Field(..., description="Primary management IPv4/IPv6 address.")
    device_type: DeviceType = Field(default=DeviceType.ROUTER)
    device_role: DeviceRole = Field(default=DeviceRole.ACCESS)
    vendor: str | None = Field(default=None, max_length=80)
    model: str | None = Field(default=None, max_length=120)
    os_version: str | None = Field(default=None, max_length=120)
    serial_number: str | None = Field(default=None, max_length=120)
    asset_tag: str | None = Field(default=None, max_length=64)
    site_id: str | None = None
    rack_id: str | None = None
    rack_u_position: int | None = Field(default=None, ge=1, le=60)
    rack_u_height: int = Field(default=1, ge=1, le=42)
    credential_profile_id: str | None = None
    edge_agent_id: str | None = None
    snmp_port: int = Field(default=161, ge=1, le=65535)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    polling_enabled: bool = Field(default=True)
    icmp_enabled: bool = Field(default=True)
    snmp_enabled: bool = Field(default=True)
    poll_interval_seconds: int = Field(default=60, ge=5, le=86400)
    group_ids: list[str] = Field(default_factory=list)
    tags: TagMap = Field(default_factory=dict)
    custom_fields: MetadataDict = Field(default_factory=dict)
    notes: str | None = Field(default=None, max_length=2000)


class DeviceUpdate(BaseSchema):
    """Partial update payload for a managed device."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    hostname: HostnameStr | None = None
    management_ip: IPAddressStr | None = None
    device_type: DeviceType | None = None
    device_role: DeviceRole | None = None
    status: DeviceStatus | None = None
    vendor: str | None = Field(default=None, max_length=80)
    model: str | None = Field(default=None, max_length=120)
    os_version: str | None = Field(default=None, max_length=120)
    serial_number: str | None = Field(default=None, max_length=120)
    asset_tag: str | None = Field(default=None, max_length=64)
    site_id: str | None = None
    rack_id: str | None = None
    rack_u_position: int | None = Field(default=None, ge=1, le=60)
    rack_u_height: int | None = Field(default=None, ge=1, le=42)
    credential_profile_id: str | None = None
    edge_agent_id: str | None = None
    snmp_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    polling_enabled: bool | None = None
    icmp_enabled: bool | None = None
    snmp_enabled: bool | None = None
    poll_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    tags: TagMap | None = None
    custom_fields: MetadataDict | None = None
    notes: str | None = Field(default=None, max_length=2000)


class DeviceSummary(BaseSchema):
    """Lightweight device representation for lists, topology cards, and alert joins."""

    id: str
    name: str
    hostname: str
    management_ip: str
    device_type: DeviceType
    device_role: DeviceRole
    status: DeviceStatus = DeviceStatus.UNKNOWN
    vendor: str | None = None
    site_id: str | None = None
    latency_ms: float | None = Field(default=None, ge=0.0)
    cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    active_alert_count: int = Field(default=0, ge=0)


class DeviceRead(TenantEntityReadSchema):
    """Standard read representation of a managed device."""

    name: str
    hostname: str
    management_ip: str
    device_type: DeviceType
    device_role: DeviceRole
    status: DeviceStatus = DeviceStatus.UNKNOWN
    vendor: str | None = None
    model: str | None = None
    os_version: str | None = None
    serial_number: str | None = None
    asset_tag: str | None = None
    sys_object_id: str | None = None
    sys_description: str | None = None
    site_id: str | None = None
    rack_id: str | None = None
    rack_u_position: int | None = None
    rack_u_height: int = 1
    credential_profile_id: str | None = None
    edge_agent_id: str | None = None
    snmp_port: int = 161
    ssh_port: int = 22
    polling_enabled: bool = True
    icmp_enabled: bool = True
    snmp_enabled: bool = True
    poll_interval_seconds: int = 60
    last_seen_at: UTCDatetime | None = None
    last_polled_at: UTCDatetime | None = None
    uptime_seconds: int | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0.0)
    packet_loss_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    temperature_c: float | None = None
    interface_count: int = Field(default=0, ge=0)
    active_alert_count: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)
    custom_fields: MetadataDict = Field(default_factory=dict)
    notes: str | None = None


class DeviceDetail(DeviceRead):
    """Expanded device view embedding site, rack, redacted credential, interfaces, and groups."""

    site: SiteSummary | None = None
    rack: RackRead | None = None
    credential_profile: CredentialProfileRead | None = None
    interfaces: list[DeviceInterfaceRead] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    compliance_score_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    last_config_backup_at: UTCDatetime | None = None


class DeviceQuery(BaseSchema):
    """Filter parameters for searching managed devices."""

    search: str | None = Field(default=None, max_length=200)
    site_id: str | None = None
    rack_id: str | None = None
    group_id: str | None = None
    device_type: DeviceType | None = None
    device_role: DeviceRole | None = None
    status: DeviceStatus | None = None
    vendor: str | None = Field(default=None, max_length=80)
    tag_key: str | None = Field(default=None, max_length=64)
    tag_value: str | None = Field(default=None, max_length=128)
    polling_enabled: bool | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_by: str = Field(default="name", max_length=64)
    sort_order: SortOrder = SortOrder.ASC


# ---------------------------------------------------------------------------
# IPAM: Subnets, VLANs, IP Allocations
# ---------------------------------------------------------------------------


class SubnetCreate(BaseSchema):
    """Request payload to register a managed IPv4 or IPv6 subnet in IPAM."""

    cidr: CIDRStr = Field(..., description="Network CIDR block (e.g. '10.20.0.0/24').")
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    site_id: str | None = None
    vlan_id: str | None = Field(default=None, description="Optional linked VLAN entity UUID.")
    parent_subnet_id: str | None = None
    gateway_ip: IPAddressStr | None = None
    dns_servers: list[IPAddressStr] = Field(default_factory=list)
    dhcp_enabled: bool = Field(default=False)
    vrf: str = Field(default="default", max_length=64)
    utilization_warn_pct: float = Field(default=80.0, ge=1.0, le=100.0)
    utilization_crit_pct: float = Field(default=95.0, ge=1.0, le=100.0)
    tags: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_gateway_and_thresholds(self) -> Self:
        if self.utilization_warn_pct > self.utilization_crit_pct:
            raise ValueError("'utilization_warn_pct' cannot exceed 'utilization_crit_pct'.")
        if self.gateway_ip is not None:
            net = ipaddress.ip_network(self.cidr, strict=False)
            gw = ipaddress.ip_address(self.gateway_ip)
            if gw not in net:
                raise ValueError(
                    f"Gateway IP {self.gateway_ip} is outside subnet CIDR {self.cidr}."
                )
        return self


class SubnetUpdate(BaseSchema):
    """Partial update for a managed IPAM subnet."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    site_id: str | None = None
    vlan_id: str | None = None
    gateway_ip: IPAddressStr | None = None
    dns_servers: list[IPAddressStr] | None = None
    dhcp_enabled: bool | None = None
    vrf: str | None = Field(default=None, max_length=64)
    utilization_warn_pct: float | None = Field(default=None, ge=1.0, le=100.0)
    utilization_crit_pct: float | None = Field(default=None, ge=1.0, le=100.0)
    tags: TagMap | None = None


class SubnetRead(TenantEntityReadSchema):
    """Full IPAM subnet view including live allocation statistics."""

    cidr: str
    name: str
    description: str | None = None
    ip_version: int = Field(default=4, ge=4, le=6)
    site_id: str | None = None
    vlan_id: str | None = None
    parent_subnet_id: str | None = None
    gateway_ip: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    dhcp_enabled: bool = False
    vrf: str = "default"
    total_hosts: int = Field(default=0, ge=0)
    allocated_count: int = Field(default=0, ge=0)
    utilization_warn_pct: float = 80.0
    utilization_crit_pct: float = 95.0
    tags: TagMap = Field(default_factory=dict)

    @computed_field
    @property
    def utilization_pct(self) -> float:
        """Compute current address allocation percentage."""
        if self.total_hosts <= 0:
            return 0.0
        return round(min(100.0, (self.allocated_count / self.total_hosts) * 100.0), 2)


class SubnetCalculationResponse(BaseSchema):
    """Deterministic IPv4/IPv6 CIDR calculation result for IPAM planning."""

    cidr: str
    ip_version: int
    network_address: str
    broadcast_address: str | None = None
    netmask: str
    hostmask: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_usable_ip: str | None = None
    last_usable_ip: str | None = None
    is_private: bool
    is_global: bool
    is_multicast: bool
    is_loopback: bool
    supernet: str | None = None
    sample_child_subnets: list[str] = Field(default_factory=list)

    @classmethod
    def from_cidr(cls, cidr: str, *, child_prefix_delta: int = 1) -> SubnetCalculationResponse:
        """Compute complete CIDR geometry directly from an IPv4/IPv6 network string."""
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        total = int(net.num_addresses)
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen == 32:
                usable, first_ip, last_ip = 1, str(net.network_address), str(net.network_address)
            elif net.prefixlen == 31:
                usable = 2
                first_ip = str(net.network_address)
                last_ip = str(net.broadcast_address)
            else:
                usable = max(0, total - 2)
                first_ip = str(net.network_address + 1)
                last_ip = str(net.broadcast_address - 1)
            broadcast: str | None = str(net.broadcast_address)
        else:
            broadcast = None
            if net.prefixlen == 128:
                usable, first_ip, last_ip = 1, str(net.network_address), str(net.network_address)
            else:
                usable = total
                first_ip = str(net.network_address + 1)
                last_ip = str(net.broadcast_address)

        supernet = str(net.supernet()) if net.prefixlen > 0 else None
        children: list[str] = []
        if net.prefixlen + child_prefix_delta <= net.max_prefixlen:
            for idx, sub in enumerate(net.subnets(prefixlen_diff=child_prefix_delta)):
                if idx >= 16:
                    break
                children.append(str(sub))

        return cls(
            cidr=str(net),
            ip_version=net.version,
            network_address=str(net.network_address),
            broadcast_address=broadcast,
            netmask=str(net.netmask),
            hostmask=str(net.hostmask),
            prefix_length=net.prefixlen,
            total_addresses=total,
            usable_hosts=usable,
            first_usable_ip=first_ip,
            last_usable_ip=last_ip,
            is_private=net.is_private,
            is_global=net.is_global,
            is_multicast=net.is_multicast,
            is_loopback=net.is_loopback,
            supernet=supernet,
            sample_child_subnets=children,
        )


class VlanCreate(BaseSchema):
    """Request payload to register an IEEE 802.1Q VLAN."""

    vlan_id: int = Field(..., ge=1, le=4094, description="IEEE 802.1Q VLAN identifier (1-4094).")
    name: str = Field(..., min_length=1, max_length=100)
    site_id: str | None = None
    status: VlanStatus = Field(default=VlanStatus.ACTIVE)
    role: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=500)
    tags: TagMap = Field(default_factory=dict)


class VlanUpdate(BaseSchema):
    """Partial update for a VLAN record."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    site_id: str | None = None
    status: VlanStatus | None = None
    role: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=500)
    tags: TagMap | None = None


class VlanRead(TenantEntityReadSchema):
    """Full representation of an IEEE 802.1Q VLAN."""

    vlan_id: int
    name: str
    site_id: str | None = None
    status: VlanStatus = VlanStatus.ACTIVE
    role: str | None = None
    description: str | None = None
    subnet_count: int = Field(default=0, ge=0)
    interface_count: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)


class IpAllocationCreate(BaseSchema):
    """Allocate or reserve an IP address inside a managed subnet."""

    subnet_id: str = Field(..., description="Parent IPAM subnet UUID.")
    ip_address: IPAddressStr = Field(..., description="Allocated IPv4/IPv6 address.")
    status: IpAllocationStatus = Field(default=IpAllocationStatus.ACTIVE)
    allocation_type: IpAllocationType = Field(default=IpAllocationType.STATIC)
    hostname: HostnameStr | None = None
    dns_ptr: str | None = Field(default=None, max_length=255)
    mac_address: MACAddressStr | None = None
    device_id: str | None = None
    interface_id: str | None = None
    owner: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    lease_expires_at: UTCDatetime | None = None
    tags: TagMap = Field(default_factory=dict)


class IpAllocationUpdate(BaseSchema):
    """Partial update for an IPAM allocation."""

    status: IpAllocationStatus | None = None
    allocation_type: IpAllocationType | None = None
    hostname: HostnameStr | None = None
    dns_ptr: str | None = Field(default=None, max_length=255)
    mac_address: MACAddressStr | None = None
    device_id: str | None = None
    interface_id: str | None = None
    owner: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    lease_expires_at: UTCDatetime | None = None
    tags: TagMap | None = None


class IpAllocationRead(TenantEntityReadSchema):
    """Full IPAM IP address allocation record."""

    subnet_id: str
    ip_address: str
    status: IpAllocationStatus = IpAllocationStatus.ACTIVE
    allocation_type: IpAllocationType = IpAllocationType.STATIC
    hostname: str | None = None
    dns_ptr: str | None = None
    mac_address: str | None = None
    device_id: str | None = None
    interface_id: str | None = None
    owner: str | None = None
    description: str | None = None
    lease_expires_at: UTCDatetime | None = None
    last_seen_at: UTCDatetime | None = None
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Device Groups & Bulk Device Import
# ---------------------------------------------------------------------------


class DeviceGroupCreate(BaseSchema):
    """Create a static, dynamic (rule-based), or hybrid device group."""

    name: str = Field(..., min_length=2, max_length=120)
    slug: SlugStr = Field(..., description="Unique tenant-scoped group slug.")
    description: str | None = Field(default=None, max_length=500)
    parent_group_id: str | None = None
    is_dynamic: bool = Field(
        default=False, description="When true, membership is evaluated via filter_rules."
    )
    filter_rules: list[KeyValueFilter] = Field(
        default_factory=list, description="Dynamic membership rules evaluated against devices."
    )
    device_ids: list[str] = Field(
        default_factory=list, description="Explicit static device UUID members."
    )
    tags: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_dynamic_rules(self) -> Self:
        if self.is_dynamic and not self.filter_rules:
            raise ValueError("Dynamic device groups must define at least one filter rule.")
        return self


class DeviceGroupUpdate(BaseSchema):
    """Partial update for a device group."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    parent_group_id: str | None = None
    is_dynamic: bool | None = None
    filter_rules: list[KeyValueFilter] | None = None
    device_ids: list[str] | None = None
    tags: TagMap | None = None


class DeviceGroupRead(TenantEntityReadSchema):
    """Full representation of a device group."""

    name: str
    slug: str
    description: str | None = None
    parent_group_id: str | None = None
    is_dynamic: bool = False
    filter_rules: list[KeyValueFilter] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)
    member_count: int = Field(default=0, ge=0)
    online_count: int = Field(default=0, ge=0)
    tags: TagMap = Field(default_factory=dict)


class BulkDeviceImportRequest(BaseSchema):
    """Bulk device onboarding payload supporting upsert and dry-run validation."""

    devices: list[DeviceCreate] = Field(
        ..., min_length=1, max_length=500, description="List of devices to import."
    )
    upsert_on_hostname: bool = Field(
        default=True, description="Update existing device if hostname already exists."
    )
    default_site_id: str | None = None
    default_credential_profile_id: str | None = None
    dry_run: bool = Field(
        default=False, description="Validate payload without committing changes."
    )


class BulkDeviceImportRowError(BaseSchema):
    """Validation or persistence error encountered for a single bulk import row."""

    row_index: int = Field(..., ge=0, description="0-based index in the submitted devices array.")
    hostname: str | None = None
    management_ip: str | None = None
    error_code: str
    message: str


class BulkDeviceImportResult(BaseSchema):
    """Summary outcome of a bulk device import job."""

    dry_run: bool = False
    total_submitted: int = Field(..., ge=0)
    created_count: int = Field(default=0, ge=0)
    updated_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)
    failed_count: int = Field(default=0, ge=0)
    created_device_ids: list[str] = Field(default_factory=list)
    updated_device_ids: list[str] = Field(default_factory=list)
    errors: list[BulkDeviceImportRowError] = Field(default_factory=list)
