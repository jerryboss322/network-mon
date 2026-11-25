"""IPAM (Subnets, Allocations, VLANs), Encrypted Credential Vault & Network Utils API router (v1).

Exposes production network engineering & address management endpoints:

- **Subnets**: IPv4/IPv6 CIDR CRUD, live utilization calculations, and a full
  CIDR calculator + VLSM splitter + supernet/summarization + DB overlap checker.
- **IP Allocations**: Per-subnet allocation listing (numerically IP-sorted),
  explicit IP allocation, automatic next-available IP allocation, and release.
- **VLANs**: IEEE 802.1Q VLAN catalog scoped to organizations and sites.
- **Credential Vault**: Fernet-encrypted SNMP/SSH/API credential profile CRUD.
  Strictly redacted on all read paths — plaintext secrets and raw ciphertext are
  NEVER returned in API responses.
- **Network Utilities**: IEEE OUI / MAC address parser & EUI-64 converter, plus
  well-known TCP/UDP port service lookup.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import AliasChoices, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from app.api.deps import get_db_session as get_db
from app.api.v1.sites import (
    TenantRequestContext,
    record_audit_event,
    resolve_tenant_context,
)
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.network_utils import (
    WELL_KNOWN_PORTS,
    allocate_vlsm,
    calculate_subnet,
    calculate_supernet,
    cidrs_overlap,
    classify_port,
    find_overlapping_cidrs,
    format_mac,
    get_oui,
    is_broadcast_mac,
    is_ephemeral_port,
    is_locally_administered_mac,
    is_multicast_mac,
    lookup_oui_vendor,
    lookup_port,
    mac_to_eui64,
    parse_network,
    reverse_dns_pointer,
    split_subnet,
    summarize_cidrs,
)
from app.core.security import get_credential_vault
from app.db.repositories.base import BaseRepository
from app.db.repositories.inventory import (
    CredentialRepository,
    DeviceRepository,
    InterfaceRepository,
    SiteRepository,
    SubnetRepository,
    VlanRepository,
)
from app.models.enums import AuditAction, CredentialType, SnmpVersion
from app.models.inventory import (
    CredentialProfile,
    IpAllocation,
    Subnet,
    Vlan,
    normalize_ip_address,
    normalize_mac_address,
)
from app.schemas.common import BaseSchema, PaginationMeta

logger = logging.getLogger(__name__)

router = APIRouter(tags=["IPAM & Credentials"])

_SECRET_FIELD_NAMES: tuple[str, ...] = (
    "username",
    "password",
    "enable_secret",
    "snmp_community",
    "snmp_auth_protocol",
    "snmp_auth_password",
    "snmp_priv_protocol",
    "snmp_priv_password",
    "snmp_context_name",
    "ssh_private_key",
    "ssh_passphrase",
    "api_token",
)


# ---------------------------------------------------------------------------
# IPAM & Credential Schemas
# ---------------------------------------------------------------------------


class SubnetCreateRequest(BaseSchema):
    """Create payload for an IPAM IPv4/IPv6 subnet."""

    cidr: str = Field(..., min_length=3, max_length=64)
    name: str = Field(..., min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    site_id: str | None = None
    gateway_ip: str | None = Field(default=None, max_length=64)
    vlan_number: int | None = Field(
        default=None,
        ge=1,
        le=4094,
        validation_alias=AliasChoices("vlan_number", "vlan_id_num"),
    )
    dns_servers: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("dns_servers", "dns_servers_json"),
    )
    dhcp_enabled: bool = False
    scan_enabled: bool = True
    allow_overlap: bool = Field(
        default=False,
        description="If false, rejects CIDRs that overlap existing subnets in the organization.",
    )

    @model_validator(mode="after")
    def _validate_subnet(self) -> SubnetCreateRequest:
        net = parse_network(self.cidr, strict=False)
        object.__setattr__(self, "cidr", str(net))
        if self.gateway_ip is not None:
            gw = ipaddress.ip_address(self.gateway_ip.strip())
            if gw.version != net.version or gw not in net:
                raise ValueError(f"gateway_ip '{gw}' does not fall within subnet '{net}'")
            object.__setattr__(self, "gateway_ip", str(gw))
        object.__setattr__(
            self,
            "dns_servers",
            [ip for raw in self.dns_servers if (ip := normalize_ip_address(raw)) is not None],
        )
        return self


class SubnetUpdateRequest(BaseSchema):
    """Partial update payload for a managed subnet."""

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    site_id: str | None = None
    gateway_ip: str | None = Field(default=None, max_length=64)
    vlan_number: int | None = Field(
        default=None,
        ge=1,
        le=4094,
        validation_alias=AliasChoices("vlan_number", "vlan_id_num"),
    )
    dns_servers: list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices("dns_servers", "dns_servers_json"),
    )
    dhcp_enabled: bool | None = None
    scan_enabled: bool | None = None


class SubnetResponse(BaseSchema):
    """Full IPAM subnet representation with live host capacity and utilization."""

    id: str
    org_id: str
    site_id: str | None = None
    site_name: str | None = None
    cidr: str
    name: str
    description: str | None = None
    ip_version: int
    network_address: str
    broadcast_address: str | None = None
    netmask: str
    prefix_length: int
    gateway_ip: str | None = None
    vlan_number: int | None = None
    dns_servers: list[str] = Field(default_factory=list)
    dhcp_enabled: bool = False
    scan_enabled: bool = True
    total_usable_hosts: int = 0
    allocated_count: int = 0
    available_count: int = 0
    utilization_pct: float = 0.0
    last_scanned_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SubnetListResponse(BaseSchema):
    """Paginated list of IPAM subnets."""

    items: list[SubnetResponse]
    meta: PaginationMeta


class SubnetCalculateRequest(BaseSchema):
    """Request payload for CIDR calculator, VLSM planner, and overlap detector."""

    cidr: str = Field(..., min_length=3, max_length=64)
    split_prefix: int | None = Field(default=None, ge=0, le=128)
    split_count: int | None = Field(default=None, ge=1, le=4096)
    supernet_prefix: int | None = Field(default=None, ge=0, le=128)
    vlsm_requirements: dict[str, int] | None = Field(
        default=None,
        description="Optional map of segment_name -> required usable hosts for VLSM planning.",
    )
    compare_cidrs: list[str] = Field(
        default_factory=list,
        description="Optional candidate CIDRs to test for pairwise overlap with 'cidr' and each other.",
    )
    summarize_with: list[str] = Field(
        default_factory=list,
        description="Optional additional CIDRs to collapse/summarize alongside 'cidr'.",
    )
    check_db_overlaps: bool = Field(
        default=True,
        description="When true, checks whether 'cidr' overlaps any existing IPAM subnet in the org.",
    )


class SubnetCalculateResponse(BaseSchema):
    """Comprehensive CIDR math, VLSM allocations, and overlap diagnostics."""

    info: dict[str, Any]
    reverse_dns_network: str
    supernet: str | None = None
    split_subnets: list[str] = Field(default_factory=list)
    vlsm_allocations: dict[str, str] = Field(default_factory=dict)
    vlsm_details: list[dict[str, Any]] = Field(default_factory=list)
    candidate_overlaps: list[tuple[str, str]] = Field(default_factory=list)
    db_overlaps: list[dict[str, Any]] = Field(default_factory=list)
    has_overlaps: bool = False
    summarized_cidrs: list[str] = Field(default_factory=list)


class IpAllocationCreateRequest(BaseSchema):
    """Explicit IP allocation request within a subnet."""

    ip_address: str = Field(..., min_length=2, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    device_id: str | None = None
    mac_address: str | None = Field(default=None, max_length=32)
    allocation_type: Literal["static", "dhcp", "slaac", "vip", "loopback", "gateway"] = "static"
    status: Literal["active", "reserved", "dhcp", "deprecated", "conflict"] = "active"

    @field_validator("ip_address")
    @classmethod
    def _val_ip(cls, value: str) -> str:
        normalized = normalize_ip_address(value)
        if normalized is None:
            raise ValueError("Invalid IP address")
        return normalized

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)


class AllocateNextIpRequest(BaseSchema):
    """Automatic next-free IP address allocation parameters."""

    hostname: str | None = Field(default=None, max_length=255)
    device_id: str | None = None
    mac_address: str | None = Field(default=None, max_length=32)
    allocation_type: Literal["static", "dhcp", "slaac", "vip", "loopback", "gateway"] = "static"
    status: Literal["active", "reserved", "dhcp"] = "active"
    start_ip: str | None = Field(
        default=None,
        description="Optional starting IP address within the subnet to begin scanning from.",
    )
    exclude_ips: list[str] = Field(default_factory=list)
    include_gateway: bool = False

    @field_validator("mac_address")
    @classmethod
    def _val_mac(cls, value: str | None) -> str | None:
        return normalize_mac_address(value)


class IpAllocationResponse(BaseSchema):
    """Full IPAM IP address allocation record."""

    id: str
    org_id: str
    subnet_id: str
    device_id: str | None = None
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    allocation_type: str
    status: str
    is_active: bool
    last_seen_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class IpAllocationListResponse(BaseSchema):
    """List of IP allocations within a subnet along with live utilization summary."""

    subnet_id: str
    cidr: str
    utilization: dict[str, Any]
    total: int
    items: list[IpAllocationResponse]


class VlanCreateRequest(BaseSchema):
    """Create payload for an IEEE 802.1Q VLAN."""

    vlan_id_num: int = Field(
        ...,
        ge=1,
        le=4094,
        validation_alias=AliasChoices("vlan_id_num", "vlan_id", "vid"),
    )
    name: str = Field(..., min_length=1, max_length=128)
    site_id: str | None = None
    description: str | None = Field(default=None, max_length=1000)
    status: Literal["active", "reserved", "deprecated"] = "active"
    subnet_cidr: str | None = Field(default=None, max_length=64)


class VlanResponse(BaseSchema):
    """Full IEEE 802.1Q VLAN representation."""

    id: str
    org_id: str
    site_id: str | None = None
    site_name: str | None = None
    vlan_id_num: int
    name: str
    description: str | None = None
    status: str
    subnet_cidr: str | None = None
    is_extended_range: bool
    is_active: bool
    subnet_count: int = 0
    interface_count: int = 0
    created_at: datetime
    updated_at: datetime


class VlanListResponse(BaseSchema):
    """Paginated VLAN catalog."""

    items: list[VlanResponse]
    meta: PaginationMeta


class CredentialCreateRequest(BaseSchema):
    """Create payload for a Fernet-encrypted credential vault profile.

    Secret fields are serialized and encrypted with :class:`CredentialVault`
    before storage and are never returned by read endpoints.
    """

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    credential_type: str = Field(default=CredentialType.SNMP_V2C.value, max_length=32)
    snmp_version: str | None = Field(default=None, max_length=16)
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("port", "default_port"),
    )
    timeout_seconds: float = Field(default=3.0, gt=0.0, le=120.0)
    retries: int = Field(default=2, ge=0, le=10)
    is_default: bool = False
    # Write-only secret fields
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512, repr=False)
    enable_secret: str | None = Field(default=None, max_length=512, repr=False)
    snmp_community: str | None = Field(default=None, max_length=256, repr=False)
    snmp_auth_protocol: str | None = Field(default=None, max_length=32)
    snmp_auth_password: str | None = Field(
        default=None,
        max_length=256,
        repr=False,
        validation_alias=AliasChoices("snmp_auth_password", "auth_passphrase"),
    )
    snmp_priv_protocol: str | None = Field(default=None, max_length=32)
    snmp_priv_password: str | None = Field(
        default=None,
        max_length=256,
        repr=False,
        validation_alias=AliasChoices("snmp_priv_password", "priv_passphrase"),
    )
    snmp_context_name: str | None = Field(default=None, max_length=128)
    ssh_private_key: str | None = Field(default=None, max_length=16384, repr=False)
    ssh_passphrase: str | None = Field(default=None, max_length=256, repr=False)
    api_token: str | None = Field(default=None, max_length=2048, repr=False)
    secret_payload: dict[str, Any] = Field(default_factory=dict, repr=False)


class CredentialUpdateRequest(BaseSchema):
    """Partial update payload for a credential vault profile; omitted secrets remain untouched."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    snmp_version: str | None = Field(default=None, max_length=16)
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("port", "default_port"),
    )
    timeout_seconds: float | None = Field(default=None, gt=0.0, le=120.0)
    retries: int | None = Field(default=None, ge=0, le=10)
    is_default: bool | None = None
    # Optional secret rotation fields
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512, repr=False)
    enable_secret: str | None = Field(default=None, max_length=512, repr=False)
    snmp_community: str | None = Field(default=None, max_length=256, repr=False)
    snmp_auth_protocol: str | None = Field(default=None, max_length=32)
    snmp_auth_password: str | None = Field(
        default=None,
        max_length=256,
        repr=False,
        validation_alias=AliasChoices("snmp_auth_password", "auth_passphrase"),
    )
    snmp_priv_protocol: str | None = Field(default=None, max_length=32)
    snmp_priv_password: str | None = Field(
        default=None,
        max_length=256,
        repr=False,
        validation_alias=AliasChoices("snmp_priv_password", "priv_passphrase"),
    )
    snmp_context_name: str | None = Field(default=None, max_length=128)
    ssh_private_key: str | None = Field(default=None, max_length=16384, repr=False)
    ssh_passphrase: str | None = Field(default=None, max_length=256, repr=False)
    api_token: str | None = Field(default=None, max_length=2048, repr=False)
    secret_payload: dict[str, Any] | None = Field(default=None, repr=False)


class CredentialResponse(BaseSchema):
    """Strictly redacted metadata view of a credential profile (ZERO secret leakage)."""

    id: str
    org_id: str
    name: str
    description: str | None = None
    credential_type: str
    snmp_version: str | None = None
    port: int
    timeout_seconds: float
    retries: int
    is_default: bool
    is_snmp: bool
    has_secret: bool
    secret_fingerprint: str | None = None
    attached_device_count: int = 0
    created_at: datetime
    updated_at: datetime


class CredentialListResponse(BaseSchema):
    """Paginated list of redacted credential profiles."""

    items: list[CredentialResponse]
    meta: PaginationMeta


class OuiLookupResponse(BaseSchema):
    """MAC address normalization, IEEE OUI vendor lookup, and EUI-64 derivation."""

    input_mac: str
    canonical_mac: str
    formats: dict[str, str]
    oui: str
    vendor: str | None = None
    known_vendor: bool
    is_broadcast: bool
    is_multicast: bool
    is_locally_administered: bool
    eui64_link_local_ipv6: str


class PortLookupResponse(BaseSchema):
    """TCP/UDP well-known port service classification and metadata."""

    port: int
    protocol_requested: str
    port_class: str
    is_ephemeral: bool
    known: bool
    service: str | None = None
    protocol: str | None = None
    category: str | None = None
    description: str | None = None
    encrypted: bool | None = None


# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------


def _serialize_subnet(
    subnet: Subnet,
    *,
    allocated_count: int = 0,
    site_name: str | None = None,
) -> SubnetResponse:
    net = subnet.network
    usable = subnet.total_usable_hosts
    available = max(0, usable - allocated_count)
    util_pct = round(min(100.0, (allocated_count / usable) * 100.0), 2) if usable > 0 else 0.0
    bcast = str(net.broadcast_address) if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31 else None

    return SubnetResponse(
        id=subnet.id,
        org_id=subnet.org_id,
        site_id=subnet.site_id,
        site_name=site_name,
        cidr=subnet.cidr,
        name=subnet.name,
        description=subnet.description,
        ip_version=net.version,
        network_address=str(net.network_address),
        broadcast_address=bcast,
        netmask=str(net.netmask),
        prefix_length=net.prefixlen,
        gateway_ip=subnet.gateway_ip,
        vlan_number=subnet.vlan_number,
        dns_servers=list(subnet.dns_servers_json or []),
        dhcp_enabled=subnet.dhcp_enabled,
        scan_enabled=subnet.scan_enabled,
        total_usable_hosts=usable,
        allocated_count=allocated_count,
        available_count=available,
        utilization_pct=util_pct,
        last_scanned_at=subnet.last_scanned_at,
        created_at=subnet.created_at,
        updated_at=subnet.updated_at,
    )


def _serialize_allocation(alloc: IpAllocation) -> IpAllocationResponse:
    return IpAllocationResponse(
        id=alloc.id,
        org_id=alloc.org_id,
        subnet_id=alloc.subnet_id,
        device_id=alloc.device_id,
        ip_address=alloc.ip_address,
        mac_address=alloc.mac_address,
        hostname=alloc.hostname,
        allocation_type=alloc.allocation_type,
        status=alloc.status,
        is_active=alloc.is_active,
        last_seen_at=alloc.last_seen_at,
        created_at=alloc.created_at,
        updated_at=alloc.updated_at,
    )


def _serialize_vlan(
    vlan: Vlan,
    *,
    site_name: str | None = None,
    subnet_count: int = 0,
    interface_count: int = 0,
) -> VlanResponse:
    return VlanResponse(
        id=vlan.id,
        org_id=vlan.org_id,
        site_id=vlan.site_id,
        site_name=site_name,
        vlan_id_num=vlan.vlan_id_num,
        name=vlan.name,
        description=vlan.description,
        status=vlan.status,
        subnet_cidr=vlan.subnet_cidr,
        is_extended_range=vlan.is_extended_range,
        is_active=vlan.is_active,
        subnet_count=subnet_count,
        interface_count=interface_count,
        created_at=vlan.created_at,
        updated_at=vlan.updated_at,
    )


def _secret_fingerprint(encrypted_payload: str | None) -> str | None:
    if not encrypted_payload:
        return None
    return hashlib.sha256(encrypted_payload.encode("utf-8")).hexdigest()[:16]


def _serialize_credential(
    cred: CredentialProfile,
    *,
    attached_device_count: int = 0,
) -> CredentialResponse:
    """Serialize credential metadata without EVER exposing plaintext or ciphertext."""
    return CredentialResponse(
        id=cred.id,
        org_id=cred.org_id,
        name=cred.name,
        description=cred.description,
        credential_type=cred.credential_type,
        snmp_version=cred.snmp_version,
        port=cred.port,
        timeout_seconds=cred.timeout_seconds,
        retries=cred.retries,
        is_default=cred.is_default,
        is_snmp=cred.is_snmp,
        has_secret=bool(cred.encrypted_payload),
        secret_fingerprint=_secret_fingerprint(cred.encrypted_payload),
        attached_device_count=attached_device_count,
        created_at=cred.created_at,
        updated_at=cred.updated_at,
    )


def _extract_secret_dict(payload: CredentialCreateRequest | CredentialUpdateRequest) -> dict[str, Any]:
    secret_dict: dict[str, Any] = {}
    if getattr(payload, "secret_payload", None):
        secret_dict.update(dict(payload.secret_payload or {}))
    for field_name in _SECRET_FIELD_NAMES:
        val = getattr(payload, field_name, None)
        if val is not None:
            secret_dict[field_name] = val
    return secret_dict


def _refresh_subnet_utilization(db: Session, org_id: str, subnet: Subnet) -> int:
    alloc_repo = BaseRepository(db, model=IpAllocation, org_id=org_id)
    allocated = alloc_repo.count(filters={"subnet_id": subnet.id})
    subnet.recalculate_utilization(allocated)
    db.add(subnet)
    return allocated


# ---------------------------------------------------------------------------
# Subnet Endpoints (static /subnets/calculate BEFORE /subnets/{subnet_id})
# ---------------------------------------------------------------------------


@router.get(
    "/subnets",
    response_model=SubnetListResponse,
    summary="List managed IPAM subnets",
)
def list_subnets(
    site_id: str | None = Query(default=None),
    vlan_number: int | None = Query(default=None, ge=1, le=4094),
    dhcp_enabled: bool | None = Query(default=None),
    scan_enabled: bool | None = Query(default=None),
    ip_version: Literal[4, 6] | None = Query(default=None),
    search: str | None = Query(default=None, max_length=160),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SubnetListResponse:
    """List IPAM subnets with live allocation counts and utilization percentages."""
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    alloc_repo = BaseRepository(db, model=IpAllocation, org_id=ctx.org_id)

    filters: dict[str, Any] = {}
    if site_id:
        filters["site_id"] = site_id
    if vlan_number is not None:
        filters["vlan_number"] = vlan_number
    if dhcp_enabled is not None:
        filters["dhcp_enabled"] = dhcp_enabled
    if scan_enabled is not None:
        filters["scan_enabled"] = scan_enabled

    all_matching = subnet_repo.list(filters=filters or None)
    if ip_version is not None:
        all_matching = [s for s in all_matching if s.network.version == ip_version]
    if search:
        needle = search.strip().lower()
        all_matching = [
            s
            for s in all_matching
            if needle in s.cidr.lower()
            or needle in s.name.lower()
            or needle in (s.description or "").lower()
        ]

    total = len(all_matching)
    start = (page - 1) * page_size
    sliced = all_matching[start : start + page_size]

    site_ids = list({s.site_id for s in sliced if s.site_id})
    sites_map = {
        s.id: s.name for s in SiteRepository(db, org_id=ctx.org_id).get_many_by_ids(site_ids)
    }

    items = [
        _serialize_subnet(
            sub,
            allocated_count=alloc_repo.count(filters={"subnet_id": sub.id}),
            site_name=sites_map.get(sub.site_id) if sub.site_id else None,
        )
        for sub in sliced
    ]
    return SubnetListResponse(
        items=items,
        meta=PaginationMeta.from_counts(total=total, page=page, page_size=page_size),
    )


@router.post(
    "/subnets/calculate",
    response_model=SubnetCalculateResponse,
    summary="CIDR calculator, VLSM planner, summarization, and overlap checker",
)
def calculate_subnet_plan(
    payload: SubnetCalculateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SubnetCalculateResponse:
    """Compute exact IPv4/IPv6 CIDR geometry, equal splits, VLSM allocations, and overlaps."""
    info = calculate_subnet(payload.cidr, strict=False)
    rev_ptr = reverse_dns_pointer(info.network_address)

    supernet: str | None = None
    if payload.supernet_prefix is not None:
        supernet = calculate_supernet(info.cidr, payload.supernet_prefix)
    elif info.prefix_length > 0:
        supernet = calculate_supernet(info.cidr, info.prefix_length - 1)

    split_list: list[str] = []
    if payload.split_prefix is not None or payload.split_count is not None:
        split_list = split_subnet(
            info.cidr,
            new_prefix=payload.split_prefix,
            count=payload.split_count,
        )

    vlsm_allocs: dict[str, str] = {}
    vlsm_details: list[dict[str, Any]] = []
    if payload.vlsm_requirements:
        vlsm_allocs = allocate_vlsm(info.cidr, payload.vlsm_requirements)
        for seg_name, alloc_cidr in vlsm_allocs.items():
            seg_info = calculate_subnet(alloc_cidr)
            vlsm_details.append(
                {
                    "segment": seg_name,
                    "requested_hosts": payload.vlsm_requirements[seg_name],
                    "allocated_cidr": alloc_cidr,
                    "usable_hosts": seg_info.usable_hosts,
                    "first_usable": seg_info.first_usable,
                    "last_usable": seg_info.last_usable,
                    "netmask": seg_info.netmask,
                }
            )

    candidate_overlaps: list[tuple[str, str]] = []
    if payload.compare_cidrs:
        candidate_overlaps = find_overlapping_cidrs([info.cidr, *payload.compare_cidrs])

    db_overlaps: list[dict[str, Any]] = []
    if payload.check_db_overlaps:
        existing_subnets = SubnetRepository(db, org_id=ctx.org_id).list()
        for existing in existing_subnets:
            if cidrs_overlap(info.cidr, existing.cidr):
                db_overlaps.append(
                    {
                        "subnet_id": existing.id,
                        "name": existing.name,
                        "cidr": existing.cidr,
                        "site_id": existing.site_id,
                    }
                )

    summarized: list[str] = []
    if payload.summarize_with:
        summarized = summarize_cidrs([info.cidr, *payload.summarize_with])

    return SubnetCalculateResponse(
        info=info.to_dict(),
        reverse_dns_network=rev_ptr,
        supernet=supernet,
        split_subnets=split_list,
        vlsm_allocations=vlsm_allocs,
        vlsm_details=vlsm_details,
        candidate_overlaps=candidate_overlaps,
        db_overlaps=db_overlaps,
        has_overlaps=bool(candidate_overlaps or db_overlaps),
        summarized_cidrs=summarized,
    )


@router.post(
    "/subnets",
    response_model=SubnetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a managed IPAM subnet",
)
def create_subnet(
    payload: SubnetCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SubnetResponse:
    """Register a new IPv4 or IPv6 subnet in IPAM with optional overlap protection."""
    ctx.require_write("subnets")
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)

    site_name: str | None = None
    if payload.site_id is not None:
        site = SiteRepository(db, org_id=ctx.org_id).get_by_id_or_raise(payload.site_id)
        site_name = site.name

    if subnet_repo.get_by_cidr(payload.cidr) is not None:
        raise ConflictError(
            f"Subnet '{payload.cidr}' already exists in this organization",
            details={"cidr": payload.cidr},
        )

    if not payload.allow_overlap:
        for existing in subnet_repo.list():
            if existing.overlaps_cidr(payload.cidr):
                raise ConflictError(
                    f"Subnet '{payload.cidr}' overlaps existing subnet '{existing.cidr}' ({existing.name})",
                    details={
                        "cidr": payload.cidr,
                        "overlapping_subnet_id": existing.id,
                        "overlapping_cidr": existing.cidr,
                    },
                )

    subnet = subnet_repo.create(
        {
            "org_id": ctx.org_id,
            "site_id": payload.site_id,
            "cidr": payload.cidr,
            "name": payload.name.strip(),
            "description": payload.description,
            "gateway_ip": payload.gateway_ip,
            "vlan_number": payload.vlan_number,
            "dns_servers_json": list(payload.dns_servers),
            "dhcp_enabled": payload.dhcp_enabled,
            "scan_enabled": payload.scan_enabled,
            "utilization_pct": 0.0,
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="subnet",
        resource_id=subnet.id,
        summary=f"Created IPAM subnet {subnet.cidr} ({subnet.name})",
        details={"cidr": subnet.cidr, "site_id": subnet.site_id},
    )
    db.commit()
    db.refresh(subnet)
    return _serialize_subnet(subnet, allocated_count=0, site_name=site_name)


@router.get(
    "/subnets/{subnet_id}",
    response_model=SubnetResponse,
    summary="Get a single IPAM subnet",
)
def get_subnet(
    subnet_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SubnetResponse:
    """Retrieve a single subnet with live IP allocation counts."""
    subnet = SubnetRepository(db, org_id=ctx.org_id).get_by_id_or_raise(subnet_id)
    alloc_count = BaseRepository(db, model=IpAllocation, org_id=ctx.org_id).count(
        filters={"subnet_id": subnet.id}
    )
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(subnet.site_id) if subnet.site_id else None
    return _serialize_subnet(
        subnet,
        allocated_count=alloc_count,
        site_name=site.name if site else None,
    )


@router.patch(
    "/subnets/{subnet_id}",
    response_model=SubnetResponse,
    summary="Update a managed IPAM subnet",
)
def update_subnet(
    subnet_id: str,
    payload: SubnetUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SubnetResponse:
    """Partially update subnet metadata, gateway IP, VLAN number, DNS servers, or scan flags."""
    ctx.require_write("subnets")
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    subnet = subnet_repo.get_by_id_or_raise(subnet_id)

    raw_patch = payload.model_dump(exclude_unset=True)
    patch: dict[str, Any] = {}

    if "name" in raw_patch and raw_patch["name"] is not None:
        patch["name"] = raw_patch["name"].strip()
    if "description" in raw_patch:
        patch["description"] = raw_patch["description"]
    if "site_id" in raw_patch:
        if raw_patch["site_id"] is not None:
            SiteRepository(db, org_id=ctx.org_id).get_by_id_or_raise(raw_patch["site_id"])
        patch["site_id"] = raw_patch["site_id"]
    if "gateway_ip" in raw_patch:
        gw = raw_patch["gateway_ip"]
        if gw is not None:
            normalized_gw = normalize_ip_address(gw)
            if normalized_gw is None or not subnet.contains_ip(normalized_gw):
                raise ValidationError(
                    f"gateway_ip '{gw}' does not belong to subnet '{subnet.cidr}'",
                    details={"gateway_ip": gw, "cidr": subnet.cidr},
                )
            patch["gateway_ip"] = normalized_gw
        else:
            patch["gateway_ip"] = None
    if "vlan_number" in raw_patch:
        patch["vlan_number"] = raw_patch["vlan_number"]
    if "dns_servers" in raw_patch and raw_patch["dns_servers"] is not None:
        patch["dns_servers_json"] = [
            ip for raw in raw_patch["dns_servers"] if (ip := normalize_ip_address(raw)) is not None
        ]
    if "dhcp_enabled" in raw_patch:
        patch["dhcp_enabled"] = raw_patch["dhcp_enabled"]
    if "scan_enabled" in raw_patch:
        patch["scan_enabled"] = raw_patch["scan_enabled"]

    updated = subnet_repo.update(subnet, patch)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="subnet",
        resource_id=updated.id,
        summary=f"Updated IPAM subnet {updated.cidr}",
        details={"updated_fields": sorted(patch.keys())},
    )
    db.commit()
    db.refresh(updated)
    alloc_count = BaseRepository(db, model=IpAllocation, org_id=ctx.org_id).count(
        filters={"subnet_id": updated.id}
    )
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(updated.site_id) if updated.site_id else None
    return _serialize_subnet(
        updated,
        allocated_count=alloc_count,
        site_name=site.name if site else None,
    )


@router.delete(
    "/subnets/{subnet_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete an IPAM subnet",
)
def delete_subnet(
    subnet_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a subnet from IPAM."""
    ctx.require_write("subnets")
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    subnet = subnet_repo.get_by_id_or_raise(subnet_id)
    subnet_repo.soft_delete(subnet)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="subnet",
        resource_id=subnet.id,
        summary=f"Soft-deleted IPAM subnet {subnet.cidr}",
        details={"cidr": subnet.cidr},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# IP Allocation Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/subnets/{subnet_id}/allocations",
    response_model=IpAllocationListResponse,
    summary="List IP allocations inside a subnet",
)
def list_subnet_allocations(
    subnet_id: str,
    status_filter: str | None = Query(default=None, alias="status"),
    allocation_type: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=160),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> IpAllocationListResponse:
    """List all IP allocations within a subnet sorted numerically by IP address."""
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    subnet = subnet_repo.get_by_id_or_raise(subnet_id)
    allocations = subnet_repo.list_allocations(subnet.id, status=status_filter)

    if allocation_type:
        allocations = [a for a in allocations if a.allocation_type == allocation_type]
    if device_id:
        allocations = [a for a in allocations if a.device_id == device_id]
    if search:
        needle = search.strip().lower()
        allocations = [
            a
            for a in allocations
            if needle in a.ip_address.lower()
            or needle in (a.hostname or "").lower()
            or needle in (a.mac_address or "").lower()
        ]

    allocations.sort(key=lambda a: int(ipaddress.ip_address(a.ip_address)))
    utilization = subnet_repo.get_utilization(subnet.id)
    return IpAllocationListResponse(
        subnet_id=subnet.id,
        cidr=subnet.cidr,
        utilization=utilization,
        total=len(allocations),
        items=[_serialize_allocation(a) for a in allocations],
    )


@router.post(
    "/subnets/{subnet_id}/allocations",
    response_model=IpAllocationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Allocate a specific IP address inside a subnet",
)
def create_subnet_allocation(
    subnet_id: str,
    payload: IpAllocationCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> IpAllocationResponse:
    """Validate CIDR membership and allocate an explicit IP address in IPAM."""
    ctx.require_write("ip_allocations")
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    subnet = subnet_repo.get_by_id_or_raise(subnet_id)

    if payload.device_id is not None:
        DeviceRepository(db, org_id=ctx.org_id).get_by_id_or_raise(payload.device_id)

    alloc = subnet_repo.allocate_ip(
        subnet.id,
        payload.ip_address,
        hostname=payload.hostname,
        device_id=payload.device_id,
        mac_address=payload.mac_address,
        status=payload.status,
    )
    alloc.allocation_type = payload.allocation_type
    db.add(alloc)
    _refresh_subnet_utilization(db, ctx.org_id, subnet)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="ip_allocation",
        resource_id=alloc.id,
        summary=f"Allocated IP {alloc.ip_address} in subnet {subnet.cidr}",
        details={"subnet_id": subnet.id, "ip_address": alloc.ip_address},
    )
    db.commit()
    db.refresh(alloc)
    return _serialize_allocation(alloc)


@router.post(
    "/subnets/{subnet_id}/allocate-next",
    response_model=IpAllocationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Automatically allocate the next available IP address in a subnet",
)
def allocate_next_ip(
    subnet_id: str,
    payload: AllocateNextIpRequest | None = None,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> IpAllocationResponse:
    """Scan usable host space in a subnet and allocate the first unoccupied IP address."""
    ctx.require_write("ip_allocations")
    req = payload or AllocateNextIpRequest()
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    subnet = subnet_repo.get_by_id_or_raise(subnet_id)

    if req.device_id is not None:
        DeviceRepository(db, org_id=ctx.org_id).get_by_id_or_raise(req.device_id)

    existing_allocs = subnet_repo.list_allocations(subnet.id)
    occupied: set[str] = {a.ip_address for a in existing_allocs}
    if not req.include_gateway and subnet.gateway_ip:
        occupied.add(subnet.gateway_ip)
    for raw_excl in req.exclude_ips:
        norm = normalize_ip_address(raw_excl)
        if norm:
            occupied.add(norm)

    net = subnet.network
    start_bound: int | None = None
    if req.start_ip:
        start_addr = ipaddress.ip_address(req.start_ip.strip())
        if start_addr.version != net.version or start_addr not in net:
            raise ValidationError(
                f"start_ip '{start_addr}' does not belong to subnet '{net}'",
                details={"start_ip": str(start_addr), "cidr": str(net)},
            )
        start_bound = int(start_addr)

    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31:
        candidate_iter = net.hosts()
    else:
        candidate_iter = iter(net)

    chosen_ip: str | None = None
    # Bound iteration to avoid hanging on huge IPv6 prefixes while still finding free slots immediately
    max_scan = 131_072
    scanned = 0
    for addr in candidate_iter:
        if start_bound is not None and int(addr) < start_bound:
            continue
        scanned += 1
        candidate_str = str(addr)
        if candidate_str not in occupied:
            chosen_ip = candidate_str
            break
        if scanned >= max_scan:
            break

    if chosen_ip is None:
        raise ConflictError(
            f"Subnet '{subnet.cidr}' has no available IP addresses left to allocate",
            error_code="SUBNET_EXHAUSTED",
            details={"subnet_id": subnet.id, "cidr": subnet.cidr},
        )

    alloc = subnet_repo.allocate_ip(
        subnet.id,
        chosen_ip,
        hostname=req.hostname,
        device_id=req.device_id,
        mac_address=req.mac_address,
        status=req.status,
    )
    alloc.allocation_type = req.allocation_type
    db.add(alloc)
    _refresh_subnet_utilization(db, ctx.org_id, subnet)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="ip_allocation",
        resource_id=alloc.id,
        summary=f"Auto-allocated next IP {alloc.ip_address} in subnet {subnet.cidr}",
        details={"subnet_id": subnet.id, "ip_address": alloc.ip_address},
    )
    db.commit()
    db.refresh(alloc)
    return _serialize_allocation(alloc)


@router.delete(
    "/allocations/{allocation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Release an IP address allocation",
)
def delete_allocation(
    allocation_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Delete an IP allocation by ID and recalculate parent subnet utilization."""
    ctx.require_write("ip_allocations")
    alloc_repo = BaseRepository(db, model=IpAllocation, org_id=ctx.org_id)
    alloc = alloc_repo.get_by_id_or_raise(allocation_id)
    parent_subnet_id = alloc.subnet_id
    released_ip = alloc.ip_address
    alloc_repo.delete(alloc)

    subnet = SubnetRepository(db, org_id=ctx.org_id).get_by_id(parent_subnet_id)
    if subnet is not None:
        _refresh_subnet_utilization(db, ctx.org_id, subnet)

    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="ip_allocation",
        resource_id=allocation_id,
        summary=f"Released IP allocation {released_ip}",
        details={"subnet_id": parent_subnet_id, "ip_address": released_ip},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# VLAN Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/vlans",
    response_model=VlanListResponse,
    summary="List IEEE 802.1Q VLANs",
)
def list_vlans(
    site_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    min_vlan: int | None = Query(default=None, ge=1, le=4094),
    max_vlan: int | None = Query(default=None, ge=1, le=4094),
    search: str | None = Query(default=None, max_length=128),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> VlanListResponse:
    """List configured VLANs with range, site, status, and text filtering."""
    vlan_repo = VlanRepository(db, org_id=ctx.org_id)
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    iface_repo = InterfaceRepository(db, org_id=ctx.org_id)

    filters: dict[str, Any] = {}
    if site_id:
        filters["site_id"] = site_id
    if status_filter:
        filters["status"] = status_filter.strip().lower()
    if min_vlan is not None:
        filters["vlan_id_num__gte"] = min_vlan
    if max_vlan is not None:
        filters["vlan_id_num__lte"] = max_vlan
    if search:
        filters["name__icontains"] = search.strip()

    page_res = vlan_repo.paginate(page=page, page_size=page_size, filters=filters or None)
    site_ids = list({v.site_id for v in page_res.items if v.site_id})
    sites_map = {
        s.id: s.name for s in SiteRepository(db, org_id=ctx.org_id).get_many_by_ids(site_ids)
    }

    items = [
        _serialize_vlan(
            v,
            site_name=sites_map.get(v.site_id) if v.site_id else None,
            subnet_count=subnet_repo.count(filters={"vlan_number": v.vlan_id_num}),
            interface_count=iface_repo.count(filters={"vlan_id": v.vlan_id_num}),
        )
        for v in page_res.items
    ]
    return VlanListResponse(
        items=items,
        meta=PaginationMeta.from_counts(total=page_res.total, page=page, page_size=page_size),
    )


@router.post(
    "/vlans",
    response_model=VlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an IEEE 802.1Q VLAN",
)
def create_vlan(
    payload: VlanCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> VlanResponse:
    """Register a new Layer-2 VLAN scoped to the organization and optional site."""
    ctx.require_write("vlans")
    vlan_repo = VlanRepository(db, org_id=ctx.org_id)

    site_name: str | None = None
    if payload.site_id is not None:
        site = SiteRepository(db, org_id=ctx.org_id).get_by_id_or_raise(payload.site_id)
        site_name = site.name

    existing = vlan_repo.get_by_vlan_id(payload.vlan_id_num, site_id=payload.site_id)
    if existing is not None and existing.site_id == payload.site_id:
        raise ConflictError(
            f"VLAN {payload.vlan_id_num} already exists in this scope",
            details={"vlan_id_num": payload.vlan_id_num, "site_id": payload.site_id},
        )

    normalized_cidr: str | None = None
    if payload.subnet_cidr:
        normalized_cidr = str(parse_network(payload.subnet_cidr, strict=False))

    vlan = vlan_repo.create(
        {
            "org_id": ctx.org_id,
            "site_id": payload.site_id,
            "vlan_id_num": payload.vlan_id_num,
            "name": payload.name.strip(),
            "description": payload.description,
            "status": payload.status,
            "subnet_cidr": normalized_cidr,
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="vlan",
        resource_id=vlan.id,
        summary=f"Created VLAN {vlan.vlan_id_num} ({vlan.name})",
        details={"vlan_id_num": vlan.vlan_id_num, "site_id": vlan.site_id},
    )
    db.commit()
    db.refresh(vlan)
    return _serialize_vlan(vlan, site_name=site_name)


@router.get(
    "/vlans/{vlan_id}",
    response_model=VlanResponse,
    summary="Get a single VLAN by ID",
)
def get_vlan(
    vlan_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> VlanResponse:
    """Retrieve a single VLAN record along with linked subnet and interface counts."""
    vlan = VlanRepository(db, org_id=ctx.org_id).get_by_id_or_raise(vlan_id)
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(vlan.site_id) if vlan.site_id else None
    subnet_count = SubnetRepository(db, org_id=ctx.org_id).count(
        filters={"vlan_number": vlan.vlan_id_num}
    )
    iface_count = InterfaceRepository(db, org_id=ctx.org_id).count(
        filters={"vlan_id": vlan.vlan_id_num}
    )
    return _serialize_vlan(
        vlan,
        site_name=site.name if site else None,
        subnet_count=subnet_count,
        interface_count=iface_count,
    )


@router.delete(
    "/vlans/{vlan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a VLAN",
)
def delete_vlan(
    vlan_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Delete a VLAN record."""
    ctx.require_write("vlans")
    vlan_repo = VlanRepository(db, org_id=ctx.org_id)
    vlan = vlan_repo.get_by_id_or_raise(vlan_id)
    vid = vlan.vlan_id_num
    vname = vlan.name
    vlan_repo.delete(vlan)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="vlan",
        resource_id=vlan_id,
        summary=f"Deleted VLAN {vid} ({vname})",
        details={"vlan_id_num": vid},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Encrypted Credential Vault Endpoints (NEVER expose secrets in responses!)
# ---------------------------------------------------------------------------


@router.get(
    "/credentials",
    response_model=CredentialListResponse,
    summary="List redacted credential vault profiles",
)
def list_credentials(
    credential_type: str | None = Query(default=None),
    is_default: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=160),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> CredentialListResponse:
    """List credential profiles with redacted metadata (never exposes secrets or ciphertext)."""
    cred_repo = CredentialRepository(db, org_id=ctx.org_id)
    filters: dict[str, Any] = {}
    if credential_type:
        filters["credential_type"] = credential_type.strip().lower()
    if is_default is not None:
        filters["is_default"] = is_default
    if search:
        filters["name__icontains"] = search.strip()

    page_res = cred_repo.paginate(page=page, page_size=page_size, filters=filters or None)
    items = [
        _serialize_credential(
            cred,
            attached_device_count=cred_repo.count_assigned_devices(cred.id),
        )
        for cred in page_res.items
    ]
    return CredentialListResponse(
        items=items,
        meta=PaginationMeta.from_counts(total=page_res.total, page=page, page_size=page_size),
    )


@router.post(
    "/credentials",
    response_model=CredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an encrypted credential vault profile",
)
def create_credential(
    payload: CredentialCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> CredentialResponse:
    """Encrypt secret material with Fernet and persist a reusable credential profile."""
    ctx.require_write("credentials")
    cred_repo = CredentialRepository(db, org_id=ctx.org_id)

    cleaned_name = payload.name.strip()
    if cred_repo.get_by_name(cleaned_name) is not None:
        raise ConflictError(
            f"Credential profile '{cleaned_name}' already exists in this organization",
            details={"name": cleaned_name},
        )

    try:
        cred_type = CredentialType(payload.credential_type.strip().lower())
    except ValueError as exc:
        raise ValidationError(
            f"Unsupported credential_type {payload.credential_type!r}",
            details={"valid": [c.value for c in CredentialType]},
        ) from exc

    snmp_ver: str | None = payload.snmp_version
    if snmp_ver is not None:
        try:
            snmp_ver = SnmpVersion(snmp_ver.strip().lower()).value
        except ValueError as exc:
            raise ValidationError(f"Unsupported snmp_version {snmp_ver!r}") from exc
    elif cred_type == CredentialType.SNMP_V1:
        snmp_ver = SnmpVersion.V1.value
    elif cred_type == CredentialType.SNMP_V2C:
        snmp_ver = SnmpVersion.V2C.value
    elif cred_type == CredentialType.SNMP_V3:
        snmp_ver = SnmpVersion.V3.value

    secret_dict = _extract_secret_dict(payload)
    vault = get_credential_vault()
    encrypted_payload = vault.encrypt_json(secret_dict)

    if payload.is_default:
        for existing_default in cred_repo.list_default_profiles():
            if existing_default.credential_type == cred_type.value:
                cred_repo.update(existing_default, {"is_default": False}, flush=False)

    cred = cred_repo.create(
        {
            "org_id": ctx.org_id,
            "name": cleaned_name,
            "description": payload.description,
            "credential_type": cred_type.value,
            "snmp_version": snmp_ver,
            "encrypted_payload": encrypted_payload,
            "port": payload.port if payload.port is not None else cred_type.default_port,
            "timeout_seconds": payload.timeout_seconds,
            "retries": payload.retries,
            "is_default": payload.is_default,
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="credential_profile",
        resource_id=cred.id,
        summary=f"Created {cred.credential_type} credential profile '{cred.name}'",
        details={"credential_type": cred.credential_type, "port": cred.port},
    )
    db.commit()
    db.refresh(cred)
    return _serialize_credential(cred, attached_device_count=0)


@router.get(
    "/credentials/{credential_id}",
    response_model=CredentialResponse,
    summary="Get redacted metadata for a credential profile",
)
def get_credential(
    credential_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> CredentialResponse:
    """Retrieve strictly redacted metadata for a single credential profile."""
    cred_repo = CredentialRepository(db, org_id=ctx.org_id)
    cred = cred_repo.get_by_id_or_raise(credential_id)
    return _serialize_credential(
        cred,
        attached_device_count=cred_repo.count_assigned_devices(cred.id),
    )


@router.patch(
    "/credentials/{credential_id}",
    response_model=CredentialResponse,
    summary="Update metadata or rotate secrets on a credential profile",
)
def update_credential(
    credential_id: str,
    payload: CredentialUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> CredentialResponse:
    """Update credential settings and optionally merge/rotate encrypted secret material."""
    ctx.require_write("credentials")
    cred_repo = CredentialRepository(db, org_id=ctx.org_id)
    cred = cred_repo.get_by_id_or_raise(credential_id)

    raw_patch = payload.model_dump(exclude_unset=True)
    patch: dict[str, Any] = {}

    if "name" in raw_patch and raw_patch["name"] is not None:
        cleaned = raw_patch["name"].strip()
        existing = cred_repo.get_by_name(cleaned)
        if existing is not None and existing.id != cred.id:
            raise ConflictError(
                f"Credential profile '{cleaned}' already exists",
                details={"name": cleaned},
            )
        patch["name"] = cleaned

    for meta_field in ("description", "snmp_version", "port", "timeout_seconds", "retries", "is_default"):
        if meta_field in raw_patch:
            patch[meta_field] = raw_patch[meta_field]

    new_secrets = _extract_secret_dict(payload)
    rotated = False
    if new_secrets:
        vault = get_credential_vault()
        try:
            current_secret = vault.decrypt_json(cred.encrypted_payload)
        except Exception:
            current_secret = {}
        current_secret.update(new_secrets)
        patch["encrypted_payload"] = vault.encrypt_json(current_secret)
        rotated = True

    updated = cred_repo.update(cred, patch) if patch else cred
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREDENTIAL_ROTATE if rotated else AuditAction.UPDATE,
        resource_type="credential_profile",
        resource_id=updated.id,
        summary=(
            f"Rotated secrets for credential profile '{updated.name}'"
            if rotated
            else f"Updated credential profile '{updated.name}'"
        ),
        details={"secret_rotated": rotated},
    )
    db.commit()
    db.refresh(updated)
    return _serialize_credential(
        updated,
        attached_device_count=cred_repo.count_assigned_devices(updated.id),
    )


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a credential profile",
)
def delete_credential(
    credential_id: str,
    detach_devices: bool = Query(
        default=True,
        description="Automatically unlink this credential profile from assigned devices.",
    ),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a credential vault profile."""
    ctx.require_write("credentials")
    cred_repo = CredentialRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    cred = cred_repo.get_by_id_or_raise(credential_id)

    assigned = device_repo.list(filters={"credential_profile_id": cred.id})
    if assigned and not detach_devices:
        raise ConflictError(
            f"Credential profile '{cred.name}' is still assigned to {len(assigned)} device(s)",
            details={"credential_id": cred.id, "device_count": len(assigned)},
        )
    for dev in assigned:
        device_repo.update(dev, {"credential_profile_id": None}, flush=False)

    cred_repo.soft_delete(cred)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="credential_profile",
        resource_id=cred.id,
        summary=f"Soft-deleted credential profile '{cred.name}'",
        details={"detached_devices": len(assigned)},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Network Utility Endpoints (OUI / MAC Lookup & Well-Known Port Registry)
# ---------------------------------------------------------------------------


@router.get(
    "/network-utils/oui/{mac}",
    response_model=OuiLookupResponse,
    summary="Lookup IEEE OUI hardware vendor and normalize MAC address formats",
)
def lookup_mac_oui(
    mac: str,
    ipv6_prefix: str = Query(
        default="fe80::",
        description="IPv6 /64 prefix used to derive modified IEEE EUI-64 address.",
    ),
) -> OuiLookupResponse:
    """Parse any standard MAC notation, identify the hardware vendor via OUI, and compute EUI-64."""
    canonical = format_mac(mac, style="colon", uppercase=False)
    oui = get_oui(mac)
    vendor = lookup_oui_vendor(mac)
    eui64 = mac_to_eui64(mac, ipv6_prefix=ipv6_prefix)

    return OuiLookupResponse(
        input_mac=mac,
        canonical_mac=canonical,
        formats={
            "colon": canonical,
            "colon_upper": format_mac(mac, style="colon", uppercase=True),
            "hyphen": format_mac(mac, style="hyphen", uppercase=True),
            "cisco": format_mac(mac, style="cisco", uppercase=False),
            "bare": format_mac(mac, style="bare", uppercase=False),
        },
        oui=oui,
        vendor=vendor,
        known_vendor=vendor is not None,
        is_broadcast=is_broadcast_mac(mac),
        is_multicast=is_multicast_mac(mac),
        is_locally_administered=is_locally_administered_mac(mac),
        eui64_link_local_ipv6=eui64,
    )


@router.get(
    "/network-utils/port/{port}",
    response_model=PortLookupResponse,
    summary="Lookup well-known TCP/UDP port service metadata",
)
def lookup_network_port(
    port: int,
    protocol: Literal["tcp", "udp", "any"] = Query(default="any"),
) -> PortLookupResponse:
    """Classify a TCP/UDP port number and resolve its well-known service metadata."""
    port_class = classify_port(port)
    ephemeral = is_ephemeral_port(port)

    if protocol == "any":
        info = WELL_KNOWN_PORTS.get(port)
    else:
        info = lookup_port(port, protocol=protocol)

    if info is None:
        return PortLookupResponse(
            port=port,
            protocol_requested=protocol,
            port_class=port_class,
            is_ephemeral=ephemeral,
            known=False,
        )

    return PortLookupResponse(
        port=info.port,
        protocol_requested=protocol,
        port_class=port_class,
        is_ephemeral=ephemeral,
        known=True,
        service=info.service,
        protocol=info.protocol,
        category=info.category,
        description=info.description,
        encrypted=info.encrypted,
    )


__all__ = [
    "AllocateNextIpRequest",
    "CredentialCreateRequest",
    "CredentialListResponse",
    "CredentialResponse",
    "CredentialUpdateRequest",
    "IpAllocationCreateRequest",
    "IpAllocationListResponse",
    "IpAllocationResponse",
    "OuiLookupResponse",
    "PortLookupResponse",
    "SubnetCalculateRequest",
    "SubnetCalculateResponse",
    "SubnetCreateRequest",
    "SubnetListResponse",
    "SubnetResponse",
    "SubnetUpdateRequest",
    "VlanCreateRequest",
    "VlanListResponse",
    "VlanResponse",
    "router",
]
