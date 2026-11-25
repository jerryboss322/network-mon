"""CMDB Sites & Racks REST API router (v1).

Provides full lifecycle management for physical locations (:class:`Site`) and
equipment cabinets (:class:`Rack`), including:

- Sites: paginated search/listing with live rack & device counts, CRUD, soft
  deletion, and rich site health/capacity summaries with Haversine proximity
  calculations to sibling sites.
- Racks: filtered listing with live U-unit occupancy metrics, CRUD with slot
  boundary validation, safe soft deletion, and visual top-to-bottom U-slot
  elevation diagrams including contiguous free-space blocks for capacity
  planning.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import AliasChoices, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_request_id
from app.core.security import (
    CIDRAllowlist,
    hash_api_key,
    verify_access_token,
)
from app.db.repositories.identity import (
    ApiKeyRepository,
    AuditLogRepository,
    OrganizationRepository,
    UserRepository,
)
from app.db.repositories.inventory import (
    DeviceRepository,
    RackRepository,
    SiteRepository,
    SubnetRepository,
    VlanRepository,
)
from app.api.deps import get_db_session as get_db
from app.db.seed import DEFAULT_ORG_SLUG
from app.models.enums import AuditAction, DeviceStatus, UserRole
from app.models.inventory import Device, Rack, Site
from app.schemas.common import BaseSchema, EmailAddress, PaginationMeta

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Sites & Racks"])

_NON_CODE_RE = re.compile(r"[^A-Za-z0-9_-]+")


# ---------------------------------------------------------------------------
# Request Authentication & Tenant Context Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TenantRequestContext:
    """Resolved organization tenant and actor identity for an API request."""

    org_id: str
    actor_user_id: str | None = None
    actor_email: str | None = None
    actor_role: str | None = None
    is_authenticated: bool = False
    auth_method: Literal["jwt", "api_key", "default_tenant"] = "default_tenant"
    client_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    def require_write(self, resource: str) -> None:
        """Enforce write RBAC when the caller authenticated as a specific user role."""
        if not self.is_authenticated or self.actor_role is None:
            return
        try:
            role_enum = UserRole(self.actor_role.strip().lower())
        except ValueError:
            return
        if not role_enum.can_write:
            raise AuthorizationError(
                f"Role '{role_enum.value}' does not have write access to {resource}",
                details={"role": role_enum.value, "resource": resource},
            )


def _extract_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client is not None:
        return request.client.host
    return None


def resolve_tenant_context(
    request: Request,
    db: Session = Depends(get_db),
) -> TenantRequestContext:
    """Resolve organization scope and optional authenticated actor from request headers.

    Supports:
    1. ``Authorization: Bearer <jwt>`` validated against :func:`verify_access_token`.
    2. ``X-API-Key: npm_...`` validated against :class:`ApiKeyRepository`.
    3. Fallback to ``X-Org-Id`` header or the default active organization when
       invoked in demo/local contexts without explicit credentials.
    """
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent")
    req_id = getattr(request.state, "request_id", None) or get_request_id()

    auth_header = request.headers.get("authorization")
    api_key_header = request.headers.get("x-api-key")

    if auth_header:
        parts = auth_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise AuthenticationError(
                "Authorization header must use 'Bearer <token>' format",
                error_code="INVALID_AUTH_HEADER",
            )
        token_payload = verify_access_token(parts[1].strip())
        user = UserRepository(db).get_by_id(token_payload.sub)
        if user is None or not user.is_active:
            raise AuthenticationError(
                "Authenticated user account is inactive or no longer exists",
                error_code="USER_INACTIVE",
            )
        return TenantRequestContext(
            org_id=user.org_id,
            actor_user_id=user.id,
            actor_email=user.email,
            actor_role=user.role,
            is_authenticated=True,
            auth_method="jwt",
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=req_id,
        )

    if api_key_header:
        raw_key = api_key_header.strip()
        key_hash = hash_api_key(raw_key)
        api_key_repo = ApiKeyRepository(db)
        api_key = api_key_repo.get_valid_by_hash(key_hash)
        if api_key is None:
            raise AuthenticationError(
                "Invalid, expired, or revoked API key",
                error_code="INVALID_API_KEY",
            )
        allowed_cidrs = list(getattr(api_key, "allowed_cidrs_json", None) or [])
        if allowed_cidrs and client_ip:
            acl = CIDRAllowlist(allowlist=allowed_cidrs, default_allow=False)
            acl.assert_allowed(client_ip)
        return TenantRequestContext(
            org_id=api_key.org_id,
            actor_user_id=api_key.created_by_user_id,
            actor_email=f"apikey:{api_key.key_prefix}",
            actor_role=UserRole.SERVICE_ACCOUNT.value,
            is_authenticated=True,
            auth_method="api_key",
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=req_id,
        )

    # Unauthenticated fallback: honor explicit X-Org-Id if valid, else default org
    org_repo = OrganizationRepository(db)
    requested_org_id = request.headers.get("x-org-id")
    if requested_org_id:
        org = org_repo.get_by_id(requested_org_id.strip())
        if org is None:
            raise NotFoundError(
                f"Organization '{requested_org_id}' was not found",
                details={"org_id": requested_org_id},
            )
        resolved_org = org
    else:
        resolved_org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
        if resolved_org is None:
            active_orgs = org_repo.list_active(limit=1)
            resolved_org = active_orgs[0] if active_orgs else None

    if resolved_org is None:
        raise NotFoundError(
            "No active organization is configured in the database",
            error_code="ORG_NOT_INITIALIZED",
        )

    return TenantRequestContext(
        org_id=resolved_org.id,
        is_authenticated=False,
        auth_method="default_tenant",
        client_ip=client_ip,
        user_agent=user_agent,
        request_id=req_id,
    )


def record_audit_event(
    db: Session,
    ctx: TenantRequestContext,
    *,
    action: AuditAction | str,
    resource_type: str,
    resource_id: str | None = None,
    summary: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Safely record an audit log entry without interrupting primary workflows."""
    try:
        action_val = action.value if isinstance(action, AuditAction) else str(action)
        AuditLogRepository(db, org_id=ctx.org_id).record(
            action=action_val,
            resource_type=resource_type,
            resource_id=resource_id,
            org_id=ctx.org_id,
            actor_user_id=ctx.actor_user_id,
            actor_email=ctx.actor_email,
            summary=summary,
            ip_address=ctx.client_ip,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            details=details,
            flush=False,
        )
    except Exception:
        logger.debug("Audit event recording skipped for %s/%s", resource_type, resource_id, exc_info=True)


# ---------------------------------------------------------------------------
# Site & Rack API Schemas (ORM-aligned with ergonomic input aliases)
# ---------------------------------------------------------------------------


def _derive_site_code(raw: str) -> str:
    cleaned = _NON_CODE_RE.sub("-", raw.strip()).strip("-_").upper()
    if not cleaned:
        raise ValueError("Unable to derive a valid site code")
    if not cleaned[0].isalnum():
        cleaned = f"S-{cleaned}"
    return cleaned[:64]


class SiteCreateRequest(BaseSchema):
    """Create payload for a physical data center, POP, branch office, or cloud region."""

    name: str = Field(..., min_length=2, max_length=160)
    code: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("code", "site_code", "slug"),
        description="Unique uppercase site code (auto-derived from name if omitted).",
    )
    region: str | None = Field(default=None, max_length=100)
    country: str | None = Field(
        default=None,
        max_length=100,
        validation_alias=AliasChoices("country", "country_code"),
    )
    city: str | None = Field(default=None, max_length=100)
    address: str | None = Field(default=None, max_length=512)
    timezone: str = Field(
        default="UTC",
        max_length=64,
        validation_alias=AliasChoices("timezone", "timezone_name"),
    )
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    contact_name: str | None = Field(default=None, max_length=160)
    contact_email: EmailAddress | None = None
    tier: str = Field(default="standard", max_length=32)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metadata_json", "metadata", "tags"),
    )

    @model_validator(mode="after")
    def _validate_site_fields(self) -> SiteCreateRequest:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("Both 'latitude' and 'longitude' must be provided together.")
        object.__setattr__(self, "code", _derive_site_code(self.code or self.name))
        return self


class SiteUpdateRequest(BaseSchema):
    """Partial update payload for an existing site."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    code: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("code", "site_code", "slug"),
    )
    region: str | None = Field(default=None, max_length=100)
    country: str | None = Field(
        default=None,
        max_length=100,
        validation_alias=AliasChoices("country", "country_code"),
    )
    city: str | None = Field(default=None, max_length=100)
    address: str | None = Field(default=None, max_length=512)
    timezone: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("timezone", "timezone_name"),
    )
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    contact_name: str | None = Field(default=None, max_length=160)
    contact_email: EmailAddress | None = None
    tier: str | None = Field(default=None, max_length=32)
    metadata_json: dict[str, Any] | None = Field(
        default=None,
        validation_alias=AliasChoices("metadata_json", "metadata", "tags"),
    )


class SiteResponse(BaseSchema):
    """Full site response enriched with live infrastructure counts."""

    id: str
    org_id: str
    name: str
    code: str
    region: str | None = None
    country: str | None = None
    city: str | None = None
    address: str | None = None
    timezone: str = "UTC"
    latitude: float | None = None
    longitude: float | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    tier: str = "standard"
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    rack_count: int = 0
    device_count: int = 0
    devices_online: int = 0
    devices_degraded: int = 0
    devices_offline: int = 0
    subnet_count: int = 0
    vlan_count: int = 0
    created_at: datetime
    updated_at: datetime


class SiteListResponse(BaseSchema):
    """Paginated collection of sites."""

    items: list[SiteResponse]
    meta: PaginationMeta


class SitePeerDistance(BaseSchema):
    """Great-circle Haversine distance to a sibling site."""

    site_id: str
    name: str
    code: str
    region: str | None = None
    distance_km: float


class SiteSummaryResponse(BaseSchema):
    """Comprehensive operational, capacity, and geographic summary for a site."""

    site: SiteResponse
    devices_total: int
    devices_by_status: dict[str, int]
    devices_by_type: dict[str, int]
    devices_by_vendor: dict[str, int]
    availability_pct: float
    racks_total: int
    rack_total_u: int
    rack_used_u: int
    rack_free_u: int
    rack_utilization_pct: float
    total_power_capacity_watts: int
    subnets_total: int
    vlans_total: int
    avg_subnet_utilization_pct: float
    nearest_sites: list[SitePeerDistance] = Field(default_factory=list)


class RackCreateRequest(BaseSchema):
    """Create payload for a physical rack enclosure within a site."""

    site_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=120)
    aisle: str | None = Field(default=None, max_length=64)
    row: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("row", "row_label"),
    )
    total_u: int = Field(
        default=42,
        ge=1,
        le=100,
        validation_alias=AliasChoices("total_u", "u_height"),
    )
    power_capacity_watts: int | None = Field(default=None, ge=0, le=500_000)
    cooling_zone: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(
        default=None,
        max_length=2000,
        validation_alias=AliasChoices("notes", "description"),
    )


class RackUpdateRequest(BaseSchema):
    """Partial update payload for a rack record."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    aisle: str | None = Field(default=None, max_length=64)
    row: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("row", "row_label"),
    )
    total_u: int | None = Field(
        default=None,
        ge=1,
        le=100,
        validation_alias=AliasChoices("total_u", "u_height"),
    )
    power_capacity_watts: int | None = Field(default=None, ge=0, le=500_000)
    cooling_zone: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(
        default=None,
        max_length=2000,
        validation_alias=AliasChoices("notes", "description"),
    )


class RackResponse(BaseSchema):
    """Full rack response with real-time rack-unit occupancy calculations."""

    id: str
    org_id: str
    site_id: str
    site_name: str | None = None
    name: str
    aisle: str | None = None
    row: str | None = None
    total_u: int
    used_u: int = 0
    free_u: int = 0
    utilization_pct: float = 0.0
    power_capacity_watts: int | None = None
    cooling_zone: str | None = None
    notes: str | None = None
    device_count: int = 0
    created_at: datetime
    updated_at: datetime


class RackListResponse(BaseSchema):
    """Paginated collection of racks."""

    items: list[RackResponse]
    meta: PaginationMeta


class RackElevationSlot(BaseSchema):
    """Single 1U slot entry inside a rack elevation diagram."""

    unit: int
    occupied: bool
    is_anchor: bool = False
    device_id: str | None = None
    hostname: str | None = None
    management_ip: str | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    status: str | None = None
    unit_height: int | None = None


class RackMountedDevice(BaseSchema):
    """Device positioned in a specific U-slot span within a rack."""

    device_id: str
    hostname: str
    management_ip: str
    device_type: str
    vendor: str
    model: str | None = None
    status: str
    rack_unit_start: int | None = None
    rack_unit_end: int | None = None
    rack_unit_height: int = 1


class RackFreeBlock(BaseSchema):
    """Contiguous range of unoccupied rack units available for new equipment."""

    start_u: int
    end_u: int
    size_u: int


class RackElevationResponse(BaseSchema):
    """Full top-to-bottom U-slot rack elevation model for DCIM visualization."""

    rack: RackResponse
    total_u: int
    used_u: int
    free_u: int
    utilization_pct: float
    power_capacity_watts: int | None = None
    slots: list[RackElevationSlot]
    mounted_devices: list[RackMountedDevice]
    unpositioned_devices: list[RackMountedDevice]
    contiguous_free_blocks: list[RackFreeBlock]


# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------


def _serialize_site(
    site: Site,
    *,
    rack_count: int = 0,
    device_counts: dict[str, int] | None = None,
    subnet_count: int = 0,
    vlan_count: int = 0,
) -> SiteResponse:
    counts = device_counts or {}
    total_devices = sum(counts.values())
    online = counts.get(DeviceStatus.UP.value, 0)
    degraded = (
        counts.get(DeviceStatus.DEGRADED.value, 0)
        + counts.get(DeviceStatus.WARNING.value, 0)
    )
    offline = (
        counts.get(DeviceStatus.DOWN.value, 0)
        + counts.get(DeviceStatus.CRITICAL.value, 0)
        + counts.get(DeviceStatus.UNREACHABLE.value, 0)
    )
    return SiteResponse(
        id=site.id,
        org_id=site.org_id,
        name=site.name,
        code=site.code,
        region=site.region,
        country=site.country,
        city=site.city,
        address=site.address,
        timezone=site.timezone,
        latitude=site.latitude,
        longitude=site.longitude,
        contact_name=site.contact_name,
        contact_email=site.contact_email,
        tier=site.tier,
        metadata_json=dict(site.metadata_json or {}),
        rack_count=rack_count,
        device_count=total_devices,
        devices_online=online,
        devices_degraded=degraded,
        devices_offline=offline,
        subnet_count=subnet_count,
        vlan_count=vlan_count,
        created_at=site.created_at,
        updated_at=site.updated_at,
    )


def _compute_rack_metrics(
    rack: Rack,
    mounted_devices: list[Device],
) -> tuple[int, int, float, int]:
    """Return ``(used_u, free_u, utilization_pct, device_count)`` for a rack."""
    occupied: set[int] = set()
    for dev in mounted_devices:
        if dev.is_deleted:
            continue
        if dev.rack_unit_start is not None:
            height = max(1, int(dev.rack_unit_height or 1))
            for u in range(dev.rack_unit_start, min(rack.total_u + 1, dev.rack_unit_start + height)):
                occupied.add(u)
    used_u = len(occupied)
    total_u = max(1, int(rack.total_u or 42))
    free_u = max(0, total_u - used_u)
    util_pct = round(min(100.0, (used_u / total_u) * 100.0), 2)
    active_devs = [d for d in mounted_devices if not d.is_deleted]
    return used_u, free_u, util_pct, len(active_devs)


def _serialize_rack(
    rack: Rack,
    *,
    mounted_devices: list[Device] | None = None,
    site_name: str | None = None,
) -> RackResponse:
    devs = mounted_devices if mounted_devices is not None else list(rack.devices or [])
    used_u, free_u, util_pct, dev_count = _compute_rack_metrics(rack, devs)
    resolved_site_name = site_name
    if resolved_site_name is None and rack.site is not None:
        resolved_site_name = rack.site.name
    return RackResponse(
        id=rack.id,
        org_id=rack.org_id,
        site_id=rack.site_id,
        site_name=resolved_site_name,
        name=rack.name,
        aisle=rack.aisle,
        row=rack.row,
        total_u=rack.total_u,
        used_u=used_u,
        free_u=free_u,
        utilization_pct=util_pct,
        power_capacity_watts=rack.power_capacity_watts,
        cooling_zone=rack.cooling_zone,
        notes=rack.notes,
        device_count=dev_count,
        created_at=rack.created_at,
        updated_at=rack.updated_at,
    )


def _bulk_site_counts(
    db: Session,
    org_id: str,
    site_ids: list[str],
) -> tuple[dict[str, int], dict[str, dict[str, int]], dict[str, int], dict[str, int]]:
    """Aggregate rack, device-by-status, subnet, and VLAN counts for a batch of sites."""
    if not site_ids:
        return {}, {}, {}, {}

    rack_rows = db.execute(
        select(Rack.site_id, func.count(Rack.id))
        .where(Rack.org_id == org_id, Rack.is_deleted.is_(False), Rack.site_id.in_(site_ids))
        .group_by(Rack.site_id)
    ).all()
    rack_counts = {str(sid): int(cnt) for sid, cnt in rack_rows}

    dev_rows = db.execute(
        select(Device.site_id, Device.status, func.count(Device.id))
        .where(Device.org_id == org_id, Device.is_deleted.is_(False), Device.site_id.in_(site_ids))
        .group_by(Device.site_id, Device.status)
    ).all()
    device_status_counts: dict[str, dict[str, int]] = {}
    for sid, st, cnt in dev_rows:
        if sid is None:
            continue
        device_status_counts.setdefault(str(sid), {})[str(st)] = int(cnt)

    subnet_repo = SubnetRepository(db, org_id=org_id)
    vlan_repo = VlanRepository(db, org_id=org_id)
    subnet_counts = {sid: subnet_repo.count(filters={"site_id": sid}) for sid in site_ids}
    vlan_counts = {sid: vlan_repo.count(filters={"site_id": sid}) for sid in site_ids}

    return rack_counts, device_status_counts, subnet_counts, vlan_counts


# ---------------------------------------------------------------------------
# Site Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/sites",
    response_model=SiteListResponse,
    summary="List and search physical sites",
)
def list_sites(
    search: str | None = Query(default=None, alias="search", max_length=160),
    q: str | None = Query(default=None, max_length=160, description="Alias for search."),
    region: str | None = Query(default=None, max_length=100),
    tier: str | None = Query(default=None, max_length=32),
    country: str | None = Query(default=None, max_length=100),
    sort_by: str = Query(default="name", max_length=64),
    sort_order: Literal["asc", "desc"] = Query(default="asc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SiteListResponse:
    """List sites for the active organization with search, filtering, sorting, and live counts."""
    repo = SiteRepository(db, org_id=ctx.org_id)
    term = search or q
    allowed_sort = {"name", "code", "region", "country", "city", "tier", "created_at", "updated_at"}
    if sort_by not in allowed_sort:
        raise ValidationError(
            f"Unsupported sort_by field '{sort_by}' for sites",
            details={"allowed": sorted(allowed_sort)},
        )

    if term:
        page_res = repo.search(
            query=term,
            region=region,
            tier=tier,
            page=page,
            page_size=page_size,
        )
        items = page_res.items
        if country:
            items = [s for s in items if (s.country or "").lower() == country.strip().lower()]
        total = len(items) if country else page_res.total
    else:
        filters: dict[str, Any] = {}
        if region:
            filters["region"] = region
        if tier:
            filters["tier"] = tier
        if country:
            filters["country__icontains"] = country.strip()
        order_expr = f"-{sort_by}" if sort_order == "desc" else sort_by
        page_res = repo.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            order_by=order_expr,
        )
        items = page_res.items
        total = page_res.total

    site_ids = [s.id for s in items]
    rack_counts, dev_counts, subnet_counts, vlan_counts = _bulk_site_counts(db, ctx.org_id, site_ids)

    serialized = [
        _serialize_site(
            site,
            rack_count=rack_counts.get(site.id, 0),
            device_counts=dev_counts.get(site.id, {}),
            subnet_count=subnet_counts.get(site.id, 0),
            vlan_count=vlan_counts.get(site.id, 0),
        )
        for site in items
    ]
    return SiteListResponse(
        items=serialized,
        meta=PaginationMeta.from_counts(total=total, page=page, page_size=page_size),
    )


@router.post(
    "/sites",
    response_model=SiteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new physical site",
)
def create_site(
    payload: SiteCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SiteResponse:
    """Register a new physical site, data center, POP, or cloud region."""
    ctx.require_write("sites")
    repo = SiteRepository(db, org_id=ctx.org_id)

    assert payload.code is not None
    if repo.get_by_code(payload.code) is not None:
        raise ConflictError(
            f"Site with code '{payload.code}' already exists in this organization",
            details={"code": payload.code},
        )

    site = repo.create(
        {
            "org_id": ctx.org_id,
            "name": payload.name.strip(),
            "code": payload.code,
            "region": payload.region,
            "country": payload.country,
            "city": payload.city,
            "address": payload.address,
            "timezone": payload.timezone,
            "latitude": payload.latitude,
            "longitude": payload.longitude,
            "contact_name": payload.contact_name,
            "contact_email": payload.contact_email,
            "tier": payload.tier,
            "metadata_json": dict(payload.metadata_json or {}),
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="site",
        resource_id=site.id,
        summary=f"Created site {site.name} ({site.code})",
        details={"code": site.code, "region": site.region, "tier": site.tier},
    )
    db.commit()
    db.refresh(site)
    return _serialize_site(site)


@router.get(
    "/sites/{site_id}",
    response_model=SiteResponse,
    summary="Get a single site by ID",
)
def get_site(
    site_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SiteResponse:
    """Retrieve full site metadata along with rack, device, subnet, and VLAN counts."""
    repo = SiteRepository(db, org_id=ctx.org_id)
    site = repo.get_by_id_or_raise(site_id)
    rack_counts, dev_counts, subnet_counts, vlan_counts = _bulk_site_counts(db, ctx.org_id, [site.id])
    return _serialize_site(
        site,
        rack_count=rack_counts.get(site.id, 0),
        device_counts=dev_counts.get(site.id, {}),
        subnet_count=subnet_counts.get(site.id, 0),
        vlan_count=vlan_counts.get(site.id, 0),
    )


@router.patch(
    "/sites/{site_id}",
    response_model=SiteResponse,
    summary="Update site metadata",
)
def update_site(
    site_id: str,
    payload: SiteUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SiteResponse:
    """Partially update an existing site's location, contact, tier, or metadata."""
    ctx.require_write("sites")
    repo = SiteRepository(db, org_id=ctx.org_id)
    site = repo.get_by_id_or_raise(site_id)

    patch = payload.model_dump(exclude_unset=True)
    if "code" in patch and patch["code"] is not None:
        normalized_code = _derive_site_code(patch["code"])
        existing = repo.get_by_code(normalized_code)
        if existing is not None and existing.id != site.id:
            raise ConflictError(
                f"Another site already uses code '{normalized_code}'",
                details={"code": normalized_code},
            )
        patch["code"] = normalized_code

    new_lat = patch.get("latitude", site.latitude)
    new_lon = patch.get("longitude", site.longitude)
    if (new_lat is None) != (new_lon is None):
        raise ValidationError("Both 'latitude' and 'longitude' must be populated together.")

    if "name" in patch and patch["name"] is not None:
        patch["name"] = patch["name"].strip()

    updated = repo.update(site, patch)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="site",
        resource_id=updated.id,
        summary=f"Updated site {updated.name} ({updated.code})",
        details={"updated_fields": sorted(patch.keys())},
    )
    db.commit()
    db.refresh(updated)
    rack_counts, dev_counts, subnet_counts, vlan_counts = _bulk_site_counts(db, ctx.org_id, [updated.id])
    return _serialize_site(
        updated,
        rack_count=rack_counts.get(updated.id, 0),
        device_counts=dev_counts.get(updated.id, {}),
        subnet_count=subnet_counts.get(updated.id, 0),
        vlan_count=vlan_counts.get(updated.id, 0),
    )


@router.delete(
    "/sites/{site_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a site",
)
def delete_site(
    site_id: str,
    force: bool = Query(
        default=False,
        description="If true, detaches devices and soft-deletes child racks along with the site.",
    ),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a site. Prevents accidental deletion when devices are still assigned unless ``force=true``."""
    ctx.require_write("sites")
    site_repo = SiteRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    rack_repo = RackRepository(db, org_id=ctx.org_id)

    site = site_repo.get_by_id_or_raise(site_id)
    attached_devices = device_repo.list_by_site(site.id)
    if attached_devices and not force:
        raise ConflictError(
            f"Site '{site.name}' still has {len(attached_devices)} assigned device(s). "
            "Reassign devices first or pass force=true.",
            details={"site_id": site.id, "device_count": len(attached_devices)},
        )

    if attached_devices and force:
        for dev in attached_devices:
            device_repo.update(dev, {"site_id": None, "rack_id": None}, flush=False)

    child_racks = rack_repo.list_by_site(site.id)
    for rack in child_racks:
        rack_repo.soft_delete(rack, flush=False)

    site_repo.soft_delete(site)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="site",
        resource_id=site.id,
        summary=f"Soft-deleted site {site.name} ({site.code})",
        details={"force": force, "detached_devices": len(attached_devices)},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/sites/{site_id}/summary",
    response_model=SiteSummaryResponse,
    summary="Get site health, capacity, IPAM, and geographic proximity summary",
)
def get_site_summary(
    site_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> SiteSummaryResponse:
    """Compute a comprehensive operational health and capacity summary for a single site."""
    site_repo = SiteRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    subnet_repo = SubnetRepository(db, org_id=ctx.org_id)
    vlan_repo = VlanRepository(db, org_id=ctx.org_id)

    site = site_repo.get_by_id_or_raise(site_id)
    devices = device_repo.list_by_site(site.id)
    racks = rack_repo.list_by_site(site.id)
    subnets = subnet_repo.list_by_site(site.id)
    vlans = vlan_repo.list_by_site(site.id)

    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_vendor: dict[str, int] = {}
    devices_by_rack: dict[str, list[Device]] = {}

    for dev in devices:
        by_status[dev.status] = by_status.get(dev.status, 0) + 1
        by_type[dev.device_type] = by_type.get(dev.device_type, 0) + 1
        by_vendor[dev.vendor] = by_vendor.get(dev.vendor, 0) + 1
        if dev.rack_id:
            devices_by_rack.setdefault(dev.rack_id, []).append(dev)

    total_devices = len(devices)
    online_devices = by_status.get(DeviceStatus.UP.value, 0)
    availability_pct = round((online_devices / total_devices) * 100.0, 2) if total_devices > 0 else 100.0

    total_u = 0
    used_u = 0
    total_power = 0
    for rack in racks:
        total_u += int(rack.total_u or 42)
        rack_used, _, _, _ = _compute_rack_metrics(rack, devices_by_rack.get(rack.id, []))
        used_u += rack_used
        if rack.power_capacity_watts:
            total_power += int(rack.power_capacity_watts)

    free_u = max(0, total_u - used_u)
    rack_util_pct = round((used_u / total_u) * 100.0, 2) if total_u > 0 else 0.0

    if subnets:
        avg_subnet_util = round(sum(float(s.utilization_pct or 0.0) for s in subnets) / len(subnets), 2)
    else:
        avg_subnet_util = 0.0

    nearest_sites: list[SitePeerDistance] = []
    if site.has_coordinates:
        for other in site_repo.list():
            if other.id == site.id or not other.has_coordinates:
                continue
            dist = site.distance_km_to(other)
            if dist is not None:
                nearest_sites.append(
                    SitePeerDistance(
                        site_id=other.id,
                        name=other.name,
                        code=other.code,
                        region=other.region,
                        distance_km=round(dist, 2),
                    )
                )
        nearest_sites.sort(key=lambda peer: peer.distance_km)

    site_resp = _serialize_site(
        site,
        rack_count=len(racks),
        device_counts=by_status,
        subnet_count=len(subnets),
        vlan_count=len(vlans),
    )

    return SiteSummaryResponse(
        site=site_resp,
        devices_total=total_devices,
        devices_by_status=by_status,
        devices_by_type=by_type,
        devices_by_vendor=by_vendor,
        availability_pct=availability_pct,
        racks_total=len(racks),
        rack_total_u=total_u,
        rack_used_u=used_u,
        rack_free_u=free_u,
        rack_utilization_pct=rack_util_pct,
        total_power_capacity_watts=total_power,
        subnets_total=len(subnets),
        vlans_total=len(vlans),
        avg_subnet_utilization_pct=avg_subnet_util,
        nearest_sites=nearest_sites[:10],
    )


# ---------------------------------------------------------------------------
# Rack Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/racks",
    response_model=RackListResponse,
    summary="List equipment racks with capacity utilization",
)
def list_racks(
    site_id: str | None = Query(default=None),
    aisle: str | None = Query(default=None, max_length=64),
    row: str | None = Query(default=None, max_length=64),
    cooling_zone: str | None = Query(default=None, max_length=64),
    search: str | None = Query(default=None, max_length=120),
    sort_by: str = Query(default="name", max_length=64),
    sort_order: Literal["asc", "desc"] = Query(default="asc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> RackListResponse:
    """List racks scoped to the active organization with live U-unit occupancy stats."""
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    allowed_sort = {"name", "aisle", "row", "total_u", "power_capacity_watts", "created_at", "updated_at"}
    if sort_by not in allowed_sort:
        raise ValidationError(
            f"Unsupported sort_by field '{sort_by}' for racks",
            details={"allowed": sorted(allowed_sort)},
        )

    filters: dict[str, Any] = {}
    if site_id:
        filters["site_id"] = site_id
    if aisle:
        filters["aisle"] = aisle
    if row:
        filters["row"] = row
    if cooling_zone:
        filters["cooling_zone"] = cooling_zone
    if search:
        filters["name__icontains"] = search.strip()

    order_expr = f"-{sort_by}" if sort_order == "desc" else sort_by
    page_res = rack_repo.paginate(
        page=page,
        page_size=page_size,
        filters=filters or None,
        order_by=order_expr,
    )

    rack_ids = [r.id for r in page_res.items]
    devices_by_rack: dict[str, list[Device]] = {}
    if rack_ids:
        devs = DeviceRepository(db, org_id=ctx.org_id).list(filters={"rack_id__in": rack_ids})
        for dev in devs:
            if dev.rack_id:
                devices_by_rack.setdefault(dev.rack_id, []).append(dev)

    site_ids = list({r.site_id for r in page_res.items if r.site_id})
    sites_map = {
        s.id: s.name for s in SiteRepository(db, org_id=ctx.org_id).get_many_by_ids(site_ids)
    }

    items = [
        _serialize_rack(
            rack,
            mounted_devices=devices_by_rack.get(rack.id, []),
            site_name=sites_map.get(rack.site_id),
        )
        for rack in page_res.items
    ]
    return RackListResponse(
        items=items,
        meta=PaginationMeta.from_counts(total=page_res.total, page=page, page_size=page_size),
    )


@router.post(
    "/racks",
    response_model=RackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new equipment rack inside a site",
)
def create_rack(
    payload: RackCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> RackResponse:
    """Create a physical rack cabinet under an existing site."""
    ctx.require_write("racks")
    site_repo = SiteRepository(db, org_id=ctx.org_id)
    rack_repo = RackRepository(db, org_id=ctx.org_id)

    site = site_repo.get_by_id_or_raise(payload.site_id)
    cleaned_name = payload.name.strip()
    if rack_repo.get_by_name_in_site(site.id, cleaned_name) is not None:
        raise ConflictError(
            f"Rack '{cleaned_name}' already exists in site '{site.name}'",
            details={"site_id": site.id, "name": cleaned_name},
        )

    rack = rack_repo.create(
        {
            "org_id": ctx.org_id,
            "site_id": site.id,
            "name": cleaned_name,
            "aisle": payload.aisle,
            "row": payload.row,
            "total_u": payload.total_u,
            "power_capacity_watts": payload.power_capacity_watts,
            "cooling_zone": payload.cooling_zone,
            "notes": payload.notes,
        }
    )
    record_audit_event(
        db,
        ctx,
        action=AuditAction.CREATE,
        resource_type="rack",
        resource_id=rack.id,
        summary=f"Created rack {rack.name} in site {site.code}",
        details={"site_id": site.id, "total_u": rack.total_u},
    )
    db.commit()
    db.refresh(rack)
    return _serialize_rack(rack, mounted_devices=[], site_name=site.name)


@router.get(
    "/racks/{rack_id}",
    response_model=RackResponse,
    summary="Get rack details and capacity stats",
)
def get_rack(
    rack_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> RackResponse:
    """Retrieve a single rack along with live mounted device and U-unit metrics."""
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    rack = rack_repo.get_by_id_or_raise(rack_id)
    mounted = DeviceRepository(db, org_id=ctx.org_id).list(filters={"rack_id": rack.id})
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(rack.site_id)
    return _serialize_rack(rack, mounted_devices=mounted, site_name=site.name if site else None)


@router.patch(
    "/racks/{rack_id}",
    response_model=RackResponse,
    summary="Update rack properties",
)
def update_rack(
    rack_id: str,
    payload: RackUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> RackResponse:
    """Partially update rack attributes, validating name uniqueness and U-height bounds."""
    ctx.require_write("racks")
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    rack = rack_repo.get_by_id_or_raise(rack_id)
    mounted = DeviceRepository(db, org_id=ctx.org_id).list(filters={"rack_id": rack.id})

    patch = payload.model_dump(exclude_unset=True)
    if "name" in patch and patch["name"] is not None:
        cleaned_name = patch["name"].strip()
        existing = rack_repo.get_by_name_in_site(rack.site_id, cleaned_name)
        if existing is not None and existing.id != rack.id:
            raise ConflictError(
                f"Rack '{cleaned_name}' already exists in this site",
                details={"site_id": rack.site_id, "name": cleaned_name},
            )
        patch["name"] = cleaned_name

    if "total_u" in patch and patch["total_u"] is not None:
        new_total_u = int(patch["total_u"])
        highest_used = 0
        for dev in mounted:
            if dev.rack_unit_start is not None:
                top_u = dev.rack_unit_start + max(1, int(dev.rack_unit_height or 1)) - 1
                highest_used = max(highest_used, top_u)
        if new_total_u < highest_used:
            raise ValidationError(
                f"Cannot shrink rack total_u to {new_total_u}; mounted equipment occupies up to U{highest_used}",
                details={"requested_total_u": new_total_u, "highest_occupied_u": highest_used},
            )

    updated = rack_repo.update(rack, patch)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.UPDATE,
        resource_type="rack",
        resource_id=updated.id,
        summary=f"Updated rack {updated.name}",
        details={"updated_fields": sorted(patch.keys())},
    )
    db.commit()
    db.refresh(updated)
    site = SiteRepository(db, org_id=ctx.org_id).get_by_id(updated.site_id)
    return _serialize_rack(updated, mounted_devices=mounted, site_name=site.name if site else None)


@router.delete(
    "/racks/{rack_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a rack",
)
def delete_rack(
    rack_id: str,
    detach_devices: bool = Query(
        default=True,
        description="Automatically clear rack assignment on mounted devices before soft-deleting.",
    ),
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> Response:
    """Soft-delete a rack cabinet, optionally detaching any currently mounted devices."""
    ctx.require_write("racks")
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)

    rack = rack_repo.get_by_id_or_raise(rack_id)
    mounted = device_repo.list(filters={"rack_id": rack.id})
    if mounted and not detach_devices:
        raise ConflictError(
            f"Rack '{rack.name}' still contains {len(mounted)} mounted device(s)",
            details={"rack_id": rack.id, "device_count": len(mounted)},
        )

    for dev in mounted:
        device_repo.update(dev, {"rack_id": None, "rack_unit_start": None}, flush=False)

    rack_repo.soft_delete(rack)
    record_audit_event(
        db,
        ctx,
        action=AuditAction.DELETE,
        resource_type="rack",
        resource_id=rack.id,
        summary=f"Soft-deleted rack {rack.name}",
        details={"detached_devices": len(mounted)},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/racks/{rack_id}/elevation",
    response_model=RackElevationResponse,
    summary="Get top-to-bottom U-slot rack elevation diagram",
)
def get_rack_elevation(
    rack_id: str,
    db: Session = Depends(get_db),
    ctx: TenantRequestContext = Depends(resolve_tenant_context),
) -> RackElevationResponse:
    """Build a complete U-by-U rack elevation model with mounted devices and free spans."""
    rack_repo = RackRepository(db, org_id=ctx.org_id)
    device_repo = DeviceRepository(db, org_id=ctx.org_id)
    site_repo = SiteRepository(db, org_id=ctx.org_id)

    rack = rack_repo.get_by_id_or_raise(rack_id)
    site = site_repo.get_by_id(rack.site_id)
    devices = device_repo.list(filters={"rack_id": rack.id})

    total_u = max(1, int(rack.total_u or 42))
    slot_map: dict[int, tuple[Device, bool]] = {}
    mounted_devices: list[RackMountedDevice] = []
    unpositioned_devices: list[RackMountedDevice] = []

    for dev in devices:
        height = max(1, int(dev.rack_unit_height or 1))
        if dev.rack_unit_start is not None:
            start_u = int(dev.rack_unit_start)
            end_u = min(total_u, start_u + height - 1)
            mounted_devices.append(
                RackMountedDevice(
                    device_id=dev.id,
                    hostname=dev.hostname,
                    management_ip=dev.management_ip,
                    device_type=dev.device_type,
                    vendor=dev.vendor,
                    model=dev.model,
                    status=dev.status,
                    rack_unit_start=start_u,
                    rack_unit_end=end_u,
                    rack_unit_height=height,
                )
            )
            for u in range(start_u, end_u + 1):
                if 1 <= u <= total_u:
                    slot_map[u] = (dev, u == start_u)
        else:
            unpositioned_devices.append(
                RackMountedDevice(
                    device_id=dev.id,
                    hostname=dev.hostname,
                    management_ip=dev.management_ip,
                    device_type=dev.device_type,
                    vendor=dev.vendor,
                    model=dev.model,
                    status=dev.status,
                    rack_unit_start=None,
                    rack_unit_end=None,
                    rack_unit_height=height,
                )
            )

    mounted_devices.sort(key=lambda d: -(d.rack_unit_start or 0))
    unpositioned_devices.sort(key=lambda d: d.hostname.lower())

    # Top-to-bottom elevation slots (U42 .. U1)
    slots: list[RackElevationSlot] = []
    for unit in range(total_u, 0, -1):
        entry = slot_map.get(unit)
        if entry is None:
            slots.append(RackElevationSlot(unit=unit, occupied=False))
        else:
            dev, is_anchor = entry
            slots.append(
                RackElevationSlot(
                    unit=unit,
                    occupied=True,
                    is_anchor=is_anchor,
                    device_id=dev.id,
                    hostname=dev.hostname,
                    management_ip=dev.management_ip,
                    device_type=dev.device_type,
                    vendor=dev.vendor,
                    model=dev.model,
                    status=dev.status,
                    unit_height=max(1, int(dev.rack_unit_height or 1)),
                )
            )

    # Compute contiguous free U blocks (bottom-to-top)
    free_blocks: list[RackFreeBlock] = []
    block_start: int | None = None
    for unit in range(1, total_u + 1):
        if unit not in slot_map:
            if block_start is None:
                block_start = unit
        elif block_start is not None:
            free_blocks.append(
                RackFreeBlock(start_u=block_start, end_u=unit - 1, size_u=unit - block_start)
            )
            block_start = None
    if block_start is not None:
        free_blocks.append(
            RackFreeBlock(start_u=block_start, end_u=total_u, size_u=total_u - block_start + 1)
        )

    rack_resp = _serialize_rack(
        rack,
        mounted_devices=devices,
        site_name=site.name if site else None,
    )
    return RackElevationResponse(
        rack=rack_resp,
        total_u=total_u,
        used_u=rack_resp.used_u,
        free_u=rack_resp.free_u,
        utilization_pct=rack_resp.utilization_pct,
        power_capacity_watts=rack.power_capacity_watts,
        slots=slots,
        mounted_devices=mounted_devices,
        unpositioned_devices=unpositioned_devices,
        contiguous_free_blocks=free_blocks,
    )


__all__ = [
    "RackCreateRequest",
    "RackElevationResponse",
    "RackListResponse",
    "RackResponse",
    "RackUpdateRequest",
    "SiteCreateRequest",
    "SiteListResponse",
    "SiteResponse",
    "SiteSummaryResponse",
    "SiteUpdateRequest",
    "TenantRequestContext",
    "record_audit_event",
    "resolve_tenant_context",
    "router",
]
