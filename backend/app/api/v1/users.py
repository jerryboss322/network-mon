"""Organization, user administration, API key, audit log, and webhook v1 endpoints."""

from __future__ import annotations

import csv
import io
import json
import secrets
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import Field, computed_field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    ResolvedTimeRange,
    get_db_session,
    normalize_orm_role,
    normalize_schema_role,
    parse_pagination,
    parse_time_range,
    rate_limit_dependency,
    require_any_permission,
    require_permission,
)
from app.api.v1.auth import user_to_read
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger, get_request_id
from app.core.security import (
    Permission,
    generate_api_key,
    get_credential_vault,
    hash_password,
    validate_password_strength,
)
from app.db.repositories.identity import (
    ApiKeyRepository,
    AuditLogRepository,
    OrganizationRepository,
    UserRepository,
    UserSessionRepository,
    WebhookEndpointRepository,
)
from app.models.alerting import AlertRule
from app.models.enums import AuditAction, UserRole as OrmUserRole
from app.models.identity import ApiKey, AuditLog, Organization, OrgWebhookEndpoint, User
from app.models.inventory import Device, Site, Subnet
from app.models.telemetry import EdgeAgent, SyntheticProbeConfig
from app.schemas.common import (
    BaseSchema,
    HttpUrlStr,
    MetadataDict,
    PaginatedResponse,
    PaginationParams,
    TenantEntityReadSchema,
    UTCDatetime,
    utcnow,
)
from app.schemas.identity import (
    AuditLogRead,
    AuditOutcome,
    OrganizationQuota,
    OrganizationRead,
    OrganizationUpdate,
    OrgPlan,
    OrgStatus,
    UserCreate,
    UserRead,
    UserUpdate,
)

logger = get_logger("netpulse.api.users")

router = APIRouter(tags=["Organization, Users, API Keys, Audit & Webhooks"])


# ---------------------------------------------------------------------------
# Flexible Endpoint-Specific Schemas
# ---------------------------------------------------------------------------


class QuotaUsageItem(BaseSchema):
    """Resource consumption against tenant quota."""

    used: int = Field(ge=0)
    limit: int | None = None
    utilization_pct: float | None = None
    near_limit: bool = False


class OrganizationUsageResponse(BaseSchema):
    """Tenant license and resource utilization breakdown."""

    org_id: str
    org_slug: str
    plan: OrgPlan
    generated_at: UTCDatetime
    quotas: dict[str, QuotaUsageItem]
    counts: dict[str, int]


class DeleteConfirmationResponse(BaseSchema):
    """Uniform response returned upon deleting or revoking a resource."""

    deleted: bool = True
    resource_type: str
    resource_id: str
    message: str


class ApiKeyCreatePayload(BaseSchema):
    """Flexible API key creation payload supporting both ApiKeyScope and Permission strings."""

    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=500)
    scopes: list[str] = Field(
        default_factory=lambda: ["devices:read", "telemetry:read"],
        min_length=1,
    )
    expires_at: UTCDatetime | None = None
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    allowed_cidrs: list[str] = Field(default_factory=list)

    @field_validator("scopes")
    @classmethod
    def _clean_scopes(cls, values: list[str]) -> list[str]:
        cleaned = [s.strip() for s in values if s and s.strip()]
        if not cleaned:
            raise ValueError("At least one scope must be specified.")
        return list(dict.fromkeys(cleaned))


class ApiKeyResponse(TenantEntityReadSchema):
    """Safe API key metadata response (never returns raw key or hash)."""

    name: str
    key_prefix: str
    last_four: str = "****"
    scopes: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    created_by_user_id: str | None = None
    is_active: bool = True
    expires_at: UTCDatetime | None = None
    last_used_at: UTCDatetime | None = None

    @computed_field
    @property
    def masked_key(self) -> str:
        return f"{self.key_prefix}...{self.last_four}"


class ApiKeyCreatedResponse(ApiKeyResponse):
    """One-time creation response exposing ``secret_key`` strictly once."""

    secret_key: str


class AuditSummaryResponse(BaseSchema):
    """Aggregated audit log analytics across a time window."""

    org_id: str
    start: UTCDatetime
    end: UTCDatetime
    total_events: int = Field(ge=0)
    by_action: dict[str, int] = Field(default_factory=dict)
    by_resource_type: dict[str, int] = Field(default_factory=dict)
    top_actors: list[dict[str, Any]] = Field(default_factory=list)
    daily_counts: list[dict[str, Any]] = Field(default_factory=list)


class WebhookCreatePayload(BaseSchema):
    """Create payload accepting either ``event_patterns`` or ``events`` lists."""

    name: str = Field(..., min_length=2, max_length=160)
    url: HttpUrlStr
    event_patterns: list[str] | None = Field(default=None)
    events: list[str] | None = Field(default=None)
    signing_secret: str | None = Field(default=None, min_length=16, max_length=256)
    is_active: bool | None = None
    is_enabled: bool | None = None

    def resolved_patterns(self) -> list[str]:
        raw = self.event_patterns if self.event_patterns is not None else self.events
        if not raw:
            raise ValidationError("At least one event or event pattern must be specified")
        cleaned = [str(item).strip() for item in raw if str(item).strip()]
        if not cleaned:
            raise ValidationError("Event patterns must not be empty")
        return list(dict.fromkeys(cleaned))

    def resolved_active(self) -> bool:
        if self.is_active is not None:
            return self.is_active
        if self.is_enabled is not None:
            return self.is_enabled
        return True


class WebhookUpdatePayload(BaseSchema):
    """Partial update payload for an outbound organization webhook endpoint."""

    name: str | None = Field(default=None, min_length=2, max_length=160)
    url: HttpUrlStr | None = None
    event_patterns: list[str] | None = None
    events: list[str] | None = None
    signing_secret: str | None = Field(default=None, min_length=16, max_length=256)
    is_active: bool | None = None
    is_enabled: bool | None = None
    reset_failures: bool = False


class WebhookResponse(TenantEntityReadSchema):
    """Safe outbound webhook representation (omits encrypted signing secret)."""

    name: str
    url: str
    event_patterns: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    has_signing_secret: bool = False
    is_active: bool = True
    is_enabled: bool = True
    failure_count: int = 0
    consecutive_failures: int = 0
    last_triggered_at: UTCDatetime | None = None


class WebhookCreatedResponse(WebhookResponse):
    """One-time creation response optionally exposing the auto-generated signing secret."""

    signing_secret: str | None = None


# ---------------------------------------------------------------------------
# Serializers & Helpers
# ---------------------------------------------------------------------------


def _org_to_read(db: Session, org: Organization) -> OrganizationRead:
    settings_map = dict(org.settings_json or {})
    try:
        plan = OrgPlan(str(org.plan_tier).lower())
    except ValueError:
        plan = OrgPlan.ENTERPRISE

    member_count = int(
        db.execute(
            select(func.count())
            .select_from(User)
            .where(User.org_id == org.id, User.is_deleted.is_(False))
        ).scalar_one()
    )
    device_count = int(
        db.execute(
            select(func.count())
            .select_from(Device)
            .where(Device.org_id == org.id, Device.is_deleted.is_(False))
        ).scalar_one()
    )

    quotas = OrganizationQuota(
        max_devices=int(org.max_devices or 500),
        max_users=int(org.max_users or 50),
        max_synthetic_probes=int(settings_map.get("max_synthetic_probes", 100)),
        max_edge_agents=int(settings_map.get("max_edge_agents", 25)),
        max_api_keys=int(settings_map.get("max_api_keys", 50)),
        raw_retention_days=min(365, max(1, int(org.retention_days or 90))),
    )

    return OrganizationRead(
        id=org.id,
        created_at=org.created_at or utcnow(),
        updated_at=org.updated_at or utcnow(),
        name=org.name,
        slug=org.slug,
        plan=plan,
        status=OrgStatus.ACTIVE if org.is_active else OrgStatus.SUSPENDED,
        billing_email=settings_map.get("billing_email"),
        timezone_name=str(settings_map.get("timezone_name") or settings_map.get("timezone") or "UTC"),
        quotas=quotas,
        settings=settings_map,
        member_count=member_count,
        device_count=device_count,
    )


def _api_key_to_response(key: ApiKey, *, last_four: str = "****") -> ApiKeyResponse:
    return ApiKeyResponse(
        id=key.id,
        org_id=key.org_id,
        created_at=key.created_at or utcnow(),
        updated_at=key.updated_at or utcnow(),
        name=key.name,
        key_prefix=key.key_prefix,
        last_four=last_four,
        scopes=list(key.scopes_json or []),
        allowed_cidrs=list(key.allowed_cidrs_json or []),
        created_by_user_id=key.created_by_user_id,
        is_active=bool(key.is_active),
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
    )


def _audit_to_read(entry: AuditLog) -> AuditLogRead:
    outcome = AuditOutcome.SUCCESS
    if entry.action == AuditAction.LOGIN_FAILED.value:
        outcome = AuditOutcome.FAILURE
    return AuditLogRead(
        id=entry.id,
        org_id=entry.org_id,
        created_at=entry.created_at or utcnow(),
        updated_at=entry.updated_at or utcnow(),
        actor_user_id=entry.actor_user_id,
        actor_api_key_id=None,
        actor_email=entry.actor_email,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        outcome=outcome,
        source_ip=entry.ip_address,
        user_agent=entry.user_agent,
        request_id=entry.request_id,
        before_state=entry.before_state,
        after_state=entry.after_state,
        metadata={
            "summary": entry.summary,
            "changed_fields": entry.changed_fields(),
        },
    )


def _webhook_to_response(endpoint: OrgWebhookEndpoint) -> WebhookResponse:
    patterns = list(endpoint.event_patterns_json or [])
    return WebhookResponse(
        id=endpoint.id,
        org_id=endpoint.org_id,
        created_at=endpoint.created_at or utcnow(),
        updated_at=endpoint.updated_at or utcnow(),
        name=endpoint.name,
        url=endpoint.url,
        event_patterns=patterns,
        events=patterns,
        has_signing_secret=bool(endpoint.secret_encrypted),
        is_active=bool(endpoint.is_active),
        is_enabled=bool(endpoint.is_active),
        failure_count=int(endpoint.failure_count or 0),
        consecutive_failures=int(endpoint.failure_count or 0),
        last_triggered_at=endpoint.last_triggered_at,
    )


def _write_audit(
    db: Session,
    auth: AuthContext,
    *,
    action: str | AuditAction,
    resource_type: str,
    resource_id: str | None = None,
    summary: str | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
) -> None:
    action_str = action.value if isinstance(action, AuditAction) else action
    AuditLogRepository(db).record(
        action=action_str,
        resource_type=resource_type,
        resource_id=resource_id,
        org_id=auth.org_id,
        actor_user_id=auth.user_id,
        actor_email=auth.email,
        summary=summary,
        ip_address=auth.client_ip,
        user_agent=auth.user_agent,
        request_id=get_request_id(),
        before_state=before_state,
        after_state=after_state,
    )


def _quota_item(used: int, limit: int | None) -> QuotaUsageItem:
    if limit is None or limit <= 0:
        return QuotaUsageItem(used=used, limit=limit, utilization_pct=None, near_limit=False)
    pct = round((used / limit) * 100.0, 2)
    return QuotaUsageItem(used=used, limit=limit, utilization_pct=pct, near_limit=pct >= 85.0)


def _count_active_admins(db: Session, org_id: str) -> int:
    admin_roles = [
        OrmUserRole.SUPER_ADMIN.value,
        OrmUserRole.ORG_ADMIN.value,
        OrmUserRole.ADMIN.value,
    ]
    return int(
        db.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.org_id == org_id,
                User.is_deleted.is_(False),
                User.is_active.is_(True),
                User.role.in_(admin_roles),
            )
        ).scalar_one()
    )


def _query_audit_logs(
    db: Session,
    *,
    org_id: str,
    actor_user_id: str | None = None,
    action: str | None = None,
    action_prefix: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    source_ip: str | None = None,
    search: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Any:
    stmt = select(AuditLog).where(AuditLog.org_id == org_id)
    if actor_user_id:
        stmt = stmt.where(AuditLog.actor_user_id == actor_user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action.strip().lower())
    if action_prefix:
        stmt = stmt.where(AuditLog.action.ilike(f"{action_prefix.strip().lower()}%"))
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type.strip().lower())
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if source_ip:
        stmt = stmt.where(AuditLog.ip_address == source_ip.strip())
    if since is not None:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until is not None:
        stmt = stmt.where(AuditLog.created_at <= until)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            AuditLog.action.ilike(pattern)
            | AuditLog.resource_type.ilike(pattern)
            | AuditLog.summary.ilike(pattern)
            | AuditLog.actor_email.ilike(pattern)
            | AuditLog.resource_id.ilike(pattern)
        )
    return stmt


# ---------------------------------------------------------------------------
# Organization Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/org",
    response_model=OrganizationRead,
    summary="Retrieve the current tenant organization profile and quotas",
)
def get_organization(
    auth: AuthContext = Depends(require_permission(Permission.ORG_READ)),
    db: Session = Depends(get_db_session),
) -> OrganizationRead:
    org = OrganizationRepository(db).get_by_id_or_raise(auth.org_id)
    return _org_to_read(db, org)


@router.patch(
    "/org",
    response_model=OrganizationRead,
    summary="Update organization name, subscription plan, quotas, or settings",
)
def update_organization(
    payload: OrganizationUpdate,
    auth: AuthContext = Depends(require_permission(Permission.ORG_UPDATE, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> OrganizationRead:
    org_repo = OrganizationRepository(db)
    org = org_repo.get_by_id_or_raise(auth.org_id)
    before = org.to_summary_dict()

    patch: dict[str, Any] = {}
    settings_patch = dict(org.settings_json or {})
    settings_dirty = False

    if payload.name is not None:
        patch["name"] = payload.name.strip()
    if payload.plan is not None:
        patch["plan_tier"] = payload.plan.value
    if payload.status is not None:
        patch["is_active"] = payload.status in {OrgStatus.ACTIVE, OrgStatus.TRIAL}
        settings_patch["status"] = payload.status.value
        settings_dirty = True
    if payload.billing_email is not None:
        settings_patch["billing_email"] = payload.billing_email
        settings_dirty = True
    if payload.timezone_name is not None:
        settings_patch["timezone"] = payload.timezone_name
        settings_patch["timezone_name"] = payload.timezone_name
        settings_dirty = True
    if payload.quotas is not None:
        patch["max_devices"] = payload.quotas.max_devices
        patch["max_users"] = payload.quotas.max_users
        patch["retention_days"] = payload.quotas.raw_retention_days
        settings_patch["max_synthetic_probes"] = payload.quotas.max_synthetic_probes
        settings_patch["max_edge_agents"] = payload.quotas.max_edge_agents
        settings_patch["max_api_keys"] = payload.quotas.max_api_keys
        settings_dirty = True
    if payload.settings is not None:
        settings_patch.update(payload.settings)
        settings_dirty = True

    if settings_dirty:
        patch["settings_json"] = settings_patch

    if patch:
        org = org_repo.update(org, patch, flush=True)
        _write_audit(
            db,
            auth,
            action=AuditAction.SETTINGS_UPDATE,
            resource_type="organization",
            resource_id=org.id,
            summary=f"Updated organization '{org.slug}' settings",
            before_state=before,
            after_state=org.to_summary_dict(),
        )
        db.commit()

    return _org_to_read(db, org)


@router.get(
    "/org/usage",
    response_model=OrganizationUsageResponse,
    summary="Inspect live organization quota consumption and resource counts",
)
def get_organization_usage(
    auth: AuthContext = Depends(require_permission(Permission.ORG_READ)),
    db: Session = Depends(get_db_session),
) -> OrganizationUsageResponse:
    org = OrganizationRepository(db).get_by_id_or_raise(auth.org_id)
    settings_map = dict(org.settings_json or {})
    thirty_days_ago = utcnow() - timedelta(days=30)

    users_used = int(
        db.execute(
            select(func.count())
            .select_from(User)
            .where(User.org_id == org.id, User.is_deleted.is_(False))
        ).scalar_one()
    )
    devices_used = int(
        db.execute(
            select(func.count())
            .select_from(Device)
            .where(Device.org_id == org.id, Device.is_deleted.is_(False))
        ).scalar_one()
    )
    sites_used = int(
        db.execute(
            select(func.count())
            .select_from(Site)
            .where(Site.org_id == org.id, Site.is_deleted.is_(False))
        ).scalar_one()
    )
    subnets_used = int(
        db.execute(
            select(func.count())
            .select_from(Subnet)
            .where(Subnet.org_id == org.id, Subnet.is_deleted.is_(False))
        ).scalar_one()
    )
    api_keys_used = int(
        db.execute(
            select(func.count())
            .select_from(ApiKey)
            .where(ApiKey.org_id == org.id, ApiKey.is_active.is_(True))
        ).scalar_one()
    )
    webhooks_used = int(
        db.execute(
            select(func.count())
            .select_from(OrgWebhookEndpoint)
            .where(OrgWebhookEndpoint.org_id == org.id)
        ).scalar_one()
    )
    probes_used = int(
        db.execute(
            select(func.count())
            .select_from(SyntheticProbeConfig)
            .where(SyntheticProbeConfig.org_id == org.id, SyntheticProbeConfig.is_deleted.is_(False))
        ).scalar_one()
    )
    agents_used = int(
        db.execute(
            select(func.count())
            .select_from(EdgeAgent)
            .where(EdgeAgent.org_id == org.id, EdgeAgent.is_deleted.is_(False))
        ).scalar_one()
    )
    alert_rules_used = int(
        db.execute(
            select(func.count())
            .select_from(AlertRule)
            .where(AlertRule.org_id == org.id, AlertRule.is_deleted.is_(False))
        ).scalar_one()
    )
    audit_logs_30d = int(
        db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.org_id == org.id, AuditLog.created_at >= thirty_days_ago)
        ).scalar_one()
    )

    try:
        plan = OrgPlan(str(org.plan_tier).lower())
    except ValueError:
        plan = OrgPlan.ENTERPRISE

    return OrganizationUsageResponse(
        org_id=org.id,
        org_slug=org.slug,
        plan=plan,
        generated_at=utcnow(),
        quotas={
            "devices": _quota_item(devices_used, int(org.max_devices)),
            "users": _quota_item(users_used, int(org.max_users)),
            "api_keys": _quota_item(api_keys_used, int(settings_map.get("max_api_keys", 50))),
            "synthetic_probes": _quota_item(
                probes_used, int(settings_map.get("max_synthetic_probes", 100))
            ),
            "edge_agents": _quota_item(
                agents_used, int(settings_map.get("max_edge_agents", 25))
            ),
        },
        counts={
            "users": users_used,
            "devices": devices_used,
            "sites": sites_used,
            "subnets": subnets_used,
            "api_keys_active": api_keys_used,
            "webhooks": webhooks_used,
            "synthetic_probes": probes_used,
            "edge_agents": agents_used,
            "alert_rules": alert_rules_used,
            "audit_logs_30d": audit_logs_30d,
        },
    )


# ---------------------------------------------------------------------------
# User Management Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=PaginatedResponse[UserRead],
    summary="List and search users within the organization",
)
def list_users(
    q: str | None = Query(default=None, max_length=200, description="Search by email, username, or name"),
    role: str | None = Query(default=None, description="Filter by RBAC role"),
    is_active: bool | None = Query(default=None, description="Filter by active status"),
    pagination: PaginationParams = Depends(parse_pagination),
    auth: AuthContext = Depends(
        require_any_permission(Permission.ORG_MANAGE_USERS, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> PaginatedResponse[UserRead]:
    orm_role_filter = normalize_orm_role(role).value if role else None
    page_result = UserRepository(db).search(
        query=q,
        role=orm_role_filter,
        is_active=is_active,
        org_id=auth.org_id,
        page=pagination.page,
        page_size=pagination.page_size,
    )
    items = [user_to_read(user) for user in page_result.items]
    return PaginatedResponse.create(
        items=items,
        total=page_result.total,
        page=page_result.page,
        page_size=page_result.page_size,
    )


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user within the organization",
)
def create_user(
    payload: UserCreate,
    auth: AuthContext = Depends(require_permission(Permission.ORG_MANAGE_USERS, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> UserRead:
    org_repo = OrganizationRepository(db)
    user_repo = UserRepository(db)
    org = org_repo.get_by_id_or_raise(auth.org_id)

    current_count = user_repo.count(org_id=org.id)
    if not org.can_add_user(current_count):
        raise ConflictError(
            "Organization has reached its maximum user limit",
            error_code="USER_QUOTA_EXCEEDED",
            details={"max_users": org.max_users, "current_users": current_count},
        )

    target_orm_role = normalize_orm_role(payload.role)
    if target_orm_role.rank > auth.orm_role.rank:
        raise AuthorizationError(
            f"Cannot assign role '{payload.role.value}' with higher privilege than your own",
            error_code="ROLE_ESCALATION_DENIED",
        )

    if user_repo.get_by_email(payload.email, org_id=org.id) is not None:
        raise ConflictError(
            f"A user with email '{payload.email}' already exists in this organization",
            error_code="DUPLICATE_EMAIL",
        )
    if user_repo.get_by_username(payload.username, org_id=org.id) is not None:
        raise ConflictError(
            f"Username '{payload.username}' is already taken in this organization",
            error_code="DUPLICATE_USERNAME",
        )

    validate_password_strength(
        payload.password,
        forbidden_substrings=(payload.username, payload.email.split("@")[0]),
        raise_on_error=True,
    )

    prefs = dict(payload.preferences or {})
    prefs["timezone_name"] = payload.timezone_name
    if payload.phone_number is not None:
        prefs["phone_number"] = payload.phone_number

    user = user_repo.create(
        {
            "org_id": org.id,
            "email": payload.email,
            "username": payload.username,
            "full_name": payload.full_name.strip(),
            "password_hash": hash_password(payload.password),
            "role": target_orm_role.value,
            "is_active": payload.is_active,
            "is_verified": True,
            "preferences_json": prefs,
        },
        flush=True,
    )
    _write_audit(
        db,
        auth,
        action=AuditAction.CREATE,
        resource_type="user",
        resource_id=user.id,
        summary=f"Created user '{user.email}' with role '{user.role}'",
        after_state=user.to_public_dict(),
    )
    db.commit()
    return user_to_read(user)


@router.get(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Fetch a single user profile by ID",
)
def get_user(
    user_id: str,
    auth: AuthContext = Depends(
        require_any_permission(Permission.ORG_MANAGE_USERS, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> UserRead:
    user = UserRepository(db).get_by_id_or_raise(user_id, org_id=auth.org_id)
    return user_to_read(user)


@router.patch(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Update a user's profile, preferences, active status, or RBAC role",
)
def update_user(
    user_id: str,
    payload: UserUpdate,
    auth: AuthContext = Depends(require_permission(Permission.ORG_READ, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> UserRead:
    is_self = auth.user_id == user_id
    can_manage_users = auth.has_permission(Permission.ORG_MANAGE_USERS)

    if not is_self and not can_manage_users:
        raise AuthorizationError(
            "Updating another user requires org:manage_users permission",
            error_code="INSUFFICIENT_PERMISSIONS",
        )
    if (payload.role is not None or payload.is_active is not None) and not can_manage_users:
        raise AuthorizationError(
            "Modifying role or active status requires org:manage_users permission",
            error_code="INSUFFICIENT_PERMISSIONS",
        )

    user_repo = UserRepository(db)
    user = user_repo.get_by_id_or_raise(user_id, org_id=auth.org_id)
    before = user.to_public_dict()
    patch: dict[str, Any] = {}
    role_changed = False

    if payload.email is not None and payload.email.lower() != user.email.lower():
        existing = user_repo.get_by_email(payload.email, org_id=auth.org_id)
        if existing is not None and existing.id != user.id:
            raise ConflictError("Another user already uses this email address", error_code="DUPLICATE_EMAIL")
        patch["email"] = payload.email

    if payload.full_name is not None:
        patch["full_name"] = payload.full_name.strip()

    if payload.mfa_enabled is not None:
        patch["mfa_enabled"] = payload.mfa_enabled

    if payload.role is not None:
        target_orm_role = normalize_orm_role(payload.role)
        if target_orm_role.rank > auth.orm_role.rank:
            raise AuthorizationError(
                f"Cannot assign role '{payload.role.value}' above your own privilege level",
                error_code="ROLE_ESCALATION_DENIED",
            )
        if user.role_enum.is_admin and not target_orm_role.is_admin:
            if _count_active_admins(db, auth.org_id) <= 1:
                raise ConflictError(
                    "Cannot demote the last active administrator in the organization",
                    error_code="LAST_ADMIN_PROTECTED",
                )
        if target_orm_role.value != user.role:
            patch["role"] = target_orm_role.value
            role_changed = True

    if payload.is_active is not None:
        if is_self and not payload.is_active:
            raise ConflictError(
                "You cannot deactivate your own account",
                error_code="SELF_DEACTIVATION_DENIED",
            )
        if not payload.is_active and user.role_enum.is_admin and _count_active_admins(db, auth.org_id) <= 1:
            raise ConflictError(
                "Cannot deactivate the last active administrator in the organization",
                error_code="LAST_ADMIN_PROTECTED",
            )
        patch["is_active"] = payload.is_active

    prefs = dict(user.preferences_json or {})
    prefs_changed = False
    if payload.phone_number is not None:
        prefs["phone_number"] = payload.phone_number
        prefs_changed = True
    if payload.timezone_name is not None:
        prefs["timezone_name"] = payload.timezone_name
        prefs_changed = True
    if payload.preferences is not None:
        prefs.update(payload.preferences)
        prefs_changed = True
    if prefs_changed:
        patch["preferences_json"] = prefs

    if patch:
        user = user_repo.update(user, patch, org_id=auth.org_id, flush=True)
        if payload.is_active is False:
            UserSessionRepository(db).revoke_all_for_user(user.id)
        _write_audit(
            db,
            auth,
            action=AuditAction.PERMISSION_CHANGE if role_changed else AuditAction.UPDATE,
            resource_type="user",
            resource_id=user.id,
            summary=f"Updated user '{user.email}'",
            before_state=before,
            after_state=user.to_public_dict(),
        )
        db.commit()

    return user_to_read(user)


@router.delete(
    "/users/{user_id}",
    response_model=DeleteConfirmationResponse,
    summary="Soft-delete a user and revoke all active sessions",
)
def delete_user(
    user_id: str,
    auth: AuthContext = Depends(require_permission(Permission.ORG_MANAGE_USERS, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> DeleteConfirmationResponse:
    if auth.user_id == user_id:
        raise ConflictError(
            "You cannot delete your own user account",
            error_code="SELF_DELETION_DENIED",
        )

    user_repo = UserRepository(db)
    user = user_repo.get_by_id_or_raise(user_id, org_id=auth.org_id)
    if user.role_enum.is_admin and _count_active_admins(db, auth.org_id) <= 1:
        raise ConflictError(
            "Cannot delete the last active administrator in the organization",
            error_code="LAST_ADMIN_PROTECTED",
        )

    before = user.to_public_dict()
    user.is_active = False
    user_repo.soft_delete(user, org_id=auth.org_id, flush=True)
    UserSessionRepository(db).revoke_all_for_user(user.id)

    _write_audit(
        db,
        auth,
        action=AuditAction.DELETE,
        resource_type="user",
        resource_id=user.id,
        summary=f"Deleted user '{user.email}'",
        before_state=before,
        after_state={"is_deleted": True, "is_active": False},
    )
    db.commit()

    return DeleteConfirmationResponse(
        deleted=True,
        resource_type="user",
        resource_id=user.id,
        message=f"User '{user.email}' has been deleted and all active sessions revoked",
    )


@router.post(
    "/users/{user_id}/unlock",
    response_model=UserRead,
    summary="Administratively unlock a brute-force-locked user account",
)
def unlock_user(
    user_id: str,
    auth: AuthContext = Depends(require_permission(Permission.ORG_MANAGE_USERS, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> UserRead:
    user_repo = UserRepository(db)
    user = user_repo.get_by_id_or_raise(user_id, org_id=auth.org_id)
    before = {
        "failed_login_attempts": user.failed_login_attempts,
        "locked_until": user.locked_until.isoformat() if user.locked_until else None,
    }
    user = user_repo.unlock_account(user.id, flush=True)
    _write_audit(
        db,
        auth,
        action=AuditAction.UPDATE,
        resource_type="user",
        resource_id=user.id,
        summary=f"Unlocked user account '{user.email}'",
        before_state=before,
        after_state={"failed_login_attempts": 0, "locked_until": None},
    )
    db.commit()
    return user_to_read(user)


# ---------------------------------------------------------------------------
# API Key Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api-keys",
    response_model=PaginatedResponse[ApiKeyResponse],
    summary="List organization API keys (omitting secrets and hashes)",
)
def list_api_keys(
    active_only: bool = Query(default=False, description="Return only active keys"),
    pagination: PaginationParams = Depends(parse_pagination),
    auth: AuthContext = Depends(
        require_any_permission(Permission.ORG_MANAGE_API_KEYS, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> PaginatedResponse[ApiKeyResponse]:
    filters: dict[str, Any] = {}
    if active_only:
        filters["is_active"] = True
    page_result = ApiKeyRepository(db).paginate(
        page=pagination.page,
        page_size=pagination.page_size,
        filters=filters or None,
        org_id=auth.org_id,
    )
    items = [_api_key_to_response(k) for k in page_result.items]
    return PaginatedResponse.create(
        items=items,
        total=page_result.total,
        page=page_result.page,
        page_size=page_result.page_size,
    )


@router.post(
    "/api-keys",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency(20, scope="api_keys:create"))],
    summary="Mint a new scoped API key (plaintext key returned once)",
)
def create_api_key(
    payload: ApiKeyCreatePayload,
    auth: AuthContext = Depends(require_permission(Permission.ORG_MANAGE_API_KEYS, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> ApiKeyCreatedResponse:
    key_repo = ApiKeyRepository(db)
    existing = key_repo.get_one_by(filters={"name": payload.name.strip()}, org_id=auth.org_id)
    if existing is not None:
        raise ConflictError(
            f"An API key named '{payload.name}' already exists in this organization",
            error_code="DUPLICATE_API_KEY_NAME",
        )

    expires_at = payload.expires_at
    if expires_at is None and payload.expires_in_days is not None:
        expires_at = utcnow() + timedelta(days=payload.expires_in_days)
    if expires_at is not None and expires_at <= utcnow():
        raise ValidationError("API key expiration timestamp must be in the future")

    generated = generate_api_key()
    api_key = key_repo.create(
        {
            "org_id": auth.org_id,
            "created_by_user_id": auth.user_id,
            "name": payload.name.strip(),
            "key_prefix": generated.prefix,
            "key_hash": generated.key_hash,
            "scopes_json": payload.scopes,
            "allowed_cidrs_json": payload.allowed_cidrs,
            "expires_at": expires_at,
            "is_active": True,
        },
        flush=True,
    )

    _write_audit(
        db,
        auth,
        action=AuditAction.API_KEY_CREATE,
        resource_type="api_key",
        resource_id=api_key.id,
        summary=f"Created API key '{api_key.name}' ({api_key.key_prefix})",
        after_state=api_key.to_public_dict(),
    )
    db.commit()

    base = _api_key_to_response(api_key, last_four=generated.raw_key[-4:])
    return ApiKeyCreatedResponse(
        **base.model_dump(exclude={"masked_key"}),
        secret_key=generated.raw_key,
    )


@router.delete(
    "/api-keys/{key_id}",
    response_model=DeleteConfirmationResponse,
    summary="Revoke (or permanently delete) an API key",
)
def delete_api_key(
    key_id: str,
    permanent: bool = Query(default=False, description="Hard-delete row instead of soft revocation"),
    auth: AuthContext = Depends(require_permission(Permission.ORG_MANAGE_API_KEYS, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> DeleteConfirmationResponse:
    key_repo = ApiKeyRepository(db)
    api_key = key_repo.get_by_id_or_raise(key_id, org_id=auth.org_id)
    before = api_key.to_public_dict()

    if permanent:
        key_repo.delete(api_key, org_id=auth.org_id, flush=True)
    else:
        key_repo.revoke(api_key.id, org_id=auth.org_id, flush=True)

    _write_audit(
        db,
        auth,
        action=AuditAction.API_KEY_REVOKE,
        resource_type="api_key",
        resource_id=api_key.id,
        summary=f"Revoked API key '{api_key.name}' (permanent={permanent})",
        before_state=before,
        after_state={"is_active": False, "permanent": permanent},
    )
    db.commit()

    return DeleteConfirmationResponse(
        deleted=True,
        resource_type="api_key",
        resource_id=api_key.id,
        message=f"API key '{api_key.name}' has been revoked",
    )


# ---------------------------------------------------------------------------
# Audit Log Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/audit-logs",
    response_model=PaginatedResponse[AuditLogRead],
    summary="Query immutable security and configuration audit logs",
)
def list_audit_logs(
    actor_user_id: str | None = Query(default=None),
    action: str | None = Query(default=None, max_length=120),
    action_prefix: str | None = Query(default=None, max_length=80),
    resource_type: str | None = Query(default=None, max_length=80),
    resource_id: str | None = Query(default=None, max_length=80),
    source_ip: str | None = Query(default=None, max_length=64),
    search: str | None = Query(default=None, alias="q", max_length=200),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    window: str | None = Query(default=None, description="Optional relative lookback window (e.g. 24h, 7d)"),
    pagination: PaginationParams = Depends(parse_pagination),
    auth: AuthContext = Depends(
        require_any_permission(Permission.ADMIN_AUDIT_LOGS_READ, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> PaginatedResponse[AuditLogRead]:
    since: datetime | None = start
    until: datetime | None = end
    if window is not None or start is not None or end is not None:
        resolved = parse_time_range(start=start, end=end, window=window)
        since = resolved.start
        until = resolved.end

    stmt = _query_audit_logs(
        db,
        org_id=auth.org_id,
        actor_user_id=actor_user_id,
        action=action,
        action_prefix=action_prefix,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=source_ip,
        search=search,
        since=since,
        until=until,
    )
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    ordered = (
        stmt.order_by(AuditLog.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    rows = list(db.execute(ordered).scalars().all())
    return PaginatedResponse.create(
        items=[_audit_to_read(row) for row in rows],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )


@router.get(
    "/audit-logs/summary",
    response_model=AuditSummaryResponse,
    summary="Summarize audit activity by action, resource type, top actors, and day",
)
def audit_logs_summary(
    time_range: ResolvedTimeRange = Depends(parse_time_range),
    window: str | None = Query(default=None),
    auth: AuthContext = Depends(
        require_any_permission(Permission.ADMIN_AUDIT_LOGS_READ, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> AuditSummaryResponse:
    # Default summary window to 30 days when caller did not explicitly specify bounds
    start = time_range.start
    end = time_range.end
    if window is None and time_range.window is None and time_range.duration_seconds <= 3601:
        start = end - timedelta(days=30)

    base = (
        select(AuditLog)
        .where(
            AuditLog.org_id == auth.org_id,
            AuditLog.created_at >= start,
            AuditLog.created_at <= end,
        )
        .subquery()
    )

    total_events = int(db.execute(select(func.count()).select_from(base)).scalar_one())

    by_action_rows = db.execute(
        select(base.c.action, func.count()).group_by(base.c.action)
    ).all()
    by_action = {str(act): int(cnt) for act, cnt in by_action_rows}

    by_resource_rows = db.execute(
        select(base.c.resource_type, func.count()).group_by(base.c.resource_type)
    ).all()
    by_resource_type = {str(rt): int(cnt) for rt, cnt in by_resource_rows}

    actor_rows = db.execute(
        select(base.c.actor_email, func.count().label("cnt"))
        .group_by(base.c.actor_email)
        .order_by(func.count().desc())
        .limit(10)
    ).all()
    top_actors = [
        {"actor_email": email or "system", "event_count": int(cnt)}
        for email, cnt in actor_rows
    ]

    day_expr = func.substr(func.cast(base.c.created_at, AuditLog.action.type), 1, 10)
    daily_rows = db.execute(
        select(day_expr.label("day"), func.count())
        .group_by(day_expr)
        .order_by(day_expr.asc())
    ).all()
    daily_counts = [{"date": str(day), "count": int(cnt)} for day, cnt in daily_rows if day]

    return AuditSummaryResponse(
        org_id=auth.org_id,
        start=start,
        end=end,
        total_events=total_events,
        by_action=by_action,
        by_resource_type=by_resource_type,
        top_actors=top_actors,
        daily_counts=daily_counts,
    )


@router.get(
    "/audit-logs/export",
    summary="Export audit logs as downloadable JSON or CSV for SIEM/compliance archival",
)
def export_audit_logs(
    export_format: Annotated[Literal["json", "csv"], Query(alias="format")] = "json",
    actor_user_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    window: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10_000),
    auth: AuthContext = Depends(
        require_any_permission(Permission.ADMIN_AUDIT_LOGS_READ, Permission.ORG_READ)
    ),
    db: Session = Depends(get_db_session),
) -> Response:
    since: datetime | None = start
    until: datetime | None = end
    if window is not None or start is not None or end is not None:
        resolved = parse_time_range(start=start, end=end, window=window)
        since = resolved.start
        until = resolved.end

    stmt = _query_audit_logs(
        db,
        org_id=auth.org_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        since=since,
        until=until,
    ).order_by(AuditLog.created_at.desc()).limit(limit)
    rows = list(db.execute(stmt).scalars().all())
    events = [row.to_event_dict() for row in rows]

    if auth.is_authenticated:
        try:
            _write_audit(
                db,
                auth,
                action=AuditAction.EXPORT,
                resource_type="audit_log",
                summary=f"Exported {len(events)} audit logs as {export_format}",
                after_state={"format": export_format, "count": len(events)},
            )
            db.commit()
        except Exception:
            db.rollback()

    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    if export_format == "csv":
        buf = io.StringIO()
        fieldnames = [
            "id",
            "created_at",
            "org_id",
            "actor_user_id",
            "actor_email",
            "action",
            "resource_type",
            "resource_id",
            "summary",
            "ip_address",
            "request_id",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(ev)
        csv_bytes = buf.getvalue().encode("utf-8")
        return StreamingResponse(
            io.BytesIO(csv_bytes),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="netpulse-audit-logs-{stamp}.csv"'
            },
        )

    json_payload = json.dumps(
        {
            "exported_at": utcnow().isoformat(),
            "org_id": auth.org_id,
            "count": len(events),
            "events": events,
        },
        indent=2,
        default=str,
    ).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(json_payload),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="netpulse-audit-logs-{stamp}.json"'
        },
    )


# ---------------------------------------------------------------------------
# Outbound Webhook Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/webhooks",
    response_model=PaginatedResponse[WebhookResponse],
    summary="List organization outbound webhook endpoints",
)
def list_webhooks(
    active_only: bool = Query(default=False, description="Return only active webhook endpoints"),
    pagination: PaginationParams = Depends(parse_pagination),
    auth: AuthContext = Depends(require_permission(Permission.ORG_READ)),
    db: Session = Depends(get_db_session),
) -> PaginatedResponse[WebhookResponse]:
    filters: dict[str, Any] = {}
    if active_only:
        filters["is_active"] = True
    page_result = WebhookEndpointRepository(db).paginate(
        page=pagination.page,
        page_size=pagination.page_size,
        filters=filters or None,
        org_id=auth.org_id,
    )
    return PaginatedResponse.create(
        items=[_webhook_to_response(ep) for ep in page_result.items],
        total=page_result.total,
        page=page_result.page,
        page_size=page_result.page_size,
    )


@router.post(
    "/webhooks",
    response_model=WebhookCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register an outbound organization webhook subscription",
)
def create_webhook(
    payload: WebhookCreatePayload,
    auth: AuthContext = Depends(require_permission(Permission.ORG_UPDATE, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> WebhookCreatedResponse:
    repo = WebhookEndpointRepository(db)
    existing = repo.get_one_by(filters={"name": payload.name.strip()}, org_id=auth.org_id)
    if existing is not None:
        raise ConflictError(
            f"A webhook named '{payload.name}' already exists in this organization",
            error_code="DUPLICATE_WEBHOOK_NAME",
        )

    patterns = payload.resolved_patterns()
    raw_secret = payload.signing_secret or f"whsec_{secrets.token_urlsafe(24)}"
    vault = get_credential_vault()
    encrypted_secret = vault.encrypt_json({"hmac_secret": raw_secret})

    endpoint = repo.create(
        {
            "org_id": auth.org_id,
            "name": payload.name.strip(),
            "url": payload.url,
            "secret_encrypted": encrypted_secret,
            "event_patterns_json": patterns,
            "is_active": payload.resolved_active(),
            "failure_count": 0,
        },
        flush=True,
    )

    _write_audit(
        db,
        auth,
        action=AuditAction.CREATE,
        resource_type="webhook",
        resource_id=endpoint.id,
        summary=f"Created webhook endpoint '{endpoint.name}'",
        after_state=endpoint.to_public_dict(),
    )
    db.commit()

    base = _webhook_to_response(endpoint)
    return WebhookCreatedResponse(**base.model_dump(), signing_secret=raw_secret)


@router.patch(
    "/webhooks/{webhook_id}",
    response_model=WebhookResponse,
    summary="Update an outbound webhook subscription or reset its circuit breaker",
)
def update_webhook(
    webhook_id: str,
    payload: WebhookUpdatePayload,
    auth: AuthContext = Depends(require_permission(Permission.ORG_UPDATE, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> WebhookResponse:
    repo = WebhookEndpointRepository(db)
    endpoint = repo.get_by_id_or_raise(webhook_id, org_id=auth.org_id)
    before = endpoint.to_public_dict()
    patch: dict[str, Any] = {}

    if payload.name is not None and payload.name.strip() != endpoint.name:
        dup = repo.get_one_by(filters={"name": payload.name.strip()}, org_id=auth.org_id)
        if dup is not None and dup.id != endpoint.id:
            raise ConflictError(
                f"A webhook named '{payload.name}' already exists",
                error_code="DUPLICATE_WEBHOOK_NAME",
            )
        patch["name"] = payload.name.strip()

    if payload.url is not None:
        patch["url"] = payload.url

    patterns = payload.event_patterns if payload.event_patterns is not None else payload.events
    if patterns is not None:
        cleaned = [str(p).strip() for p in patterns if str(p).strip()]
        if not cleaned:
            raise ValidationError("Event patterns must contain at least one pattern")
        patch["event_patterns_json"] = list(dict.fromkeys(cleaned))

    if payload.signing_secret is not None:
        patch["secret_encrypted"] = get_credential_vault().encrypt_json(
            {"hmac_secret": payload.signing_secret}
        )

    active_flag = payload.is_active if payload.is_active is not None else payload.is_enabled
    if active_flag is not None:
        patch["is_active"] = active_flag
        if active_flag and endpoint.failure_count > 0:
            patch["failure_count"] = 0

    if payload.reset_failures:
        patch["failure_count"] = 0

    if patch:
        endpoint = repo.update(endpoint, patch, org_id=auth.org_id, flush=True)
        _write_audit(
            db,
            auth,
            action=AuditAction.UPDATE,
            resource_type="webhook",
            resource_id=endpoint.id,
            summary=f"Updated webhook endpoint '{endpoint.name}'",
            before_state=before,
            after_state=endpoint.to_public_dict(),
        )
        db.commit()

    return _webhook_to_response(endpoint)


@router.delete(
    "/webhooks/{webhook_id}",
    response_model=DeleteConfirmationResponse,
    summary="Delete an organization webhook subscription",
)
def delete_webhook(
    webhook_id: str,
    auth: AuthContext = Depends(require_permission(Permission.ORG_UPDATE, strict_auth=True)),
    db: Session = Depends(get_db_session),
) -> DeleteConfirmationResponse:
    repo = WebhookEndpointRepository(db)
    endpoint = repo.get_by_id_or_raise(webhook_id, org_id=auth.org_id)
    before = endpoint.to_public_dict()

    repo.delete(endpoint, org_id=auth.org_id, flush=True)
    _write_audit(
        db,
        auth,
        action=AuditAction.DELETE,
        resource_type="webhook",
        resource_id=endpoint.id,
        summary=f"Deleted webhook endpoint '{endpoint.name}'",
        before_state=before,
    )
    db.commit()

    return DeleteConfirmationResponse(
        deleted=True,
        resource_type="webhook",
        resource_id=endpoint.id,
        message=f"Webhook endpoint '{endpoint.name}' has been deleted",
    )
