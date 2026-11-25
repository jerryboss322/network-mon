"""Identity, multi-tenancy, authentication, RBAC, audit, and webhook schemas.

Covers organizations, user registration/lifecycle, strong password management,
JWT login/refresh flows, scoped API keys (exposing plaintext secrets strictly once
at creation), immutable audit logs, outbound webhook subscriptions, and RBAC
permission introspection.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Self

from pydantic import Field, computed_field, field_validator, model_validator

from app.schemas.common import (
    BaseSchema,
    EmailAddress,
    EntityReadSchema,
    HttpUrlStr,
    MetadataDict,
    SlugStr,
    SortOrder,
    TenantEntityReadSchema,
    UTCDatetime,
)

# ---------------------------------------------------------------------------
# Identity & Security Enums
# ---------------------------------------------------------------------------


class OrgPlan(str, Enum):
    """Subscription tiers governing tenant quotas and features."""

    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class OrgStatus(str, Enum):
    """Operational lifecycle state of a tenant organization."""

    ACTIVE = "active"
    TRIAL = "trial"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class UserRole(str, Enum):
    """Hierarchical RBAC roles within an organization."""

    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    NETOPS_ENGINEER = "netops_engineer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class ApiKeyScope(str, Enum):
    """Granular capability scopes assignable to programmatic API keys."""

    INVENTORY_READ = "inventory:read"
    INVENTORY_WRITE = "inventory:write"
    TELEMETRY_READ = "telemetry:read"
    TELEMETRY_INGEST = "telemetry:ingest"
    TOPOLOGY_READ = "topology:read"
    TOPOLOGY_WRITE = "topology:write"
    ALERTING_READ = "alerting:read"
    ALERTING_WRITE = "alerting:write"
    AUTOMATION_READ = "automation:read"
    AUTOMATION_EXECUTE = "automation:execute"
    AUDIT_READ = "audit:read"
    ADMIN_ALL = "admin:*"


class AuditOutcome(str, Enum):
    """Outcome recorded on an audit log entry."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class WebhookEventType(str, Enum):
    """Platform events that can trigger outbound webhook deliveries."""

    ALERT_FIRED = "alert.fired"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_RESOLVED = "incident.resolved"
    DEVICE_CREATED = "device.created"
    DEVICE_OFFLINE = "device.offline"
    DEVICE_RECOVERED = "device.recovered"
    CONFIG_DRIFT_DETECTED = "config.drift_detected"
    COMPLIANCE_FAILED = "compliance.failed"
    PLAYBOOK_COMPLETED = "playbook.completed"
    PLAYBOOK_FAILED = "playbook.failed"
    DISCOVERY_COMPLETED = "discovery.completed"


class WebhookDeliveryStatus(str, Enum):
    """Delivery state for an outbound webhook attempt."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


# ---------------------------------------------------------------------------
# Password Policy Helper
# ---------------------------------------------------------------------------

_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


def validate_password_strength(password: str, *, min_length: int = 8) -> str:
    """Enforce baseline password complexity requirements."""
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long.")
    if len(password) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if not _UPPER_RE.search(password):
        raise ValueError("Password must include at least one uppercase letter.")
    if not _LOWER_RE.search(password):
        raise ValueError("Password must include at least one lowercase letter.")
    if not _DIGIT_RE.search(password):
        raise ValueError("Password must include at least one numeric digit.")
    if not _SPECIAL_RE.search(password):
        raise ValueError("Password must include at least one special character.")
    return password


# ---------------------------------------------------------------------------
# Organization Schemas
# ---------------------------------------------------------------------------


class OrganizationQuota(BaseSchema):
    """Resource limits enforced for a tenant organization."""

    max_devices: int = Field(default=500, ge=1, le=1_000_000)
    max_users: int = Field(default=50, ge=1, le=100_000)
    max_synthetic_probes: int = Field(default=100, ge=0, le=50_000)
    max_edge_agents: int = Field(default=25, ge=0, le=10_000)
    max_api_keys: int = Field(default=50, ge=1, le=1_000)
    raw_retention_days: int = Field(default=7, ge=1, le=365)


class OrganizationCreate(BaseSchema):
    """Payload for provisioning a new tenant organization."""

    name: str = Field(..., min_length=2, max_length=120, description="Organization display name.")
    slug: SlugStr = Field(..., description="Globally unique lowercase URL slug.")
    plan: OrgPlan = Field(default=OrgPlan.PRO, description="Subscription plan tier.")
    billing_email: EmailAddress | None = Field(
        default=None, description="Billing and administrative contact email."
    )
    timezone_name: str = Field(
        default="UTC", max_length=64, description="Default IANA timezone for reports and schedules."
    )
    quotas: OrganizationQuota = Field(
        default_factory=OrganizationQuota, description="Optional custom resource quotas."
    )
    settings: MetadataDict = Field(
        default_factory=dict, description="Tenant-specific feature flags and preferences."
    )


class OrganizationUpdate(BaseSchema):
    """Partial update payload for an existing organization."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    plan: OrgPlan | None = None
    status: OrgStatus | None = None
    billing_email: EmailAddress | None = None
    timezone_name: str | None = Field(default=None, max_length=64)
    quotas: OrganizationQuota | None = None
    settings: MetadataDict | None = None


class OrganizationSummary(BaseSchema):
    """Lightweight organization reference embedded in user or token responses."""

    id: str
    name: str
    slug: str
    plan: OrgPlan = OrgPlan.PRO
    status: OrgStatus = OrgStatus.ACTIVE


class OrganizationRead(EntityReadSchema):
    """Full representation of a tenant organization."""

    name: str
    slug: str
    plan: OrgPlan = OrgPlan.PRO
    status: OrgStatus = OrgStatus.ACTIVE
    billing_email: str | None = None
    timezone_name: str = "UTC"
    quotas: OrganizationQuota = Field(default_factory=OrganizationQuota)
    settings: MetadataDict = Field(default_factory=dict)
    member_count: int = Field(default=0, ge=0)
    device_count: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# User & Password Schemas
# ---------------------------------------------------------------------------


class UserRegister(BaseSchema):
    """Self-service registration payload creating a user and optional initial org."""

    email: EmailAddress = Field(..., description="Unique user login email address.")
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$",
        description="Unique handle using alphanumerics, dots, underscores, or hyphens.",
    )
    full_name: str = Field(..., min_length=1, max_length=120, description="User's full name.")
    password: str = Field(..., min_length=8, max_length=128, description="Account password.")
    organization_name: str | None = Field(
        default=None,
        min_length=2,
        max_length=120,
        description="Optional organization name to create for the registering user.",
    )
    organization_slug: SlugStr | None = Field(
        default=None, description="Optional slug for newly created organization."
    )
    timezone_name: str = Field(default="UTC", max_length=64)

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        return validate_password_strength(value)


class UserCreate(BaseSchema):
    """Admin-initiated user creation within a specific organization."""

    email: EmailAddress = Field(..., description="User login email.")
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$",
    )
    full_name: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = Field(default=UserRole.OPERATOR, description="Assigned RBAC role.")
    org_id: str | None = Field(
        default=None, description="Target organization ID (defaults to caller's tenant)."
    )
    is_active: bool = Field(default=True)
    phone_number: str | None = Field(default=None, max_length=32)
    timezone_name: str = Field(default="UTC", max_length=64)
    preferences: MetadataDict = Field(default_factory=dict)

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        return validate_password_strength(value)


class UserUpdate(BaseSchema):
    """Partial update payload for user profile or administrative role adjustments."""

    email: EmailAddress | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: UserRole | None = None
    is_active: bool | None = None
    mfa_enabled: bool | None = None
    phone_number: str | None = Field(default=None, max_length=32)
    timezone_name: str | None = Field(default=None, max_length=64)
    preferences: MetadataDict | None = None


class UserSummary(BaseSchema):
    """Compact user reference suitable for audit entries, incidents, and assignments."""

    id: str
    email: str
    username: str
    full_name: str
    role: UserRole


class UserRead(TenantEntityReadSchema):
    """Public user representation (never includes password hashes or MFA secrets)."""

    email: str
    username: str
    full_name: str
    role: UserRole = UserRole.VIEWER
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False
    phone_number: str | None = None
    timezone_name: str = "UTC"
    last_login_at: UTCDatetime | None = None
    failed_login_attempts: int = Field(default=0, ge=0)
    locked_until: UTCDatetime | None = None
    preferences: MetadataDict = Field(default_factory=dict)


class PasswordChangeRequest(BaseSchema):
    """Authenticated user password rotation request."""

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _check_new_password(cls, value: str) -> str:
        return validate_password_strength(value)

    @model_validator(mode="after")
    def _check_passwords_match_and_differ(self) -> Self:
        if self.new_password != self.confirm_new_password:
            raise ValueError("New password and confirmation do not match.")
        if self.current_password == self.new_password:
            raise ValueError("New password must differ from the current password.")
        return self


# ---------------------------------------------------------------------------
# Authentication & JWT Token Schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseSchema):
    """User credential login request supporting email or username plus optional MFA."""

    identifier: str = Field(
        ...,
        min_length=3,
        max_length=254,
        alias="email",
        description="User email address or username.",
    )
    password: str = Field(..., min_length=1, max_length=128, description="Account password.")
    mfa_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=8,
        pattern=r"^[0-9]{6,8}$",
        description="Optional 6-8 digit TOTP verification code.",
    )
    remember_me: bool = Field(
        default=False, description="Request an extended refresh token session."
    )


class TokenResponse(BaseSchema):
    """OAuth2-style JWT access and refresh token pair returned on authentication."""

    access_token: str = Field(..., description="Signed JWT bearer access token.")
    refresh_token: str | None = Field(
        default=None, description="Signed JWT refresh token for rotating sessions."
    )
    token_type: str = Field(default="bearer", description="HTTP Authorization scheme.")
    expires_in: int = Field(..., ge=1, description="Access token lifetime in seconds.")
    refresh_expires_in: int | None = Field(
        default=None, ge=1, description="Refresh token lifetime in seconds."
    )
    scopes: list[str] = Field(
        default_factory=list, description="Effective RBAC permissions encoded in token."
    )
    user: UserRead | None = Field(
        default=None, description="Authenticated user profile."
    )


class RefreshRequest(BaseSchema):
    """Request to exchange a valid refresh token for a fresh access token."""

    refresh_token: str = Field(..., min_length=20, description="Active JWT refresh token.")


class LogoutRequest(BaseSchema):
    """Request to revoke the current refresh token or all active sessions."""

    refresh_token: str | None = Field(default=None)
    revoke_all_sessions: bool = Field(default=False)


# ---------------------------------------------------------------------------
# API Key Schemas (Strict Secret Handling)
# ---------------------------------------------------------------------------


class ApiKeyCreate(BaseSchema):
    """Request payload to mint a new scoped API key."""

    name: str = Field(..., min_length=2, max_length=100, description="Descriptive key label.")
    description: str | None = Field(default=None, max_length=500)
    scopes: list[ApiKeyScope] = Field(
        default_factory=lambda: [ApiKeyScope.INVENTORY_READ, ApiKeyScope.TELEMETRY_READ],
        min_length=1,
        description="Explicit list of granted capability scopes.",
    )
    expires_at: UTCDatetime | None = Field(
        default=None, description="Optional UTC expiration timestamp (null = non-expiring)."
    )
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="Optional IP/CIDR allowlist restricting where this key may be used.",
    )


class ApiKeyRead(TenantEntityReadSchema):
    """Safe API key metadata representation (NEVER exposes the raw secret or hash)."""

    name: str
    description: str | None = None
    key_prefix: str = Field(..., description="Public prefix (e.g. 'npm_live_ab12').")
    last_four: str = Field(..., min_length=4, max_length=4, description="Final 4 chars of key.")
    scopes: list[ApiKeyScope] = Field(default_factory=list)
    created_by_user_id: str | None = None
    is_active: bool = True
    expires_at: UTCDatetime | None = None
    last_used_at: UTCDatetime | None = None
    last_used_ip: str | None = None
    allowed_cidrs: list[str] = Field(default_factory=list)
    revoked_at: UTCDatetime | None = None

    @computed_field
    @property
    def masked_key(self) -> str:
        """Return a safe display representation such as 'npm_ab12...9f0c'."""
        return f"{self.key_prefix}...{self.last_four}"


class ApiKeyCreated(ApiKeyRead):
    """One-time creation response containing the plaintext API key.

    Callers must store `secret_key` immediately; subsequent reads return `ApiKeyRead`
    which permanently omits the plaintext secret.
    """

    secret_key: str = Field(
        ...,
        min_length=24,
        description="Plaintext API key shown ONLY once upon creation.",
    )


# ---------------------------------------------------------------------------
# Audit Log Schemas
# ---------------------------------------------------------------------------


class AuditLogRead(TenantEntityReadSchema):
    """Immutable security and operational audit trail entry."""

    actor_user_id: str | None = Field(default=None, description="Acting user UUID, if human.")
    actor_api_key_id: str | None = Field(default=None, description="Acting API key UUID.")
    actor_email: str | None = Field(default=None, description="Denormalized actor identifier.")
    action: str = Field(
        ..., description="Dot-delimited verb (e.g. 'device.delete', 'auth.login')."
    )
    resource_type: str = Field(..., description="Target entity type (e.g. 'device', 'alert_rule').")
    resource_id: str | None = Field(default=None, description="Target entity UUID or slug.")
    outcome: AuditOutcome = Field(default=AuditOutcome.SUCCESS)
    source_ip: str | None = Field(default=None, description="Originating client IP.")
    user_agent: str | None = Field(default=None, max_length=512)
    request_id: str | None = Field(default=None, description="HTTP correlation ID.")
    before_state: MetadataDict | None = Field(
        default=None, description="Redacted snapshot prior to mutation."
    )
    after_state: MetadataDict | None = Field(
        default=None, description="Redacted snapshot after mutation."
    )
    metadata: MetadataDict = Field(default_factory=dict)


class AuditLogQuery(BaseSchema):
    """Filter criteria for searching immutable audit logs."""

    actor_user_id: str | None = None
    action: str | None = Field(default=None, max_length=120)
    action_prefix: str | None = Field(default=None, max_length=80)
    resource_type: str | None = Field(default=None, max_length=80)
    resource_id: str | None = Field(default=None, max_length=80)
    outcome: AuditOutcome | None = None
    source_ip: str | None = Field(default=None, max_length=45)
    search: str | None = Field(default=None, max_length=200)
    start: UTCDatetime | None = None
    end: UTCDatetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_order: SortOrder = SortOrder.DESC

    @model_validator(mode="after")
    def _validate_range(self) -> Self:
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("'start' must be earlier than 'end'.")
        return self


# ---------------------------------------------------------------------------
# Webhook Endpoint Schemas
# ---------------------------------------------------------------------------


class WebhookEndpointCreate(BaseSchema):
    """Configuration for registering an outbound event webhook subscription."""

    name: str = Field(..., min_length=2, max_length=120)
    url: HttpUrlStr = Field(..., description="HTTPS/HTTP destination URL.")
    events: list[WebhookEventType] = Field(
        ..., min_length=1, description="Subscribed platform event types."
    )
    signing_secret: str | None = Field(
        default=None,
        min_length=16,
        max_length=256,
        description="Optional HMAC-SHA256 signing secret (auto-generated if omitted).",
    )
    custom_headers: dict[str, str] = Field(
        default_factory=dict, description="Additional HTTP headers sent with each delivery."
    )
    is_enabled: bool = Field(default=True)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_retries: int = Field(default=3, ge=0, le=10)
    verify_tls: bool = Field(default=True)

    @field_validator("custom_headers")
    @classmethod
    def _validate_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        forbidden = {"host", "content-length", "x-netpulse-signature"}
        for key in headers:
            if key.lower() in forbidden:
                raise ValueError(f"Header {key!r} is reserved and cannot be overridden.")
        return headers


class WebhookEndpointUpdate(BaseSchema):
    """Partial update for a webhook endpoint."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    url: HttpUrlStr | None = None
    events: list[WebhookEventType] | None = Field(default=None, min_length=1)
    signing_secret: str | None = Field(default=None, min_length=16, max_length=256)
    custom_headers: dict[str, str] | None = None
    is_enabled: bool | None = None
    timeout_seconds: float | None = Field(default=None, ge=1.0, le=60.0)
    max_retries: int | None = Field(default=None, ge=0, le=10)
    verify_tls: bool | None = None


class WebhookEndpointRead(TenantEntityReadSchema):
    """Outbound webhook subscription state (omits raw HMAC signing secret)."""

    name: str
    url: str
    events: list[WebhookEventType] = Field(default_factory=list)
    has_signing_secret: bool = Field(
        default=True, description="Indicates whether HMAC signing is configured."
    )
    secret_hint: str | None = Field(
        default=None, description="Last 4 characters of the signing secret for identification."
    )
    custom_headers: dict[str, str] = Field(default_factory=dict)
    is_enabled: bool = True
    timeout_seconds: float = 10.0
    max_retries: int = 3
    verify_tls: bool = True
    last_delivery_at: UTCDatetime | None = None
    last_delivery_status: WebhookDeliveryStatus | None = None
    consecutive_failures: int = Field(default=0, ge=0)


class WebhookDeliveryRead(TenantEntityReadSchema):
    """Record of an individual outbound webhook delivery attempt."""

    endpoint_id: str
    event_type: WebhookEventType
    status: WebhookDeliveryStatus
    attempt_number: int = Field(default=1, ge=1)
    http_status_code: int | None = None
    latency_ms: float | None = Field(default=None, ge=0.0)
    error_message: str | None = None
    delivered_at: UTCDatetime | None = None


# ---------------------------------------------------------------------------
# RBAC Permission Introspection Schemas
# ---------------------------------------------------------------------------


class PermissionDescriptor(BaseSchema):
    """Metadata describing a single atomic RBAC permission."""

    code: str = Field(..., description="Canonical permission key (e.g. 'devices:write').")
    domain: str = Field(..., description="Functional area (inventory, telemetry, alerting, etc.).")
    description: str = Field(..., description="Human-readable explanation of the capability.")
    is_destructive: bool = Field(default=False)


class RolePermissionMatrix(BaseSchema):
    """Complete mapping of a role to its granted permissions."""

    role: UserRole
    display_name: str
    description: str
    permissions: list[str] = Field(default_factory=list)


class RbacPermissionsResponse(BaseSchema):
    """RBAC introspection response for the authenticated principal and platform roles."""

    user_id: str | None = None
    org_id: str | None = None
    current_role: UserRole
    effective_permissions: list[str] = Field(
        default_factory=list, description="Sorted list of permissions granted to the caller."
    )
    is_admin: bool = Field(default=False)
    catalog: list[PermissionDescriptor] = Field(
        default_factory=list, description="All defined platform permissions."
    )
    role_matrix: list[RolePermissionMatrix] = Field(
        default_factory=list, description="Role-to-permission inheritance matrix."
    )
