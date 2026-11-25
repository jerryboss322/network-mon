"""Organization administration, RBAC user management, API keys, and webhook service.

Implements :class:`RbacService` for tenant-scoped governance and security administration:

- Organization profile read & update with strict plan-tier quota enforcement
  (``max_devices``, ``max_users``, ``retention_days``) and live utilization metrics.
- Organization-scoped user CRUD (list/filter/paginate, create, update role/status,
  deactivate, reactivate, unlock, reset password, soft-delete) guarded by
  anti-privilege-escalation rules and last-admin protection.
- Scoped API key lifecycle management (create returning plaintext secret strictly once,
  redacted listings, cryptographic rotation, immediate revocation) with CIDR & scope validation.
- Outbound :class:`OrgWebhookEndpoint` CRUD backed by :class:`CredentialVault` secret
  encryption plus HMAC-SHA256 payload signing and constant-time signature verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.security import (
    CIDRAllowlist,
    CredentialVault,
    Permission,
    TokenRevocationStore,
    check_permission,
    generate_api_key,
    get_credential_vault,
    get_revocation_store,
    hash_password,
    validate_password_strength,
)
from app.db.base import new_uuid, utcnow
from app.db.repositories.base import PageResult
from app.db.repositories.identity import (
    ApiKeyRepository,
    OrganizationRepository,
    UserRepository,
    UserSessionRepository,
    WebhookEndpointRepository,
)
from app.db.repositories.inventory import DeviceRepository
from app.models.enums import AuditAction, UserRole
from app.models.identity import ApiKey, Organization, OrgWebhookEndpoint, User
from app.services.audit_service import AuditService
from app.services.auth_service import (
    normalize_model_role,
    resolve_security_role,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plan tier ceilings & webhook signature constants
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PlanTierPolicy:
    """Upper bounds and defaults for a NetPulse subscription tier."""

    tier: str
    default_max_devices: int
    max_devices_ceiling: int
    default_max_users: int
    max_users_ceiling: int
    default_retention_days: int
    max_retention_days: int
    max_api_keys: int
    max_webhooks: int


PLAN_TIER_POLICIES: dict[str, PlanTierPolicy] = {
    "free": PlanTierPolicy(
        tier="free",
        default_max_devices=25,
        max_devices_ceiling=50,
        default_max_users=5,
        max_users_ceiling=10,
        default_retention_days=14,
        max_retention_days=30,
        max_api_keys=5,
        max_webhooks=3,
    ),
    "starter": PlanTierPolicy(
        tier="starter",
        default_max_devices=100,
        max_devices_ceiling=250,
        default_max_users=20,
        max_users_ceiling=50,
        default_retention_days=30,
        max_retention_days=90,
        max_api_keys=20,
        max_webhooks=10,
    ),
    "pro": PlanTierPolicy(
        tier="pro",
        default_max_devices=500,
        max_devices_ceiling=2_500,
        default_max_users=50,
        max_users_ceiling=250,
        default_retention_days=90,
        max_retention_days=365,
        max_api_keys=50,
        max_webhooks=25,
    ),
    "enterprise": PlanTierPolicy(
        tier="enterprise",
        default_max_devices=5_000,
        max_devices_ceiling=1_000_000,
        default_max_users=250,
        max_users_ceiling=100_000,
        default_retention_days=365,
        max_retention_days=3_650,
        max_api_keys=500,
        max_webhooks=200,
    ),
}

WEBHOOK_SIGNATURE_HEADER = "X-NetPulse-Signature"
WEBHOOK_SIGNATURE_256_HEADER = "X-NetPulse-Signature-256"
WEBHOOK_TIMESTAMP_HEADER = "X-NetPulse-Timestamp"
DEFAULT_SIGNATURE_TOLERANCE_SECONDS = 300


# ---------------------------------------------------------------------------
# Structured result containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuotaStatus:
    """Current usage and remaining capacity for an organization resource quota."""

    resource: str
    current: int
    limit: int
    remaining: int
    utilization_pct: float
    exceeded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "current": self.current,
            "limit": self.limit,
            "remaining": self.remaining,
            "utilization_pct": self.utilization_pct,
            "exceeded": self.exceeded,
        }


@dataclass(frozen=True, slots=True)
class CreatedApiKeyResult:
    """One-time API key creation or rotation result exposing the plaintext key once."""

    api_key: ApiKey
    secret_key: str
    display_hint: str
    last_four: str

    def to_dict(self) -> dict[str, Any]:
        payload = self.api_key.to_public_dict()
        payload["secret_key"] = self.secret_key
        payload["display_hint"] = self.display_hint
        payload["last_four"] = self.last_four
        payload["masked_key"] = f"{self.api_key.key_prefix}...{self.last_four}"
        return payload


@dataclass(frozen=True, slots=True)
class CreatedWebhookResult:
    """One-time webhook creation or secret rotation result."""

    endpoint: OrgWebhookEndpoint
    signing_secret: str

    def to_dict(self) -> dict[str, Any]:
        payload = self.endpoint.to_public_dict()
        payload["signing_secret"] = self.signing_secret
        payload["secret_hint"] = self.signing_secret[-4:] if len(self.signing_secret) >= 4 else "****"
        return payload


@dataclass(frozen=True, slots=True)
class WebhookSignature:
    """Computed HMAC-SHA256 webhook signature and HTTP header bundle."""

    timestamp: int
    digest_hex: str
    header_value: str
    headers: dict[str, str]
    canonical_body: str


# ---------------------------------------------------------------------------
# Pure HMAC-SHA256 signing & verification helpers
# ---------------------------------------------------------------------------


def canonicalize_webhook_payload(payload: Mapping[str, Any] | str | bytes) -> str:
    """Serialize a webhook payload into deterministic UTF-8 text for HMAC signing."""
    if isinstance(payload, bytes):
        return payload.decode("utf-8")
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)


def sign_webhook_payload(
    payload: Mapping[str, Any] | str | bytes,
    secret: str,
    *,
    timestamp: int | None = None,
) -> WebhookSignature:
    """Compute an HMAC-SHA256 signature over ``"<timestamp>.<payload>"``.

    Produces headers suitable for outbound webhook delivery:
    - ``X-NetPulse-Timestamp``: Unix epoch timestamp in seconds.
    - ``X-NetPulse-Signature``: Versioned Stripe-style header ``t=<ts>,v1=<hex>``.
    - ``X-NetPulse-Signature-256``: GitHub-style header ``sha256=<hex>``.
    """
    if not secret or not isinstance(secret, str):
        raise ValidationError("Webhook signing secret must be a non-empty string")
    ts = int(timestamp if timestamp is not None else time.time())
    body = canonicalize_webhook_payload(payload)
    signed_message = f"{ts}.{body}".encode("utf-8")
    digest_hex = hmac.new(secret.encode("utf-8"), signed_message, hashlib.sha256).hexdigest()
    header_value = f"t={ts},v1={digest_hex}"
    return WebhookSignature(
        timestamp=ts,
        digest_hex=digest_hex,
        header_value=header_value,
        headers={
            WEBHOOK_TIMESTAMP_HEADER: str(ts),
            WEBHOOK_SIGNATURE_HEADER: header_value,
            WEBHOOK_SIGNATURE_256_HEADER: f"sha256={digest_hex}",
        },
        canonical_body=body,
    )


def verify_webhook_signature(
    payload: Mapping[str, Any] | str | bytes,
    signature_header: str,
    secret: str,
    *,
    timestamp: int | None = None,
    tolerance_seconds: int = DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
    now_timestamp: int | None = None,
) -> bool:
    """Verify an HMAC-SHA256 webhook signature in constant time with replay protection.

    Supports both ``t=<ts>,v1=<hex>`` (preferred) and ``sha256=<hex>`` (when
    *timestamp* is supplied separately).
    """
    if not signature_header or not secret:
        return False

    body = canonicalize_webhook_payload(payload)
    cleaned = signature_header.strip()
    now_ts = int(now_timestamp if now_timestamp is not None else time.time())

    # Format 1: t=<ts>,v1=<digest>
    if "v1=" in cleaned:
        parts: dict[str, str] = {}
        for segment in cleaned.split(","):
            if "=" in segment:
                k, v = segment.strip().split("=", 1)
                parts[k.strip()] = v.strip()
        ts_raw = parts.get("t")
        presented_sig = parts.get("v1")
        if not ts_raw or not presented_sig:
            return False
        try:
            sig_ts = int(ts_raw)
        except ValueError:
            return False
        if tolerance_seconds > 0 and abs(now_ts - sig_ts) > tolerance_seconds:
            return False
        expected = hmac.new(
            secret.encode("utf-8"),
            f"{sig_ts}.{body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(presented_sig.lower(), expected.lower())

    # Format 2: sha256=<digest>
    if cleaned.lower().startswith("sha256="):
        presented_sig = cleaned.split("=", 1)[1].strip()
        if timestamp is not None:
            if tolerance_seconds > 0 and abs(now_ts - int(timestamp)) > tolerance_seconds:
                return False
            msg = f"{int(timestamp)}.{body}".encode("utf-8")
        else:
            msg = body.encode("utf-8")
        expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(presented_sig.lower(), expected.lower())

    return False


def _generate_webhook_secret() -> str:
    return f"whsec_{secrets.token_hex(24)}"


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# RbacService
# ---------------------------------------------------------------------------


class RbacService:
    """Tenant-scoped service for organization governance, user RBAC, API keys, and webhooks."""

    def __init__(
        self,
        db: Session,
        *,
        vault: CredentialVault | None = None,
        revocation_store: TokenRevocationStore | None = None,
        settings: Settings | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.vault = vault or get_credential_vault()
        self.revocation_store = revocation_store or get_revocation_store()
        self.org_repo = OrganizationRepository(db)
        self.user_repo = UserRepository(db)
        self.session_repo = UserSessionRepository(db)
        self.api_key_repo = ApiKeyRepository(db)
        self.webhook_repo = WebhookEndpointRepository(db)
        self.device_repo = DeviceRepository(db)
        self.audit = audit_service or AuditService(db)

    # ── Authorization & Privilege-Escalation Guards ──────────────────────────

    def _assert_tenant_access(self, actor: User, org_id: str) -> None:
        """Ensure *actor* belongs to *org_id* unless *actor* is a ``SUPER_ADMIN``."""
        if not actor.is_active or actor.is_deleted:
            raise AuthorizationError("Actor account is not active")
        if actor.role_enum != UserRole.SUPER_ADMIN and actor.org_id != org_id:
            raise AuthorizationError(
                "Cross-organization administrative access is forbidden",
                details={"actor_org_id": actor.org_id, "target_org_id": org_id},
            )

    def _require_permission(
        self,
        actor: User,
        permission: Permission,
        *,
        org_id: str,
        resource: str | None = None,
    ) -> None:
        self._assert_tenant_access(actor, org_id)
        sec_role = resolve_security_role(actor.role)
        check_permission(sec_role, permission, resource=resource)

    def _assert_can_assign_role(self, actor: User, desired_role: UserRole) -> None:
        """Prevent vertical privilege escalation when assigning a role to a user."""
        actor_role = actor.role_enum
        if actor_role == UserRole.SUPER_ADMIN:
            return
        if desired_role == UserRole.SUPER_ADMIN:
            raise AuthorizationError(
                "Only a super_admin may assign the super_admin role",
                details={"actor_role": actor_role.value, "desired_role": desired_role.value},
            )
        if desired_role.rank > actor_role.rank:
            raise AuthorizationError(
                f"Role '{actor_role.value}' cannot assign higher-privilege role '{desired_role.value}'",
                details={"actor_role": actor_role.value, "desired_role": desired_role.value},
            )

    def _assert_can_manage_target_user(
        self,
        actor: User,
        target: User,
        *,
        allow_self: bool = False,
    ) -> None:
        """Prevent lateral/vertical tampering with equal- or higher-ranked accounts."""
        actor_role = actor.role_enum
        target_role = target.role_enum

        if actor.id == target.id:
            if not allow_self:
                raise AuthorizationError(
                    "Operation cannot be performed on your own account",
                    details={"user_id": target.id},
                )
            return

        if actor_role == UserRole.SUPER_ADMIN:
            return

        if target_role == UserRole.SUPER_ADMIN or target_role.rank >= actor_role.rank:
            raise AuthorizationError(
                f"Role '{actor_role.value}' cannot manage user with role '{target_role.value}'",
                details={
                    "actor_role": actor_role.value,
                    "target_role": target_role.value,
                    "target_user_id": target.id,
                },
            )

    def _assert_not_last_org_admin(self, org_id: str, target: User) -> None:
        """Ensure an organization always retains at least one active administrative user."""
        if not target.role_enum.is_admin or not target.is_active:
            return
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ORG_ADMIN.value, UserRole.ADMIN.value]
        active_admins = self.user_repo.list(
            filters={"role__in": admin_roles, "is_active": True},
            org_id=org_id,
        )
        remaining = [u for u in active_admins if u.id != target.id]
        if not remaining:
            raise ConflictError(
                "Cannot remove or demote the last active administrator in the organization",
                details={"org_id": org_id, "user_id": target.id},
            )

    # ── Organization Profile & Quota Enforcement ─────────────────────────────

    def get_organization(self, org_id: str) -> Organization:
        """Return an organization by ID or raise :class:`NotFoundError`."""
        return self.org_repo.get_by_id_or_raise(org_id)

    def check_user_quota(self, org_id: str, *, additional: int = 1) -> QuotaStatus:
        """Evaluate user seat usage against ``organization.max_users``."""
        org = self.get_organization(org_id)
        current = self.user_repo.count(filters={"is_active": True}, org_id=org_id)
        limit = int(org.max_users)
        remaining = max(0, limit - current)
        pct = round((current / limit) * 100.0, 2) if limit > 0 else 100.0
        exceeded = (current + max(0, additional)) > limit
        return QuotaStatus(
            resource="users",
            current=current,
            limit=limit,
            remaining=remaining,
            utilization_pct=pct,
            exceeded=exceeded,
        )

    def check_device_quota(self, org_id: str, *, additional: int = 1) -> QuotaStatus:
        """Evaluate managed device count against ``organization.max_devices``."""
        org = self.get_organization(org_id)
        current = self.device_repo.count(org_id=org_id)
        limit = int(org.max_devices)
        remaining = max(0, limit - current)
        pct = round((current / limit) * 100.0, 2) if limit > 0 else 100.0
        exceeded = (current + max(0, additional)) > limit
        return QuotaStatus(
            resource="devices",
            current=current,
            limit=limit,
            remaining=remaining,
            utilization_pct=pct,
            exceeded=exceeded,
        )

    def enforce_user_quota(self, org_id: str, *, additional: int = 1) -> QuotaStatus:
        """Raise :class:`AuthorizationError` if adding users exceeds plan limits."""
        status = self.check_user_quota(org_id, additional=additional)
        if status.exceeded:
            raise AuthorizationError(
                f"Organization user quota exceeded ({status.current}/{status.limit} active users)",
                error_code="QUOTA_EXCEEDED",
                details=status.to_dict(),
            )
        return status

    def enforce_device_quota(self, org_id: str, *, additional: int = 1) -> QuotaStatus:
        """Raise :class:`AuthorizationError` if adding devices exceeds plan limits."""
        status = self.check_device_quota(org_id, additional=additional)
        if status.exceeded:
            raise AuthorizationError(
                f"Organization device quota exceeded ({status.current}/{status.limit} devices)",
                error_code="QUOTA_EXCEEDED",
                details=status.to_dict(),
            )
        return status

    def get_organization_profile(self, org_id: str, *, actor: User | None = None) -> dict[str, Any]:
        """Return full organization profile, plan limits, and live quota usage."""
        if actor is not None:
            self._require_permission(actor, Permission.ORG_READ, org_id=org_id, resource=org_id)
        org = self.get_organization(org_id)
        user_quota = self.check_user_quota(org_id, additional=0)
        device_quota = self.check_device_quota(org_id, additional=0)
        total_users = self.user_repo.count(org_id=org_id)
        active_api_keys = self.api_key_repo.count(filters={"is_active": True}, org_id=org_id)
        active_webhooks = self.webhook_repo.count(filters={"is_active": True}, org_id=org_id)
        policy = PLAN_TIER_POLICIES.get(org.plan_tier, PLAN_TIER_POLICIES["enterprise"])

        return {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "plan_tier": org.plan_tier,
            "max_devices": org.max_devices,
            "max_users": org.max_users,
            "retention_days": org.retention_days,
            "settings": dict(org.settings_json or {}),
            "is_active": org.is_active,
            "created_at": org.created_at.isoformat() if org.created_at else None,
            "updated_at": org.updated_at.isoformat() if org.updated_at else None,
            "usage": {
                "users": user_quota.to_dict(),
                "total_users": total_users,
                "devices": device_quota.to_dict(),
                "active_api_keys": active_api_keys,
                "max_api_keys": policy.max_api_keys,
                "active_webhooks": active_webhooks,
                "max_webhooks": policy.max_webhooks,
            },
            "plan_limits": {
                "tier": policy.tier,
                "max_devices_ceiling": policy.max_devices_ceiling,
                "max_users_ceiling": policy.max_users_ceiling,
                "max_retention_days": policy.max_retention_days,
                "max_api_keys": policy.max_api_keys,
                "max_webhooks": policy.max_webhooks,
            },
        }

    def update_organization_profile(
        self,
        org_id: str,
        *,
        actor: User,
        name: str | None = None,
        plan_tier: str | None = None,
        max_devices: int | None = None,
        max_users: int | None = None,
        retention_days: int | None = None,
        settings_patch: Mapping[str, Any] | None = None,
        is_active: bool | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> Organization:
        """Update organization settings and quotas while enforcing plan limits."""
        self._require_permission(actor, Permission.ORG_UPDATE, org_id=org_id, resource=org_id)
        org = self.get_organization(org_id)
        before_snapshot = {
            "name": org.name,
            "plan_tier": org.plan_tier,
            "max_devices": org.max_devices,
            "max_users": org.max_users,
            "retention_days": org.retention_days,
            "is_active": org.is_active,
            "settings_json": dict(org.settings_json or {}),
        }

        is_super = actor.role_enum == UserRole.SUPER_ADMIN
        effective_tier = org.plan_tier

        if plan_tier is not None:
            normalized_tier = plan_tier.strip().lower()
            if normalized_tier not in PLAN_TIER_POLICIES:
                raise ValidationError(
                    f"Unsupported plan tier '{plan_tier}'",
                    details={"supported": sorted(PLAN_TIER_POLICIES.keys())},
                )
            if normalized_tier != org.plan_tier and not is_super:
                raise AuthorizationError(
                    "Only a super_admin may change an organization's subscription plan tier",
                    details={"current_tier": org.plan_tier, "requested_tier": normalized_tier},
                )
            effective_tier = normalized_tier
            org.plan_tier = normalized_tier

        policy = PLAN_TIER_POLICIES.get(effective_tier, PLAN_TIER_POLICIES["enterprise"])

        if name is not None:
            cleaned_name = name.strip()
            if len(cleaned_name) < 2 or len(cleaned_name) > 160:
                raise ValidationError("Organization name must be between 2 and 160 characters")
            org.name = cleaned_name

        if max_devices is not None:
            if max_devices < 1:
                raise ValidationError("max_devices must be >= 1")
            current_devices = self.device_repo.count(org_id=org_id)
            if max_devices < current_devices:
                raise ValidationError(
                    f"max_devices ({max_devices}) cannot be lower than current device count ({current_devices})",
                    details={"current_devices": current_devices, "requested_max_devices": max_devices},
                )
            if not is_super and max_devices > policy.max_devices_ceiling:
                raise AuthorizationError(
                    f"Plan '{policy.tier}' allows at most {policy.max_devices_ceiling} devices",
                    details={"ceiling": policy.max_devices_ceiling, "requested": max_devices},
                )
            org.max_devices = max_devices

        if max_users is not None:
            if max_users < 1:
                raise ValidationError("max_users must be >= 1")
            current_users = self.user_repo.count(filters={"is_active": True}, org_id=org_id)
            if max_users < current_users:
                raise ValidationError(
                    f"max_users ({max_users}) cannot be lower than current active user count ({current_users})",
                    details={"current_users": current_users, "requested_max_users": max_users},
                )
            if not is_super and max_users > policy.max_users_ceiling:
                raise AuthorizationError(
                    f"Plan '{policy.tier}' allows at most {policy.max_users_ceiling} users",
                    details={"ceiling": policy.max_users_ceiling, "requested": max_users},
                )
            org.max_users = max_users

        if retention_days is not None:
            if retention_days < 1:
                raise ValidationError("retention_days must be >= 1")
            if not is_super and retention_days > policy.max_retention_days:
                raise AuthorizationError(
                    f"Plan '{policy.tier}' allows retention up to {policy.max_retention_days} days",
                    details={"ceiling": policy.max_retention_days, "requested": retention_days},
                )
            org.retention_days = retention_days

        if is_active is not None:
            if not is_super:
                raise AuthorizationError("Only a super_admin may activate or suspend an organization")
            org.is_active = is_active

        if settings_patch is not None:
            merged_settings = dict(org.settings_json or {})
            merged_settings.update(dict(settings_patch))
            org.settings_json = merged_settings

        self.db.add(org)
        self.db.flush()

        after_snapshot = {
            "name": org.name,
            "plan_tier": org.plan_tier,
            "max_devices": org.max_devices,
            "max_users": org.max_users,
            "retention_days": org.retention_days,
            "is_active": org.is_active,
            "settings_json": dict(org.settings_json or {}),
        }
        self.audit.record(
            org_id=org.id,
            action=AuditAction.SETTINGS_UPDATE,
            resource_type="organization",
            resource_id=org.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Updated organization profile '{org.name}'",
            before_state=before_snapshot,
            after_state=after_snapshot,
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return org

    # ── User CRUD within Organization ────────────────────────────────────────

    def list_users(
        self,
        org_id: str,
        *,
        actor: User | None = None,
        query: str | None = None,
        role: UserRole | str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[User]:
        """List, filter, and paginate users belonging to *org_id*."""
        if actor is not None:
            self._require_permission(actor, Permission.ORG_READ, org_id=org_id, resource="users")
        if page < 1:
            raise ValidationError("page must be >= 1")
        if page_size < 1 or page_size > 200:
            raise ValidationError("page_size must be between 1 and 200")

        role_filter: str | None = None
        if role is not None:
            role_filter = normalize_model_role(role).value

        return self.user_repo.search(
            query=query,
            role=role_filter,
            is_active=is_active,
            org_id=org_id,
            page=page,
            page_size=page_size,
        )

    def get_user(self, org_id: str, user_id: str, *, actor: User | None = None) -> User:
        """Fetch a tenant-scoped user or raise :class:`NotFoundError`."""
        if actor is not None:
            self._require_permission(actor, Permission.ORG_READ, org_id=org_id, resource=user_id)
        return self.user_repo.get_by_id_or_raise(user_id, org_id=org_id)

    def create_user(
        self,
        org_id: str,
        *,
        actor: User,
        email: str,
        username: str,
        password: str,
        full_name: str = "",
        role: UserRole | str = UserRole.OPERATOR,
        is_active: bool = True,
        is_verified: bool = True,
        preferences: Mapping[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Create a new user inside *org_id* enforcing quotas and privilege guards."""
        self._require_permission(actor, Permission.ORG_MANAGE_USERS, org_id=org_id, resource="users")

        target_role = normalize_model_role(role)
        self._assert_can_assign_role(actor, target_role)

        if is_active:
            self.enforce_user_quota(org_id, additional=1)

        normalized_email = email.strip().lower()
        normalized_username = username.strip()

        if self.user_repo.get_by_email(normalized_email, org_id=org_id, include_deleted=True) is not None:
            raise ConflictError(
                f"A user with email '{normalized_email}' already exists in this organization",
                details={"field": "email"},
            )
        if self.user_repo.get_by_username(normalized_username, org_id=org_id) is not None:
            raise ConflictError(
                f"Username '{normalized_username}' is already taken in this organization",
                details={"field": "username"},
            )

        validate_password_strength(
            password,
            forbidden_substrings=(normalized_email.split("@", 1)[0], normalized_username),
            raise_on_error=True,
        )

        user = User(
            id=new_uuid(),
            org_id=org_id,
            email=normalized_email,
            username=normalized_username,
            full_name=full_name.strip() or normalized_username,
            password_hash=hash_password(password),
            role=target_role.value,
            is_active=is_active,
            is_verified=is_verified,
            mfa_enabled=False,
            failed_login_attempts=0,
            preferences_json=dict(preferences or {}),
        )
        self.db.add(user)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="user",
            resource_id=user.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Created user '{user.email}' with role '{user.role}'",
            after_state=user.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return user

    def update_user(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        email: str | None = None,
        full_name: str | None = None,
        role: UserRole | str | None = None,
        is_active: bool | None = None,
        mfa_enabled: bool | None = None,
        preferences: Mapping[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Update user profile, role, or status with privilege-escalation protection."""
        self._require_permission(actor, Permission.ORG_MANAGE_USERS, org_id=org_id, resource=user_id)
        target = self.user_repo.get_by_id_or_raise(user_id, org_id=org_id)
        self._assert_can_manage_target_user(actor, target, allow_self=True)

        before_state = target.to_public_dict()
        role_changed = False
        revoke_sessions_needed = False

        if role is not None:
            new_role = normalize_model_role(role)
            if new_role != target.role_enum:
                self._require_permission(
                    actor,
                    Permission.ORG_MANAGE_ROLES,
                    org_id=org_id,
                    resource=user_id,
                )
                if actor.id == target.id and new_role.rank > actor.role_enum.rank:
                    raise AuthorizationError(
                        "Users cannot escalate their own RBAC role",
                        details={"current_role": actor.role, "requested_role": new_role.value},
                    )
                self._assert_can_assign_role(actor, new_role)
                if target.role_enum.is_admin and not new_role.is_admin:
                    self._assert_not_last_org_admin(org_id, target)
                target.role = new_role.value
                role_changed = True
                if new_role.rank < UserRole(before_state["role"]).rank:
                    revoke_sessions_needed = True

        if is_active is not None and is_active != target.is_active:
            if not is_active:
                if actor.id == target.id:
                    raise ValidationError("You cannot deactivate your own account")
                self._assert_not_last_org_admin(org_id, target)
                target.is_active = False
                revoke_sessions_needed = True
            else:
                self.enforce_user_quota(org_id, additional=1)
                target.is_active = True

        if email is not None:
            normalized_email = email.strip().lower()
            if normalized_email != target.email:
                conflict = self.user_repo.get_by_email(
                    normalized_email,
                    org_id=org_id,
                    include_deleted=True,
                )
                if conflict is not None and conflict.id != target.id:
                    raise ConflictError(
                        f"Email '{normalized_email}' is already used by another user in this organization",
                        details={"field": "email"},
                    )
                target.email = normalized_email

        if full_name is not None:
            cleaned_name = full_name.strip()
            if not cleaned_name:
                raise ValidationError("full_name must not be empty")
            target.full_name = cleaned_name

        if mfa_enabled is not None:
            target.mfa_enabled = mfa_enabled

        if preferences is not None:
            merged_prefs = dict(target.preferences_json or {})
            merged_prefs.update(dict(preferences))
            target.preferences_json = merged_prefs

        self.db.add(target)
        self.db.flush()

        if revoke_sessions_needed:
            self.session_repo.revoke_all_for_user(target.id, flush=True)
            self.revocation_store.revoke_subject(target.id)

        audit_action = AuditAction.PERMISSION_CHANGE if role_changed else AuditAction.UPDATE
        self.audit.record(
            org_id=org_id,
            action=audit_action,
            resource_type="user",
            resource_id=target.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=(
                f"Changed role for '{target.email}' from '{before_state['role']}' to '{target.role}'"
                if role_changed
                else f"Updated user '{target.email}'"
            ),
            before_state=before_state,
            after_state=target.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return target

    def deactivate_user(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Deactivate a user account and immediately revoke all active sessions & tokens."""
        return self.update_user(
            org_id,
            user_id,
            actor=actor,
            is_active=False,
            ip_address=ip_address,
            user_agent=user_agent,
            commit=commit,
        )

    def reactivate_user(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Re-enable a deactivated user account after verifying organization user seat quota."""
        target = self.update_user(
            org_id,
            user_id,
            actor=actor,
            is_active=True,
            ip_address=ip_address,
            user_agent=user_agent,
            commit=False,
        )
        target.unlock()
        self.db.add(target)
        self.db.flush()
        if commit:
            self.db.commit()
        return target

    def unlock_user(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Clear brute-force lockout and reset failed login attempts for a user."""
        self._require_permission(actor, Permission.ORG_MANAGE_USERS, org_id=org_id, resource=user_id)
        target = self.user_repo.get_by_id_or_raise(user_id, org_id=org_id)
        self._assert_can_manage_target_user(actor, target, allow_self=False)

        before_state = {
            "failed_login_attempts": target.failed_login_attempts,
            "locked_until": target.locked_until.isoformat() if target.locked_until else None,
        }
        target.unlock()
        self.db.add(target)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.UPDATE,
            resource_type="user",
            resource_id=target.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Administratively unlocked account '{target.email}'",
            before_state=before_state,
            after_state={"failed_login_attempts": 0, "locked_until": None},
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return target

    def reset_user_password(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        new_password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> dict[str, Any]:
        """Administratively reset a user's password, unlock them, and revoke all sessions."""
        self._require_permission(actor, Permission.ORG_MANAGE_USERS, org_id=org_id, resource=user_id)
        target = self.user_repo.get_by_id_or_raise(user_id, org_id=org_id)
        self._assert_can_manage_target_user(actor, target, allow_self=False)

        validate_password_strength(
            new_password,
            forbidden_substrings=(target.email.split("@", 1)[0], target.username),
            raise_on_error=True,
        )

        target.password_hash = hash_password(new_password)
        target.unlock()
        self.db.add(target)
        self.db.flush()

        revoked_sessions = self.session_repo.revoke_all_for_user(target.id, flush=True)
        self.revocation_store.revoke_subject(target.id)

        self.audit.record(
            org_id=org_id,
            action=AuditAction.PASSWORD_CHANGE,
            resource_type="user",
            resource_id=target.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Admin '{actor.email}' reset password for '{target.email}'",
            after_state={
                "password_reset_by_admin": True,
                "revoked_sessions": revoked_sessions,
            },
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return {
            "user_id": target.id,
            "password_reset": True,
            "revoked_sessions": revoked_sessions,
        }

    def soft_delete_user(
        self,
        org_id: str,
        user_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> User:
        """Soft-delete a user, revoke sessions, and preserve audit trail integrity."""
        self._require_permission(actor, Permission.ORG_MANAGE_USERS, org_id=org_id, resource=user_id)
        target = self.user_repo.get_by_id_or_raise(user_id, org_id=org_id)
        self._assert_can_manage_target_user(actor, target, allow_self=False)
        self._assert_not_last_org_admin(org_id, target)

        before_state = target.to_public_dict()
        target.is_active = False
        target.mark_deleted()
        self.db.add(target)
        self.db.flush()

        self.session_repo.revoke_all_for_user(target.id, flush=True)
        self.revocation_store.revoke_subject(target.id)

        self.audit.record(
            org_id=org_id,
            action=AuditAction.DELETE,
            resource_type="user",
            resource_id=target.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Soft-deleted user '{target.email}'",
            before_state=before_state,
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return target

    # ── API Key Management ───────────────────────────────────────────────────

    def create_api_key(
        self,
        org_id: str,
        *,
        actor: User,
        name: str,
        scopes: Sequence[str],
        allowed_cidrs: Sequence[str] = (),
        expires_at: datetime | None = None,
        expires_in_days: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> CreatedApiKeyResult:
        """Mint a new scoped API key, returning the plaintext secret strictly once."""
        self._require_permission(actor, Permission.ORG_MANAGE_API_KEYS, org_id=org_id, resource="api_keys")

        org = self.get_organization(org_id)
        policy = PLAN_TIER_POLICIES.get(org.plan_tier, PLAN_TIER_POLICIES["enterprise"])
        active_key_count = self.api_key_repo.count(filters={"is_active": True}, org_id=org_id)
        if active_key_count >= policy.max_api_keys:
            raise AuthorizationError(
                f"Organization has reached the maximum of {policy.max_api_keys} active API keys",
                error_code="QUOTA_EXCEEDED",
                details={"current": active_key_count, "limit": policy.max_api_keys},
            )

        cleaned_name = name.strip()
        if len(cleaned_name) < 2 or len(cleaned_name) > 160:
            raise ValidationError("API key name must be between 2 and 160 characters")

        if self.api_key_repo.exists(filters={"name": cleaned_name}, org_id=org_id):
            raise ConflictError(
                f"An API key named '{cleaned_name}' already exists in this organization",
                details={"field": "name"},
            )

        cleaned_scopes = self._validate_api_key_scopes(actor, scopes)
        normalized_cidrs = self._validate_cidrs(allowed_cidrs)
        resolved_expires_at = self._resolve_expiry(expires_at=expires_at, expires_in_days=expires_in_days)

        generated = generate_api_key(namespace=self.settings.security.api_key_prefix)
        api_key = ApiKey(
            id=new_uuid(),
            org_id=org_id,
            created_by_user_id=actor.id,
            name=cleaned_name,
            key_prefix=generated.prefix,
            key_hash=generated.key_hash,
            scopes_json=cleaned_scopes,
            allowed_cidrs_json=normalized_cidrs,
            expires_at=resolved_expires_at,
            is_active=True,
        )
        self.db.add(api_key)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.API_KEY_CREATE,
            resource_type="api_key",
            resource_id=api_key.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Created API key '{api_key.name}' ({api_key.key_prefix})",
            after_state=api_key.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return CreatedApiKeyResult(
            api_key=api_key,
            secret_key=generated.raw_key,
            display_hint=generated.display_hint,
            last_four=generated.raw_key[-4:],
        )

    def list_api_keys(
        self,
        org_id: str,
        *,
        actor: User | None = None,
        active_only: bool = False,
        created_by_user_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[dict[str, Any]]:
        """Return paginated, redacted API key metadata (never exposes key hashes)."""
        if actor is not None:
            self._require_permission(
                actor,
                Permission.ORG_MANAGE_API_KEYS,
                org_id=org_id,
                resource="api_keys",
            )
        filters: dict[str, Any] = {}
        if active_only:
            filters["is_active"] = True
        if created_by_user_id:
            filters["created_by_user_id"] = created_by_user_id

        result = self.api_key_repo.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            org_id=org_id,
        )
        redacted_items = [self._redact_api_key(item) for item in result.items]
        return PageResult(
            items=redacted_items,
            total=result.total,
            page=result.page,
            page_size=result.page_size,
            total_pages=result.total_pages,
            has_next=result.has_next,
            has_prev=result.has_prev,
        )

    def get_api_key(
        self,
        org_id: str,
        api_key_id: str,
        *,
        actor: User | None = None,
    ) -> dict[str, Any]:
        """Return redacted metadata for a single organization API key."""
        if actor is not None:
            self._require_permission(
                actor,
                Permission.ORG_MANAGE_API_KEYS,
                org_id=org_id,
                resource=api_key_id,
            )
        entity = self.api_key_repo.get_by_id_or_raise(api_key_id, org_id=org_id)
        return self._redact_api_key(entity)

    def rotate_api_key(
        self,
        org_id: str,
        api_key_id: str,
        *,
        actor: User,
        expires_at: datetime | None = None,
        expires_in_days: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> CreatedApiKeyResult:
        """Replace an API key's prefix and SHA-256 hash, returning the new secret once."""
        self._require_permission(
            actor,
            Permission.ORG_MANAGE_API_KEYS,
            org_id=org_id,
            resource=api_key_id,
        )
        api_key = self.api_key_repo.get_by_id_or_raise(api_key_id, org_id=org_id)
        before_state = api_key.to_public_dict()

        generated = generate_api_key(namespace=self.settings.security.api_key_prefix)
        api_key.key_prefix = generated.prefix
        api_key.key_hash = generated.key_hash
        api_key.is_active = True

        if expires_at is not None or expires_in_days is not None:
            api_key.expires_at = self._resolve_expiry(
                expires_at=expires_at,
                expires_in_days=expires_in_days,
            )

        self.db.add(api_key)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.CREDENTIAL_ROTATE,
            resource_type="api_key",
            resource_id=api_key.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Rotated API key '{api_key.name}' (new prefix {api_key.key_prefix})",
            before_state=before_state,
            after_state=api_key.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return CreatedApiKeyResult(
            api_key=api_key,
            secret_key=generated.raw_key,
            display_hint=generated.display_hint,
            last_four=generated.raw_key[-4:],
        )

    def revoke_api_key(
        self,
        org_id: str,
        api_key_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> ApiKey:
        """Immediately deactivate an organization API key."""
        self._require_permission(
            actor,
            Permission.ORG_MANAGE_API_KEYS,
            org_id=org_id,
            resource=api_key_id,
        )
        api_key = self.api_key_repo.get_by_id_or_raise(api_key_id, org_id=org_id)
        before_state = api_key.to_public_dict()
        api_key.revoke()
        self.db.add(api_key)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.API_KEY_REVOKE,
            resource_type="api_key",
            resource_id=api_key.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Revoked API key '{api_key.name}' ({api_key.key_prefix})",
            before_state=before_state,
            after_state=api_key.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return api_key

    # ── Organization Webhook Endpoints & HMAC Signing ────────────────────────

    def create_webhook_endpoint(
        self,
        org_id: str,
        *,
        actor: User,
        name: str,
        url: str,
        event_patterns: Sequence[str],
        secret: str | None = None,
        is_active: bool = True,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> CreatedWebhookResult:
        """Create a tenant outbound webhook subscription with vaulted HMAC secret."""
        self._require_permission(actor, Permission.ORG_UPDATE, org_id=org_id, resource="webhooks")

        org = self.get_organization(org_id)
        policy = PLAN_TIER_POLICIES.get(org.plan_tier, PLAN_TIER_POLICIES["enterprise"])
        existing_count = self.webhook_repo.count(org_id=org_id)
        if existing_count >= policy.max_webhooks:
            raise AuthorizationError(
                f"Organization has reached the maximum of {policy.max_webhooks} webhook endpoints",
                error_code="QUOTA_EXCEEDED",
                details={"current": existing_count, "limit": policy.max_webhooks},
            )

        cleaned_name = name.strip()
        if len(cleaned_name) < 2 or len(cleaned_name) > 160:
            raise ValidationError("Webhook name must be between 2 and 160 characters")
        if self.webhook_repo.exists(filters={"name": cleaned_name}, org_id=org_id):
            raise ConflictError(
                f"A webhook endpoint named '{cleaned_name}' already exists in this organization",
                details={"field": "name"},
            )

        cleaned_patterns = self._validate_event_patterns(event_patterns)
        signing_secret = secret.strip() if secret and secret.strip() else _generate_webhook_secret()
        if len(signing_secret) < 16:
            raise ValidationError("Webhook signing secret must be at least 16 characters long")

        encrypted_secret = self.vault.encrypt_json({"hmac_secret": signing_secret})
        try:
            endpoint = OrgWebhookEndpoint(
                id=new_uuid(),
                org_id=org_id,
                name=cleaned_name,
                url=url.strip(),
                secret_encrypted=encrypted_secret,
                event_patterns_json=cleaned_patterns,
                is_active=is_active,
                failure_count=0,
            )
        except ValueError as exc:
            raise ValidationError(str(exc), details={"field": "url"}) from exc

        self.db.add(endpoint)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.CREATE,
            resource_type="webhook_endpoint",
            resource_id=endpoint.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Created webhook endpoint '{endpoint.name}'",
            after_state=endpoint.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return CreatedWebhookResult(endpoint=endpoint, signing_secret=signing_secret)

    def list_webhook_endpoints(
        self,
        org_id: str,
        *,
        actor: User | None = None,
        active_only: bool = False,
    ) -> list[OrgWebhookEndpoint]:
        """List outbound webhook endpoints for *org_id*."""
        if actor is not None:
            self._require_permission(actor, Permission.ORG_READ, org_id=org_id, resource="webhooks")
        filters = {"is_active": True} if active_only else None
        return self.webhook_repo.list(filters=filters, org_id=org_id)

    def get_webhook_endpoint(
        self,
        org_id: str,
        endpoint_id: str,
        *,
        actor: User | None = None,
    ) -> OrgWebhookEndpoint:
        """Fetch a tenant-scoped webhook endpoint or raise :class:`NotFoundError`."""
        if actor is not None:
            self._require_permission(actor, Permission.ORG_READ, org_id=org_id, resource=endpoint_id)
        return self.webhook_repo.get_by_id_or_raise(endpoint_id, org_id=org_id)

    def update_webhook_endpoint(
        self,
        org_id: str,
        endpoint_id: str,
        *,
        actor: User,
        name: str | None = None,
        url: str | None = None,
        event_patterns: Sequence[str] | None = None,
        secret: str | None = None,
        is_active: bool | None = None,
        reset_failures: bool = False,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> OrgWebhookEndpoint:
        """Update webhook URL, event subscriptions, enabled state, or vaulted HMAC secret."""
        self._require_permission(actor, Permission.ORG_UPDATE, org_id=org_id, resource=endpoint_id)
        endpoint = self.webhook_repo.get_by_id_or_raise(endpoint_id, org_id=org_id)
        before_state = endpoint.to_public_dict()

        if name is not None:
            cleaned_name = name.strip()
            if len(cleaned_name) < 2 or len(cleaned_name) > 160:
                raise ValidationError("Webhook name must be between 2 and 160 characters")
            if cleaned_name != endpoint.name:
                if self.webhook_repo.exists(filters={"name": cleaned_name}, org_id=org_id):
                    raise ConflictError(
                        f"A webhook endpoint named '{cleaned_name}' already exists",
                        details={"field": "name"},
                    )
                endpoint.name = cleaned_name

        if url is not None:
            try:
                endpoint.url = url.strip()
            except ValueError as exc:
                raise ValidationError(str(exc), details={"field": "url"}) from exc

        if event_patterns is not None:
            endpoint.event_patterns_json = self._validate_event_patterns(event_patterns)

        if secret is not None:
            cleaned_secret = secret.strip()
            if len(cleaned_secret) < 16:
                raise ValidationError("Webhook signing secret must be at least 16 characters long")
            endpoint.secret_encrypted = self.vault.encrypt_json({"hmac_secret": cleaned_secret})

        if is_active is not None:
            endpoint.is_active = is_active

        if reset_failures:
            endpoint.failure_count = 0

        self.db.add(endpoint)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.UPDATE,
            resource_type="webhook_endpoint",
            resource_id=endpoint.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Updated webhook endpoint '{endpoint.name}'",
            before_state=before_state,
            after_state=endpoint.to_public_dict(),
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return endpoint

    def rotate_webhook_secret(
        self,
        org_id: str,
        endpoint_id: str,
        *,
        actor: User,
        new_secret: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> CreatedWebhookResult:
        """Rotate the vaulted HMAC-SHA256 signing secret for a webhook endpoint."""
        self._require_permission(actor, Permission.ORG_UPDATE, org_id=org_id, resource=endpoint_id)
        endpoint = self.webhook_repo.get_by_id_or_raise(endpoint_id, org_id=org_id)

        signing_secret = new_secret.strip() if new_secret and new_secret.strip() else _generate_webhook_secret()
        if len(signing_secret) < 16:
            raise ValidationError("Webhook signing secret must be at least 16 characters long")

        endpoint.secret_encrypted = self.vault.encrypt_json({"hmac_secret": signing_secret})
        self.db.add(endpoint)
        self.db.flush()

        self.audit.record(
            org_id=org_id,
            action=AuditAction.CREDENTIAL_ROTATE,
            resource_type="webhook_endpoint",
            resource_id=endpoint.id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Rotated HMAC signing secret for webhook endpoint '{endpoint.name}'",
            after_state={"endpoint_id": endpoint.id, "secret_rotated": True},
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return CreatedWebhookResult(endpoint=endpoint, signing_secret=signing_secret)

    def delete_webhook_endpoint(
        self,
        org_id: str,
        endpoint_id: str,
        *,
        actor: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> bool:
        """Delete a tenant-scoped outbound webhook endpoint."""
        self._require_permission(actor, Permission.ORG_UPDATE, org_id=org_id, resource=endpoint_id)
        endpoint = self.webhook_repo.get_by_id_or_raise(endpoint_id, org_id=org_id)
        before_state = endpoint.to_public_dict()
        deleted = self.webhook_repo.delete(endpoint, flush=True)

        self.audit.record(
            org_id=org_id,
            action=AuditAction.DELETE,
            resource_type="webhook_endpoint",
            resource_id=endpoint_id,
            actor_user_id=actor.id,
            actor_email=actor.email,
            summary=f"Deleted webhook endpoint '{before_state['name']}'",
            before_state=before_state,
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()
        return deleted

    def get_matching_webhooks(self, org_id: str, event_name: str) -> list[OrgWebhookEndpoint]:
        """Return all active webhook endpoints subscribed to *event_name*."""
        endpoints = self.webhook_repo.list_enabled(org_id=org_id)
        return [ep for ep in endpoints if ep.matches_event(event_name)]

    def decrypt_webhook_secret(self, endpoint: OrgWebhookEndpoint) -> str:
        """Decrypt an endpoint's vaulted HMAC secret (supports JSON or raw-string payloads)."""
        if not endpoint.secret_encrypted:
            raise ValidationError(
                f"Webhook endpoint '{endpoint.id}' has no signing secret configured",
                details={"endpoint_id": endpoint.id},
            )
        raw_text = self.vault.decrypt_str(endpoint.secret_encrypted)
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                secret_val = parsed.get("hmac_secret") or parsed.get("secret")
                if isinstance(secret_val, str) and secret_val:
                    return secret_val
        except json.JSONDecodeError:
            pass
        return raw_text

    def sign_payload_for_endpoint(
        self,
        endpoint_or_id: OrgWebhookEndpoint | str,
        payload: Mapping[str, Any] | str | bytes,
        *,
        org_id: str | None = None,
        timestamp: int | None = None,
    ) -> WebhookSignature:
        """Decrypt the endpoint's HMAC secret and return signed delivery headers."""
        endpoint = (
            self.webhook_repo.get_by_id_or_raise(endpoint_or_id, org_id=org_id)
            if isinstance(endpoint_or_id, str)
            else endpoint_or_id
        )
        secret = self.decrypt_webhook_secret(endpoint)
        return sign_webhook_payload(payload, secret, timestamp=timestamp)

    # ── Private Validation & Redaction Helpers ───────────────────────────────

    def _validate_api_key_scopes(self, actor: User, scopes: Sequence[str]) -> list[str]:
        cleaned = sorted({str(s).strip() for s in scopes if str(s).strip()})
        if not cleaned:
            raise ValidationError("At least one API key scope must be specified")
        if actor.role_enum != UserRole.SUPER_ADMIN:
            for scope in cleaned:
                if scope in {"*", "admin:*"} and actor.role_enum not in {UserRole.ORG_ADMIN, UserRole.ADMIN}:
                    raise AuthorizationError(
                        f"Role '{actor.role}' cannot mint wildcard administrative API keys",
                        details={"scope": scope},
                    )
        return cleaned

    @staticmethod
    def _validate_cidrs(cidrs: Sequence[str]) -> list[str]:
        if not cidrs:
            return []
        acl = CIDRAllowlist(allowlist=cidrs, default_allow=False)
        return list(acl.allow_networks)

    @staticmethod
    def _resolve_expiry(
        *,
        expires_at: datetime | None,
        expires_in_days: int | None,
    ) -> datetime | None:
        now = utcnow()
        if expires_at is not None:
            resolved = _as_utc(expires_at)
            if resolved is not None and resolved <= now:
                raise ValidationError("expires_at must be in the future")
            return resolved
        if expires_in_days is not None:
            if expires_in_days < 1 or expires_in_days > 3650:
                raise ValidationError("expires_in_days must be between 1 and 3650")
            return now + timedelta(days=expires_in_days)
        return None

    @staticmethod
    def _validate_event_patterns(event_patterns: Sequence[str]) -> list[str]:
        cleaned = [str(p).strip() for p in event_patterns if str(p).strip()]
        if not cleaned:
            raise ValidationError("At least one webhook event pattern must be specified")
        # Preserve order while deduplicating
        return list(dict.fromkeys(cleaned))

    @staticmethod
    def _redact_api_key(api_key: ApiKey) -> dict[str, Any]:
        """Serialize API key strictly omitting ``key_hash`` and plaintext secret."""
        data = api_key.to_public_dict()
        data["created_by_user_id"] = api_key.created_by_user_id
        data["masked_key"] = f"{api_key.key_prefix}_********"
        data["is_expired"] = api_key.is_expired()
        return data


__all__ = [
    "CreatedApiKeyResult",
    "CreatedWebhookResult",
    "DEFAULT_SIGNATURE_TOLERANCE_SECONDS",
    "PLAN_TIER_POLICIES",
    "PlanTierPolicy",
    "QuotaStatus",
    "RbacService",
    "WEBHOOK_SIGNATURE_256_HEADER",
    "WEBHOOK_SIGNATURE_HEADER",
    "WEBHOOK_TIMESTAMP_HEADER",
    "WebhookSignature",
    "canonicalize_webhook_payload",
    "sign_webhook_payload",
    "verify_webhook_signature",
]
