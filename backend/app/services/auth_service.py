"""Identity, authentication, JWT session lifecycle, and API-key verification service.

Implements :class:`AuthService` for the NetPulse Observability Platform:

- Self-service tenant onboarding (:meth:`AuthService.register_organization_and_admin`)
  creating an isolated :class:`Organization` and initial ``org_admin`` :class:`User`.
- Credential authentication (:meth:`AuthService.authenticate_user`) with brute-force
  lockout enforcement, constant-time PBKDF2-HMAC-SHA256 verification, transparent hash
  upgrading, stateful :class:`UserSession` creation, JWT minting, and audit emission.
- Refresh-token rotation (:meth:`AuthService.refresh_access_token`) with replay-attack
  detection that automatically revokes compromised session families.
- Session & JWT logout (:meth:`AuthService.logout`), password rotation
  (:meth:`AuthService.change_password`), and scoped machine-to-machine API key
  authentication (:meth:`AuthService.authenticate_api_key`) with prefix lookup,
  constant-time SHA-256 verification, expiration enforcement, and CIDR ACL evaluation.
- Canonical RBAC permission resolution (:meth:`AuthService.get_user_permissions`)
  bridging ORM :class:`app.models.enums.UserRole` values and :class:`app.core.security.Role`.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.security import (
    CIDRAllowlist,
    Permission,
    Role,
    TokenPair,
    TokenPayload,
    TokenRevocationStore,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_revocation_store,
    get_role_permissions,
    hash_password,
    needs_rehash,
    parse_api_key,
    validate_password_strength,
    verify_access_token,
    verify_api_key,
    verify_password,
    verify_refresh_token,
)
from app.db.base import new_uuid, utcnow
from app.db.repositories.identity import (
    ApiKeyRepository,
    OrganizationRepository,
    UserRepository,
    UserSessionRepository,
)
from app.models.enums import AuditAction, UserRole
from app.models.identity import ApiKey, Organization, User, UserSession
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants, dummy timing-attack mitigation hash, and role translation maps
# ---------------------------------------------------------------------------

_SLUG_SANITIZE_RE = re.compile(r"[^a-z0-9]+")
_USERNAME_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9._-]+")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Pre-computed PBKDF2 dummy hash used when authenticating unknown accounts to
#: minimize timing differences between existing and non-existing users.
_DUMMY_PASSWORD_HASH = hash_password(
    "NetPulse!TimingGuard#2026",
    iterations=10_000,
    salt=b"netpulse_timing!",
)

#: Default quotas provisioned per subscription tier during organization signup.
PLAN_DEFAULT_QUOTAS: dict[str, dict[str, int]] = {
    "free": {"max_devices": 25, "max_users": 5, "retention_days": 14},
    "starter": {"max_devices": 100, "max_users": 20, "retention_days": 30},
    "pro": {"max_devices": 500, "max_users": 50, "retention_days": 90},
    "enterprise": {"max_devices": 5000, "max_users": 250, "retention_days": 365},
}

#: Mapping from ORM/schema lowercase role names to security RBAC :class:`Role`.
_MODEL_TO_SECURITY_ROLE: dict[str, Role] = {
    UserRole.SUPER_ADMIN.value: Role.SUPER_ADMIN,
    UserRole.ORG_ADMIN.value: Role.ORG_ADMIN,
    UserRole.ADMIN.value: Role.ORG_ADMIN,
    UserRole.NETOPS.value: Role.NETOPS_ENGINEER,
    "netops_engineer": Role.NETOPS_ENGINEER,
    UserRole.OPERATOR.value: Role.SRE_OPERATOR,
    "sre_operator": Role.SRE_OPERATOR,
    UserRole.ANALYST.value: Role.SECURITY_AUDITOR,
    "auditor": Role.SECURITY_AUDITOR,
    "security_auditor": Role.SECURITY_AUDITOR,
    UserRole.VIEWER.value: Role.VIEWER,
    UserRole.SERVICE_ACCOUNT.value: Role.AGENT,
    "agent": Role.AGENT,
}

#: Mapping from schema/security aliases back to canonical ORM :class:`UserRole`.
_ROLE_ALIAS_TO_MODEL: dict[str, UserRole] = {
    "super_admin": UserRole.SUPER_ADMIN,
    "org_admin": UserRole.ORG_ADMIN,
    "admin": UserRole.ADMIN,
    "netops": UserRole.NETOPS,
    "netops_engineer": UserRole.NETOPS,
    "operator": UserRole.OPERATOR,
    "sre_operator": UserRole.OPERATOR,
    "analyst": UserRole.ANALYST,
    "auditor": UserRole.ANALYST,
    "security_auditor": UserRole.ANALYST,
    "viewer": UserRole.VIEWER,
    "service_account": UserRole.SERVICE_ACCOUNT,
    "agent": UserRole.SERVICE_ACCOUNT,
}


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------


def hash_refresh_token(refresh_token: str) -> str:
    """Return the hex-encoded SHA-256 digest stored in ``user_sessions.refresh_token_hash``."""
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def slugify_organization_name(name: str) -> str:
    """Generate a valid lowercase alphanumeric-hyphen slug from an organization name."""
    cleaned = _SLUG_SANITIZE_RE.sub("-", name.strip().lower()).strip("-")
    if len(cleaned) < 2:
        cleaned = f"org-{new_uuid()[:8]}"
    return cleaned[:120].strip("-")


def derive_username_from_email(email: str) -> str:
    """Derive a valid username handle from the local part of an email address."""
    local = email.strip().lower().split("@", 1)[0]
    cleaned = _USERNAME_SANITIZE_RE.sub("-", local).strip(".-_")
    if len(cleaned) < 3:
        cleaned = f"user-{new_uuid()[:6]}"
    return cleaned[:64]


def resolve_security_role(role: UserRole | Role | str) -> Role:
    """Translate any ORM, schema, or security role identifier into :class:`Role`."""
    if isinstance(role, Role):
        return role
    raw = role.value if isinstance(role, UserRole) else str(role)
    normalized = raw.strip().lower()
    if normalized in _MODEL_TO_SECURITY_ROLE:
        return _MODEL_TO_SECURITY_ROLE[normalized]
    try:
        return Role(raw.strip().upper())
    except ValueError as exc:
        raise AuthorizationError(
            f"Unsupported RBAC role: {role!r}",
            details={"role": raw},
        ) from exc


def normalize_model_role(role: UserRole | Role | str) -> UserRole:
    """Translate any ORM, schema, or security role identifier into ORM :class:`UserRole`."""
    if isinstance(role, UserRole):
        return role
    raw = role.value if isinstance(role, Role) else str(role)
    normalized = raw.strip().lower()
    if normalized in _ROLE_ALIAS_TO_MODEL:
        return _ROLE_ALIAS_TO_MODEL[normalized]
    raise ValidationError(
        f"Invalid user role: {role!r}",
        details={"role": raw, "allowed_roles": [r.value for r in UserRole]},
    )


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Structured service return types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Comprehensive authentication payload returned by registration and login flows."""

    user: User
    organization: Organization
    session: UserSession
    token_pair: TokenPair
    permissions: list[str] = field(default_factory=list)

    @property
    def access_token(self) -> str:
        return self.token_pair.access_token

    @property
    def refresh_token(self) -> str:
        return self.token_pair.refresh_token

    @property
    def token_type(self) -> str:
        return self.token_pair.token_type

    @property
    def expires_in(self) -> int:
        return self.token_pair.expires_in

    @property
    def refresh_expires_in(self) -> int:
        return self.token_pair.refresh_expires_in

    def to_token_response_dict(self) -> dict[str, Any]:
        """Serialize into a JSON structure compatible with ``TokenResponse``."""
        return {
            "access_token": self.token_pair.access_token,
            "refresh_token": self.token_pair.refresh_token,
            "token_type": self.token_pair.token_type.lower(),
            "expires_in": self.token_pair.expires_in,
            "refresh_expires_in": self.token_pair.refresh_expires_in,
            "scopes": list(self.permissions),
            "user": self.user.to_public_dict(),
            "organization": self.organization.to_summary_dict(),
            "session_id": self.session.id,
        }


@dataclass(frozen=True, slots=True)
class ApiKeyAuthContext:
    """Verified machine-to-machine API key authentication context."""

    api_key_id: str
    org_id: str
    org_slug: str
    name: str
    key_prefix: str
    scopes: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    created_by_user_id: str | None
    expires_at: datetime | None
    last_used_at: datetime | None
    client_ip: str | None
    api_key: ApiKey
    organization: Organization

    def has_scope(self, required_scope: str) -> bool:
        """Check whether this authenticated API key holds *required_scope*."""
        return self.api_key.has_scope(required_scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_key_id": self.api_key_id,
            "org_id": self.org_id,
            "org_slug": self.org_slug,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": list(self.scopes),
            "allowed_cidrs": list(self.allowed_cidrs),
            "created_by_user_id": self.created_by_user_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "client_ip": self.client_ip,
        }


# ---------------------------------------------------------------------------
# AuthService
# ---------------------------------------------------------------------------


class AuthService:
    """Business-logic service managing authentication, tokens, sessions, and API keys."""

    def __init__(
        self,
        db: Session,
        *,
        revocation_store: TokenRevocationStore | None = None,
        settings: Settings | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.revocation_store = revocation_store or get_revocation_store()
        self.org_repo = OrganizationRepository(db)
        self.user_repo = UserRepository(db)
        self.session_repo = UserSessionRepository(db)
        self.api_key_repo = ApiKeyRepository(db)
        self.audit = audit_service or AuditService(db)

    # ── Vercel / Serverless Lazy Seeding Support ─────────────────────────────

    def ensure_serverless_seed(self) -> bool:
        """Lazily initialize & seed the ephemeral database on Vercel cold starts.

        Safe to call inside request paths: performs a single lightweight count check
        and only runs the idempotent demo seeder when ``settings.is_vercel`` is True
        and no organizations exist yet.
        """
        if not self.settings.is_vercel:
            return False
        org_count = int(
            self.db.execute(select(func.count(Organization.id))).scalar_one()
        )
        if org_count > 0:
            return False
        from app.db.seed import seed_enterprise_demo

        result = seed_enterprise_demo(self.db, commit=True, force=False)
        return bool(result.get("seeded"))

    # ── Organization + Admin Registration ────────────────────────────────────

    def register_organization_and_admin(
        self,
        *,
        organization_name: str,
        email: str,
        password: str,
        username: str | None = None,
        full_name: str = "",
        organization_slug: str | None = None,
        plan_tier: str = "pro",
        timezone_name: str = "UTC",
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> AuthResult:
        """Provision a new tenant :class:`Organization` and its initial ``org_admin`` user.

        Enforces unique organization slug, unique login email, password complexity
        rules, creates an active refresh-token :class:`UserSession`, emits immutable
        audit records, and returns an :class:`AuthResult` with a fresh JWT token pair.
        """
        cleaned_org_name = organization_name.strip()
        if len(cleaned_org_name) < 2 or len(cleaned_org_name) > 160:
            raise ValidationError(
                "Organization name must be between 2 and 160 characters",
                details={"field": "organization_name"},
            )

        normalized_email = email.strip().lower()
        if not _EMAIL_RE.match(normalized_email):
            raise ValidationError(
                "Invalid email address format",
                details={"field": "email", "email": email},
            )

        resolved_slug = (
            organization_slug.strip().lower()
            if organization_slug and organization_slug.strip()
            else slugify_organization_name(cleaned_org_name)
        )
        if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,118}[a-z0-9])?$", resolved_slug):
            raise ValidationError(
                "Organization slug must contain lowercase alphanumerics and hyphens only",
                details={"field": "organization_slug", "slug": resolved_slug},
            )

        resolved_username = (
            username.strip() if username and username.strip() else derive_username_from_email(normalized_email)
        )
        if len(resolved_username) < 2 or len(resolved_username) > 100:
            raise ValidationError(
                "Username must be between 2 and 100 characters",
                details={"field": "username"},
            )

        # Uniqueness checks
        if self.org_repo.slug_exists(resolved_slug):
            raise ConflictError(
                f"Organization slug '{resolved_slug}' is already registered",
                details={"field": "organization_slug", "slug": resolved_slug},
            )

        existing_email = self.user_repo.get_by_email(normalized_email, include_deleted=True)
        if existing_email is not None:
            raise ConflictError(
                f"An account with email '{normalized_email}' already exists",
                details={"field": "email"},
            )

        # Enforce password complexity
        email_local = normalized_email.split("@", 1)[0]
        validate_password_strength(
            password,
            forbidden_substrings=(email_local, resolved_username, resolved_slug),
            raise_on_error=True,
        )

        # Resolve plan quotas
        normalized_plan = plan_tier.strip().lower() if plan_tier else "pro"
        if normalized_plan not in PLAN_DEFAULT_QUOTAS:
            raise ValidationError(
                f"Unsupported plan tier '{plan_tier}'",
                details={
                    "field": "plan_tier",
                    "supported": sorted(PLAN_DEFAULT_QUOTAS.keys()),
                },
            )
        quotas = PLAN_DEFAULT_QUOTAS[normalized_plan]

        org = Organization(
            id=new_uuid(),
            name=cleaned_org_name,
            slug=resolved_slug,
            plan_tier=normalized_plan,
            max_devices=quotas["max_devices"],
            max_users=quotas["max_users"],
            retention_days=quotas["retention_days"],
            settings_json={
                "timezone": timezone_name or "UTC",
                "default_polling_interval_s": 30,
                "enable_anomaly_detection": True,
            },
            is_active=True,
        )
        self.db.add(org)
        self.db.flush()

        password_hashed = hash_password(password)
        admin_user = User(
            id=new_uuid(),
            org_id=org.id,
            email=normalized_email,
            username=resolved_username,
            full_name=full_name.strip() or resolved_username,
            password_hash=password_hashed,
            role=UserRole.ORG_ADMIN.value,
            is_active=True,
            is_verified=True,
            mfa_enabled=False,
            failed_login_attempts=0,
            last_login_at=utcnow(),
            last_login_ip=ip_address,
            preferences_json={"timezone": timezone_name or "UTC"},
        )
        self.db.add(admin_user)
        self.db.flush()

        permissions = self.get_user_permissions(admin_user)
        token_pair, session_row = self._issue_tokens_and_session(
            user=admin_user,
            permissions=permissions,
            ip_address=ip_address,
            user_agent=user_agent,
            remember_me=False,
        )

        self.audit.record(
            org_id=org.id,
            action=AuditAction.CREATE,
            resource_type="organization",
            resource_id=org.id,
            actor_user_id=admin_user.id,
            actor_email=admin_user.email,
            summary=f"Registered organization '{org.name}' ({org.slug}) with admin '{admin_user.email}'",
            after_state={
                "organization": org.to_summary_dict(),
                "admin_user": admin_user.to_public_dict(),
            },
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        logger.info(
            "Registered organization slug=%s org_id=%s admin_user_id=%s",
            org.slug,
            org.id,
            admin_user.id,
        )
        return AuthResult(
            user=admin_user,
            organization=org,
            session=session_row,
            token_pair=token_pair,
            permissions=permissions,
        )

    # ── Credential Authentication ────────────────────────────────────────────

    def authenticate_user(
        self,
        email_or_username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        *,
        org_slug: str | None = None,
        org_id: str | None = None,
        remember_me: bool = False,
        commit: bool = True,
    ) -> AuthResult:
        """Authenticate a user by email or username and password.

        Checks account/organization status and brute-force lockout, verifies the
        PBKDF2 password hash, updates failure counters or login timestamps, creates
        a stateful :class:`UserSession`, mints JWT access + refresh tokens, and
        records an immutable :class:`AuditLog` event.
        """
        self.ensure_serverless_seed()

        identifier = (email_or_username or "").strip()
        if not identifier or not password:
            raise AuthenticationError(
                "Email/username and password are required",
                error_code="INVALID_CREDENTIALS",
            )

        scoped_org_id = org_id
        if scoped_org_id is None and org_slug:
            org_match = self.org_repo.get_by_slug(org_slug)
            if org_match is not None:
                scoped_org_id = org_match.id

        user = self._lookup_user(identifier, org_id=scoped_org_id)
        if user is None:
            # Perform constant-time dummy work to mitigate account enumeration timing.
            verify_password(password, _DUMMY_PASSWORD_HASH)
            raise AuthenticationError(
                "Invalid email/username or password",
                error_code="INVALID_CREDENTIALS",
            )

        org = self.org_repo.get_by_id(user.org_id, include_deleted=True)
        if org is None or org.is_deleted or not org.is_active:
            self.audit.record(
                org_id=user.org_id,
                action=AuditAction.LOGIN_FAILED,
                resource_type="user",
                resource_id=user.id,
                actor_user_id=user.id,
                actor_email=user.email,
                summary="Login rejected: organization is inactive or archived",
                after_state={"reason": "organization_inactive"},
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
                commit=commit,
            )
            raise AuthenticationError(
                "Organization account is inactive",
                error_code="ORGANIZATION_INACTIVE",
            )

        if user.is_deleted or not user.is_active:
            self.audit.record(
                org_id=user.org_id,
                action=AuditAction.LOGIN_FAILED,
                resource_type="user",
                resource_id=user.id,
                actor_user_id=user.id,
                actor_email=user.email,
                summary="Login rejected: user account is disabled",
                after_state={"reason": "account_disabled"},
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
                commit=commit,
            )
            raise AuthenticationError(
                "User account is disabled",
                error_code="ACCOUNT_DISABLED",
            )

        now = utcnow()
        if user.is_locked(now=now):
            locked_until_utc = _as_utc(user.locked_until)
            self.audit.record(
                org_id=user.org_id,
                action=AuditAction.LOGIN_FAILED,
                resource_type="user",
                resource_id=user.id,
                actor_user_id=user.id,
                actor_email=user.email,
                summary="Login rejected: account is temporarily locked",
                after_state={
                    "reason": "account_locked",
                    "locked_until": locked_until_utc.isoformat() if locked_until_utc else None,
                    "failed_login_attempts": user.failed_login_attempts,
                },
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
                commit=commit,
            )
            raise AuthenticationError(
                "Account is temporarily locked due to repeated failed login attempts",
                error_code="ACCOUNT_LOCKED",
                details={
                    "locked_until": locked_until_utc.isoformat() if locked_until_utc else None,
                },
            )

        sec_cfg = self.settings.security
        if not verify_password(password, user.password_hash):
            locked_now = user.record_failed_login(
                max_attempts=sec_cfg.max_login_attempts,
                lockout_minutes=sec_cfg.lockout_minutes,
                now=now,
            )
            self.db.add(user)
            self.db.flush()

            locked_until_utc = _as_utc(user.locked_until)
            self.audit.record(
                org_id=user.org_id,
                action=AuditAction.LOGIN_FAILED,
                resource_type="user",
                resource_id=user.id,
                actor_user_id=user.id,
                actor_email=user.email,
                summary=(
                    f"Login failed for '{user.email}' "
                    f"(attempt {user.failed_login_attempts}/{sec_cfg.max_login_attempts})"
                    + (" — account locked" if locked_now else "")
                ),
                after_state={
                    "reason": "invalid_password",
                    "failed_login_attempts": user.failed_login_attempts,
                    "locked": locked_now,
                    "locked_until": locked_until_utc.isoformat() if locked_until_utc else None,
                },
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
                commit=commit,
            )
            if locked_now:
                raise AuthenticationError(
                    "Too many failed login attempts; account is temporarily locked",
                    error_code="ACCOUNT_LOCKED",
                    details={
                        "locked_until": locked_until_utc.isoformat() if locked_until_utc else None,
                        "failed_login_attempts": user.failed_login_attempts,
                    },
                )
            raise AuthenticationError(
                "Invalid email/username or password",
                error_code="INVALID_CREDENTIALS",
            )

        # Transparently rehash legacy or under-iterated password hashes on successful login
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        user.record_successful_login(ip_address=ip_address, now=now)
        self.db.add(user)
        self.db.flush()

        permissions = self.get_user_permissions(user)
        token_pair, session_row = self._issue_tokens_and_session(
            user=user,
            permissions=permissions,
            ip_address=ip_address,
            user_agent=user_agent,
            remember_me=remember_me,
        )

        self.audit.record(
            org_id=user.org_id,
            action=AuditAction.LOGIN,
            resource_type="user_session",
            resource_id=session_row.id,
            actor_user_id=user.id,
            actor_email=user.email,
            summary=f"User '{user.email}' authenticated successfully",
            after_state={
                "session_id": session_row.id,
                "role": user.role,
                "remember_me": remember_me,
            },
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        logger.info("Authenticated user_id=%s org_id=%s session_id=%s", user.id, user.org_id, session_row.id)
        return AuthResult(
            user=user,
            organization=org,
            session=session_row,
            token_pair=token_pair,
            permissions=permissions,
        )

    # ── Token Refresh & Rotation ─────────────────────────────────────────────

    def refresh_access_token(
        self,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        *,
        commit: bool = True,
    ) -> TokenPair:
        """Validate a refresh token, rotate its session hash, revoke the old JTI, and return a fresh :class:`TokenPair`.

        Implements refresh-token reuse detection: if a cryptographically valid refresh
        JWT is replayed after its session was already rotated or revoked, all active
        sessions for the subject are immediately revoked as a security precaution.
        """
        payload = verify_refresh_token(
            refresh_token,
            revocation_store=self.revocation_store,
            settings=self.settings.security,
        )

        presented_hash = hash_refresh_token(refresh_token)
        session_row = self.session_repo.get_by_token_hash(presented_hash)

        if session_row is None:
            # Cryptographically valid refresh JWT whose hash is no longer active -> possible reuse
            self._handle_refresh_token_reuse(
                payload=payload,
                ip_address=ip_address,
                user_agent=user_agent,
                reason="session_not_found_or_already_rotated",
                commit=commit,
            )
            raise AuthenticationError(
                "Refresh token is no longer valid; please sign in again",
                error_code="TOKEN_REVOKED",
            )

        if session_row.user_id != payload.sub:
            self.revocation_store.revoke(payload.jti, payload.exp)
            raise AuthenticationError(
                "Refresh token subject mismatch",
                error_code="TOKEN_INVALID",
            )

        if session_row.is_revoked:
            self._handle_refresh_token_reuse(
                payload=payload,
                ip_address=ip_address,
                user_agent=user_agent,
                reason="revoked_session_replayed",
                commit=commit,
            )
            raise AuthenticationError(
                "Refresh token session has been revoked",
                error_code="TOKEN_REVOKED",
            )

        now = utcnow()
        if session_row.is_expired(now=now):
            session_row.revoke(now=now)
            self.revocation_store.revoke(payload.jti, payload.exp)
            self.db.add(session_row)
            self.db.flush()
            if commit:
                self.db.commit()
            raise AuthenticationError(
                "Refresh token session has expired",
                error_code="TOKEN_EXPIRED",
            )

        user = self.user_repo.get_by_id(session_row.user_id)
        if user is None or not user.can_authenticate(now=now):
            session_row.revoke(now=now)
            self.revocation_store.revoke(payload.jti, payload.exp)
            self.db.add(session_row)
            self.db.flush()
            if commit:
                self.db.commit()
            raise AuthenticationError(
                "User account is no longer permitted to authenticate",
                error_code="ACCOUNT_DISABLED",
            )

        org = self.org_repo.get_by_id(user.org_id)
        if org is None or not org.is_active:
            session_row.revoke(now=now)
            self.revocation_store.revoke(payload.jti, payload.exp)
            self.db.add(session_row)
            self.db.flush()
            if commit:
                self.db.commit()
            raise AuthenticationError(
                "Organization account is inactive",
                error_code="ORGANIZATION_INACTIVE",
            )

        # Revoke old refresh JTI and mint rotated token pair
        self.revocation_store.revoke(payload.jti, payload.exp)
        permissions = self.get_user_permissions(user)
        sec_cfg = self.settings.security
        refresh_delta = timedelta(days=sec_cfg.refresh_token_expire_days)

        new_access = create_access_token(
            user.id,
            org_id=user.org_id,
            role=user.role,
            scopes=permissions,
            extra_claims={"sid": session_row.id, "email": user.email},
            settings=sec_cfg,
        )
        new_refresh = create_refresh_token(
            user.id,
            org_id=user.org_id,
            role=user.role,
            expires_delta=refresh_delta,
            extra_claims={"sid": session_row.id},
            settings=sec_cfg,
        )

        session_row.refresh_token_hash = hash_refresh_token(new_refresh)
        session_row.expires_at = now + refresh_delta
        if ip_address is not None:
            session_row.ip_address = ip_address
        if user_agent is not None:
            session_row.user_agent = user_agent[:512]
        self.db.add(session_row)
        self.db.flush()

        self.audit.record(
            org_id=user.org_id,
            action=AuditAction.TOKEN_REFRESH,
            resource_type="user_session",
            resource_id=session_row.id,
            actor_user_id=user.id,
            actor_email=user.email,
            summary=f"Rotated refresh token for session '{session_row.id}'",
            after_state={"session_id": session_row.id},
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return TokenPair(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=sec_cfg.access_token_expire_minutes * 60,
            refresh_expires_in=int(refresh_delta.total_seconds()),
        )

    # ── Logout & Session Revocation ──────────────────────────────────────────

    def logout(
        self,
        refresh_token: str | None = None,
        access_token: str | None = None,
        user_id: str | None = None,
        *,
        revoke_all_sessions: bool = False,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> dict[str, Any]:
        """Revoke presented access/refresh JWTs and deactivate corresponding DB session(s)."""
        revoked_jtis: list[str] = []
        revoked_sessions = 0
        resolved_user_id = user_id
        resolved_org_id: str | None = None
        resolved_email: str | None = None

        # 1. Revoke access token JTI (tolerate expired tokens)
        if access_token:
            access_payload = self._safe_decode_for_revocation(access_token)
            if access_payload is not None:
                self.revocation_store.revoke(access_payload.jti, access_payload.exp)
                revoked_jtis.append(access_payload.jti)
                resolved_user_id = resolved_user_id or access_payload.sub
                resolved_org_id = resolved_org_id or access_payload.org_id

        # 2. Revoke refresh token JTI + matching DB UserSession
        if refresh_token:
            refresh_payload = self._safe_decode_for_revocation(refresh_token)
            if refresh_payload is not None:
                self.revocation_store.revoke(refresh_payload.jti, refresh_payload.exp)
                revoked_jtis.append(refresh_payload.jti)
                resolved_user_id = resolved_user_id or refresh_payload.sub
                resolved_org_id = resolved_org_id or refresh_payload.org_id

            session_row = self.session_repo.get_by_token_hash(hash_refresh_token(refresh_token))
            if session_row is not None and not session_row.is_revoked:
                session_row.revoke()
                self.db.add(session_row)
                self.db.flush()
                revoked_sessions += 1
                resolved_user_id = resolved_user_id or session_row.user_id

        # 3. Optionally revoke every active session for the user
        if revoke_all_sessions and resolved_user_id:
            revoked_sessions += self.session_repo.revoke_all_for_user(
                resolved_user_id,
                flush=True,
            )
            self.revocation_store.revoke_subject(resolved_user_id)

        # 4. Emit audit log if user/org can be resolved
        if resolved_user_id:
            user = self.user_repo.get_by_id(resolved_user_id, include_deleted=True)
            if user is not None:
                resolved_org_id = resolved_org_id or user.org_id
                resolved_email = user.email

        if resolved_org_id:
            self.audit.record(
                org_id=resolved_org_id,
                action=AuditAction.LOGOUT,
                resource_type="user_session",
                resource_id=resolved_user_id,
                actor_user_id=resolved_user_id,
                actor_email=resolved_email,
                summary=(
                    "Logged out and revoked all active sessions"
                    if revoke_all_sessions
                    else "Logged out and revoked current session"
                ),
                after_state={
                    "revoked_sessions": revoked_sessions,
                    "revoked_token_count": len(revoked_jtis),
                    "revoke_all_sessions": revoke_all_sessions,
                },
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
            )

        if commit:
            self.db.commit()

        return {
            "user_id": resolved_user_id,
            "revoked_sessions": revoked_sessions,
            "revoked_tokens": revoked_jtis,
            "revoke_all_sessions": revoke_all_sessions,
        }

    # ── Password Change ──────────────────────────────────────────────────────

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        *,
        current_session_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> dict[str, Any]:
        """Verify current password, enforce complexity, update hash, and revoke other sessions."""
        user = self.user_repo.get_by_id(user_id)
        if user is None:
            raise NotFoundError(
                f"User '{user_id}' was not found",
                details={"entity": "User", "id": user_id},
            )

        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError(
                "Current password is incorrect",
                error_code="INVALID_PASSWORD",
            )

        if current_password == new_password:
            raise ValidationError(
                "New password must differ from the current password",
                details={"field": "new_password"},
            )

        email_local = user.email.split("@", 1)[0]
        validate_password_strength(
            new_password,
            forbidden_substrings=(email_local, user.username),
            raise_on_error=True,
        )

        user.password_hash = hash_password(new_password)
        user.unlock()
        self.db.add(user)
        self.db.flush()

        revoked_count = self.session_repo.revoke_all_for_user(
            user.id,
            exclude_session_id=current_session_id,
            flush=True,
        )
        if current_session_id is None:
            self.revocation_store.revoke_subject(user.id)

        self.audit.record(
            org_id=user.org_id,
            action=AuditAction.PASSWORD_CHANGE,
            resource_type="user",
            resource_id=user.id,
            actor_user_id=user.id,
            actor_email=user.email,
            summary=f"User '{user.email}' rotated account password ({revoked_count} other sessions revoked)",
            after_state={
                "password_changed": True,
                "revoked_other_sessions": revoked_count,
                "preserved_session_id": current_session_id,
            },
            ip_address=ip_address,
            user_agent=user_agent,
            flush=True,
        )

        if commit:
            self.db.commit()

        return {
            "user_id": user.id,
            "password_updated": True,
            "revoked_sessions": revoked_count,
        }

    # ── API Key Authentication ───────────────────────────────────────────────

    def authenticate_api_key(
        self,
        raw_key: str,
        client_ip: str | None = None,
        *,
        required_scope: str | None = None,
        commit: bool = True,
    ) -> ApiKeyAuthContext:
        """Authenticate a machine-to-machine API key with prefix lookup and CIDR enforcement.

        Steps:
        1. Parse ``npm_<prefix>_<secret>`` structure.
        2. Look up :class:`ApiKey` record by indexed ``key_prefix``.
        3. Verify SHA-256 digest in constant time via :func:`verify_api_key`.
        4. Enforce ``is_active``, ``expires_at``, and active parent :class:`Organization`.
        5. Evaluate ``allowed_cidrs_json`` against *client_ip* when configured.
        6. Optionally verify *required_scope* against ``scopes_json``.
        7. Stamp ``last_used_at`` and return :class:`ApiKeyAuthContext`.
        """
        self.ensure_serverless_seed()

        _, full_prefix, _ = parse_api_key(
            raw_key,
            expected_namespace=self.settings.security.api_key_prefix,
        )

        api_key = self.api_key_repo.get_by_prefix(full_prefix)
        if api_key is None or not verify_api_key(raw_key, api_key.key_hash):
            raise AuthenticationError(
                "Invalid API key",
                error_code="INVALID_API_KEY",
            )

        if not api_key.is_active:
            raise AuthenticationError(
                "API key has been revoked",
                error_code="API_KEY_REVOKED",
            )

        now = utcnow()
        if api_key.is_expired(now=now):
            raise AuthenticationError(
                "API key has expired",
                error_code="API_KEY_EXPIRED",
                details={
                    "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                },
            )

        org = self.org_repo.get_by_id(api_key.org_id, include_deleted=True)
        if org is None or org.is_deleted or not org.is_active:
            raise AuthenticationError(
                "Organization for this API key is inactive",
                error_code="ORGANIZATION_INACTIVE",
            )

        allowed_cidrs = list(api_key.allowed_cidrs_json or [])
        if allowed_cidrs:
            if not client_ip:
                raise AuthorizationError(
                    "Client IP address is required for CIDR-restricted API keys",
                    details={"api_key_id": api_key.id},
                )
            acl = CIDRAllowlist(allowlist=allowed_cidrs, default_allow=False)
            if not acl.is_allowed(client_ip):
                raise AuthorizationError(
                    f"Client IP '{client_ip}' is not permitted by this API key's CIDR allowlist",
                    details={"api_key_id": api_key.id, "client_ip": client_ip},
                )

        if required_scope and not api_key.has_scope(required_scope):
            raise AuthorizationError(
                f"API key lacks required scope '{required_scope}'",
                details={
                    "api_key_id": api_key.id,
                    "required_scope": required_scope,
                    "granted_scopes": list(api_key.scopes_json or []),
                },
            )

        api_key.mark_used(now=now)
        self.db.add(api_key)
        self.db.flush()
        if commit:
            self.db.commit()

        return ApiKeyAuthContext(
            api_key_id=api_key.id,
            org_id=org.id,
            org_slug=org.slug,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            scopes=tuple(str(s) for s in (api_key.scopes_json or [])),
            allowed_cidrs=tuple(allowed_cidrs),
            created_by_user_id=api_key.created_by_user_id,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
            client_ip=client_ip,
            api_key=api_key,
            organization=org,
        )

    # ── Permissions & Token Introspection ────────────────────────────────────

    def get_user_permissions(self, user: User | UserRole | Role | str) -> list[str]:
        """Resolve the sorted canonical list of RBAC permission strings for *user*.

        Accepts a :class:`User` ORM entity, a :class:`UserRole`/:class:`Role` enum,
        or a role string. If a :class:`User` carries validated custom grants under
        ``preferences_json["extra_permissions"]``, they are unioned into the result.
        """
        if isinstance(user, User):
            sec_role = resolve_security_role(user.role)
            granted: set[str] = {perm.value for perm in get_role_permissions(sec_role)}
            extra_raw = user.get_preference("extra_permissions", [])
            if isinstance(extra_raw, Sequence) and not isinstance(extra_raw, (str, bytes)):
                valid_codes = {p.value for p in Permission}
                for item in extra_raw:
                    code = str(item)
                    if code in valid_codes:
                        granted.add(code)
            return sorted(granted)

        sec_role = resolve_security_role(user)
        return sorted(perm.value for perm in get_role_permissions(sec_role))

    def verify_access_token_and_load_user(self, access_token: str) -> tuple[TokenPayload, User]:
        """Verify a bearer JWT access token and load its active :class:`User`."""
        payload = verify_access_token(
            access_token,
            revocation_store=self.revocation_store,
            settings=self.settings.security,
        )
        user = self.user_repo.get_by_id(payload.sub)
        if user is None or not user.can_authenticate():
            raise AuthenticationError(
                "Authenticated user is inactive or locked",
                error_code="ACCOUNT_DISABLED",
            )
        if payload.org_id and user.org_id != payload.org_id:
            raise AuthenticationError(
                "Token tenant scope does not match user organization",
                error_code="TOKEN_INVALID",
            )
        return payload, user

    def list_active_sessions(self, user_id: str) -> list[UserSession]:
        """Return all non-revoked, non-expired sessions for *user_id*."""
        return self.session_repo.list_active_for_user(user_id)

    def revoke_user_session(
        self,
        *,
        user_id: str,
        session_id: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        commit: bool = True,
    ) -> UserSession:
        """Revoke a specific :class:`UserSession` owned by *user_id*."""
        session_row = self.session_repo.get_by_id(session_id)
        if session_row is None or session_row.user_id != user_id:
            raise NotFoundError(
                f"Session '{session_id}' was not found for user",
                details={"entity": "UserSession", "id": session_id},
            )
        session_row.revoke()
        self.db.add(session_row)
        self.db.flush()

        user = self.user_repo.get_by_id(user_id, include_deleted=True)
        if user is not None:
            self.audit.record(
                org_id=user.org_id,
                action=AuditAction.SESSION_REVOKE,
                resource_type="user_session",
                resource_id=session_row.id,
                actor_user_id=user.id,
                actor_email=user.email,
                summary=f"Revoked session '{session_row.id}'",
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
            )
        if commit:
            self.db.commit()
        return session_row

    # ── Private Helpers ──────────────────────────────────────────────────────

    def _lookup_user(self, identifier: str, *, org_id: str | None = None) -> User | None:
        """Resolve a user by email (preferred when '@' present) or username."""
        if "@" in identifier:
            user = self.user_repo.get_by_email(identifier, org_id=org_id, include_deleted=True)
            if user is not None:
                return user
        user = self.user_repo.get_by_username(identifier, org_id=org_id)
        if user is not None:
            return user
        if "@" not in identifier:
            return self.user_repo.get_by_email(identifier, org_id=org_id, include_deleted=True)
        return None

    def _issue_tokens_and_session(
        self,
        *,
        user: User,
        permissions: Sequence[str],
        ip_address: str | None,
        user_agent: str | None,
        remember_me: bool,
    ) -> tuple[TokenPair, UserSession]:
        sec_cfg = self.settings.security
        refresh_days = max(sec_cfg.refresh_token_expire_days, 30) if remember_me else sec_cfg.refresh_token_expire_days
        refresh_delta = timedelta(days=refresh_days)
        session_id = new_uuid()

        access_token = create_access_token(
            user.id,
            org_id=user.org_id,
            role=user.role,
            scopes=permissions,
            extra_claims={"sid": session_id, "email": user.email},
            settings=sec_cfg,
        )
        refresh_token = create_refresh_token(
            user.id,
            org_id=user.org_id,
            role=user.role,
            expires_delta=refresh_delta,
            extra_claims={"sid": session_id},
            settings=sec_cfg,
        )

        now = utcnow()
        session_row = UserSession(
            id=session_id,
            user_id=user.id,
            refresh_token_hash=hash_refresh_token(refresh_token),
            ip_address=ip_address,
            user_agent=user_agent[:512] if user_agent else None,
            expires_at=now + refresh_delta,
        )
        self.db.add(session_row)
        self.db.flush()

        token_pair = TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=sec_cfg.access_token_expire_minutes * 60,
            refresh_expires_in=int(refresh_delta.total_seconds()),
        )
        return token_pair, session_row

    def _safe_decode_for_revocation(self, token: str) -> TokenPayload | None:
        """Decode token without revocation checks, returning ``None`` on malformed/expired tokens."""
        try:
            return decode_token(
                token,
                check_revocation=False,
                settings=self.settings.security,
            )
        except AuthenticationError:
            return None

    def _handle_refresh_token_reuse(
        self,
        *,
        payload: TokenPayload,
        ip_address: str | None,
        user_agent: str | None,
        reason: str,
        commit: bool,
    ) -> None:
        """Revoke all sessions for a subject when refresh-token replay is detected."""
        self.revocation_store.revoke(payload.jti, payload.exp)
        self.revocation_store.revoke_subject(payload.sub)
        revoked_count = self.session_repo.revoke_all_for_user(payload.sub, flush=True)

        user = self.user_repo.get_by_id(payload.sub, include_deleted=True)
        org_id = user.org_id if user is not None else payload.org_id
        if org_id:
            self.audit.record(
                org_id=org_id,
                action=AuditAction.SESSION_REVOKE,
                resource_type="user",
                resource_id=payload.sub,
                actor_user_id=payload.sub,
                actor_email=user.email if user is not None else None,
                summary=(
                    f"Refresh token replay detected ({reason}); revoked {revoked_count} active sessions"
                ),
                after_state={"reason": reason, "revoked_sessions": revoked_count},
                ip_address=ip_address,
                user_agent=user_agent,
                flush=True,
                commit=commit,
            )
        elif commit:
            self.db.commit()

        logger.warning(
            "Refresh token replay detected for subject=%s reason=%s revoked_sessions=%d",
            payload.sub,
            reason,
            revoked_count,
        )


__all__ = [
    "ApiKeyAuthContext",
    "AuthResult",
    "AuthService",
    "PLAN_DEFAULT_QUOTAS",
    "derive_username_from_email",
    "hash_refresh_token",
    "normalize_model_role",
    "resolve_security_role",
    "slugify_organization_name",
]
