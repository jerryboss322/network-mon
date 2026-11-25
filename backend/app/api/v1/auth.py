"""Authentication, session lifecycle, password rotation, RBAC introspection, and demo tokens."""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    ensure_database_ready,
    get_client_ip,
    get_current_auth,
    get_db_session,
    normalize_schema_role,
    normalize_security_role,
    rate_limit_dependency,
    require_auth,
    resolve_permissions_for_role,
)
from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger, get_request_id
from app.core.security import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    create_token_pair,
    get_revocation_store,
    hash_password,
    needs_rehash,
    revoke_token,
    validate_password_strength,
    verify_password,
    verify_refresh_token,
)
from app.db.repositories.identity import (
    AuditLogRepository,
    OrganizationRepository,
    UserRepository,
    UserSessionRepository,
)
from app.db.seed import DEFAULT_ADMIN_EMAIL, DEFAULT_ORG_SLUG
from app.models.enums import AuditAction, UserRole as OrmUserRole
from app.models.identity import Organization, User
from app.schemas.common import BaseSchema, utcnow
from app.schemas.identity import (
    LoginRequest,
    LogoutRequest,
    OrganizationSummary,
    OrgPlan,
    OrgStatus,
    PasswordChangeRequest,
    PermissionDescriptor,
    RbacPermissionsResponse,
    RefreshRequest,
    RolePermissionMatrix,
    TokenResponse,
    UserRead,
    UserRegister,
    UserRole as SchemaUserRole,
)

logger = get_logger("netpulse.api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])

_SLUG_CLEAN_RE = re.compile(r"[^a-z0-9]+")

_DEMO_PROFILE_EMAILS: dict[str, str] = {
    "admin": DEFAULT_ADMIN_EMAIL,
    "super_admin": DEFAULT_ADMIN_EMAIL,
    "netops": "netops@netpulse.io",
    "operator": "sre@netpulse.io",
    "sre": "sre@netpulse.io",
    "viewer": "viewer@netpulse.io",
}

_ROLE_METADATA: dict[Role, tuple[str, str]] = {
    Role.SUPER_ADMIN: (
        "Super Administrator",
        "Unrestricted platform-wide access across all tenants, security controls, and vault keys.",
    ),
    Role.ORG_ADMIN: (
        "Organization Administrator",
        "Full administrative control within the organization including users, API keys, and policies.",
    ),
    Role.NETOPS_ENGINEER: (
        "NetOps Engineer",
        "Manage devices, topology, credentials, compliance policies, alerts, and playbooks.",
    ),
    Role.SRE_OPERATOR: (
        "SRE / NOC Operator",
        "Respond to alerts and incidents, trigger polls, manage synthetics, and run approved playbooks.",
    ),
    Role.SECURITY_AUDITOR: (
        "Security Auditor",
        "Read-only fleet visibility plus compliance audits, data exports, and audit log inspection.",
    ),
    Role.VIEWER: (
        "Read-Only Viewer",
        "Read-only access to dashboards, devices, telemetry, topology, alerts, and reports.",
    ),
    Role.AGENT: (
        "Collector / Edge Agent",
        "Machine identity for telemetry ingestion, discovery reporting, and config snapshot upload.",
    ),
}

_DESTRUCTIVE_VERBS: frozenset[str] = frozenset(
    {"delete", "execute", "execute_commands", "remediate", "vault_rotate", "manage_credentials"}
)


# ---------------------------------------------------------------------------
# Auxiliary Response / Request Schemas
# ---------------------------------------------------------------------------


class AuthMeResponse(BaseSchema):
    """Current authenticated principal profile, organization context, and permissions."""

    authenticated: bool
    auth_method: str
    api_key_id: str | None = None
    user: UserRead | None = None
    organization: OrganizationSummary | None = None
    role: SchemaUserRole
    is_admin: bool = False
    permissions: list[str] = []


class ActionStatusResponse(BaseSchema):
    """Simple confirmation payload for logout and password rotation actions."""

    status: str = "ok"
    message: str
    revoked_sessions: int = 0


class DemoTokenRequest(BaseSchema):
    """Optional profile selector for minting a demo JWT token."""

    profile: str = "admin"


# ---------------------------------------------------------------------------
# Serialization & Helper Functions
# ---------------------------------------------------------------------------


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _slugify(value: str) -> str:
    cleaned = _SLUG_CLEAN_RE.sub("-", value.strip().lower()).strip("-")
    return (cleaned or "netpulse-org")[:100]


def user_to_read(user: User) -> UserRead:
    """Convert an ORM :class:`User` into a safe :class:`UserRead` schema."""
    prefs = dict(user.preferences_json or {})
    return UserRead(
        id=user.id,
        org_id=user.org_id,
        created_at=user.created_at or utcnow(),
        updated_at=user.updated_at or utcnow(),
        email=user.email,
        username=user.username,
        full_name=user.full_name or "",
        role=normalize_schema_role(user.role),
        is_active=bool(user.is_active),
        is_verified=bool(user.is_verified),
        mfa_enabled=bool(user.mfa_enabled),
        phone_number=prefs.get("phone_number"),
        timezone_name=str(prefs.get("timezone_name") or prefs.get("timezone") or "UTC"),
        last_login_at=user.last_login_at,
        failed_login_attempts=int(user.failed_login_attempts or 0),
        locked_until=user.locked_until,
        preferences=prefs,
    )


def org_to_summary(org: Organization) -> OrganizationSummary:
    """Convert an ORM :class:`Organization` into :class:`OrganizationSummary`."""
    try:
        plan = OrgPlan(str(org.plan_tier).lower())
    except ValueError:
        plan = OrgPlan.ENTERPRISE
    org_status = OrgStatus.ACTIVE if org.is_active else OrgStatus.SUSPENDED
    return OrganizationSummary(
        id=org.id,
        name=org.name,
        slug=org.slug,
        plan=plan,
        status=org_status,
    )


def _issue_session_tokens(
    db: Session,
    user: User,
    *,
    client_ip: str | None,
    user_agent: str | None,
    remember_me: bool = False,
    settings: Settings | None = None,
) -> TokenResponse:
    """Mint JWT access & refresh tokens and persist a stateful :class:`UserSession`."""
    cfg = settings or get_settings()
    perms = sorted(p.value for p in resolve_permissions_for_role(user.role))
    pair = create_token_pair(
        user.id,
        org_id=user.org_id,
        role=user.role,
        scopes=perms,
        settings=cfg.security,
    )
    refresh_days = cfg.security.refresh_token_expire_days * (2 if remember_me else 1)
    expires_at = utcnow() + timedelta(days=refresh_days)

    UserSessionRepository(db).create(
        {
            "user_id": user.id,
            "refresh_token_hash": _hash_token(pair.refresh_token),
            "ip_address": client_ip,
            "user_agent": (user_agent or "")[:512] or None,
            "expires_at": expires_at,
        },
        flush=True,
    )

    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type="bearer",
        expires_in=pair.expires_in,
        refresh_expires_in=refresh_days * 86400,
        scopes=perms,
        user=user_to_read(user),
    )


def _record_auth_audit(
    db: Session,
    *,
    action: AuditAction,
    org_id: str,
    user_id: str | None,
    email: str | None,
    summary: str,
    client_ip: str | None,
    user_agent: str | None,
    resource_id: str | None = None,
    after_state: dict[str, Any] | None = None,
) -> None:
    AuditLogRepository(db).record(
        action=action.value,
        resource_type="auth",
        resource_id=resource_id or user_id,
        org_id=org_id,
        actor_user_id=user_id,
        actor_email=email,
        summary=summary,
        ip_address=client_ip,
        user_agent=user_agent,
        request_id=get_request_id(),
        after_state=after_state,
    )


def _demo_token_allowed(settings: Settings) -> bool:
    disabled = os.getenv("NETMON_DISABLE_DEMO_TOKEN", "").strip().lower()
    if disabled in {"1", "true", "yes", "on"}:
        return False
    enabled = os.getenv("NETMON_ENABLE_DEMO_TOKEN", "").strip().lower()
    if enabled in {"1", "true", "yes", "on"}:
        return True
    return bool(
        settings.is_vercel
        or settings.collectors.simulate_demo_telemetry
        or settings.environment in {"development", "test"}
    )


def _describe_permission(perm: Permission) -> PermissionDescriptor:
    domain, _, action = perm.value.partition(":")
    readable_action = action.replace("_", " ")
    readable_domain = domain.replace("_", " ")
    return PermissionDescriptor(
        code=perm.value,
        domain=domain,
        description=f"Allows {readable_action} operations on {readable_domain} resources.",
        is_destructive=action in _DESTRUCTIVE_VERBS,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency(15, scope="auth:register"))],
    summary="Register a new user account (and optional organization)",
)
def register(
    payload: UserRegister,
    request: Request,
    db: Session = Depends(get_db_session),
) -> TokenResponse:
    """Create a new user account, optionally provisioning a dedicated organization."""
    settings = get_settings()
    org_repo = OrganizationRepository(db)
    user_repo = UserRepository(db)

    # Validate password strength against security policy (including personal identifiers)
    validate_password_strength(
        payload.password,
        forbidden_substrings=(payload.username, payload.email.split("@")[0]),
        raise_on_error=True,
    )

    creating_new_org = bool(payload.organization_name or payload.organization_slug)
    if creating_new_org:
        org_name = (payload.organization_name or payload.organization_slug or "My Organization").strip()
        slug = payload.organization_slug or _slugify(org_name)
        if org_repo.slug_exists(slug):
            raise ConflictError(
                f"Organization slug '{slug}' is already in use",
                error_code="ORG_SLUG_TAKEN",
                details={"slug": slug},
            )
        org = org_repo.create(
            {
                "name": org_name,
                "slug": slug,
                "plan_tier": OrgPlan.PRO.value,
                "max_devices": 500,
                "max_users": 50,
                "retention_days": 90,
                "is_active": True,
                "settings_json": {"timezone": payload.timezone_name},
            },
            flush=True,
        )
        assigned_role = OrmUserRole.ORG_ADMIN.value
    else:
        org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
        if org is None:
            active_orgs = org_repo.list_active(limit=1)
            org = active_orgs[0] if active_orgs else None
        if org is None:
            org = org_repo.create(
                {
                    "name": f"{payload.full_name}'s Organization",
                    "slug": _slugify(f"{payload.username}-org"),
                    "plan_tier": OrgPlan.PRO.value,
                    "is_active": True,
                    "settings_json": {"timezone": payload.timezone_name},
                },
                flush=True,
            )
            assigned_role = OrmUserRole.ORG_ADMIN.value
        else:
            current_users = user_repo.count(org_id=org.id)
            if not org.can_add_user(current_users):
                raise ConflictError(
                    "Organization has reached its maximum user quota",
                    error_code="USER_QUOTA_EXCEEDED",
                    details={"max_users": org.max_users},
                )
            assigned_role = OrmUserRole.VIEWER.value

    if user_repo.get_by_email(payload.email, org_id=org.id) is not None:
        raise ConflictError(
            "An account with this email address already exists",
            error_code="EMAIL_ALREADY_REGISTERED",
        )
    if user_repo.get_by_username(payload.username, org_id=org.id) is not None:
        raise ConflictError(
            "This username is already taken within the organization",
            error_code="USERNAME_ALREADY_TAKEN",
        )

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent")
    now = utcnow()

    user = user_repo.create(
        {
            "org_id": org.id,
            "email": payload.email,
            "username": payload.username,
            "full_name": payload.full_name.strip(),
            "password_hash": hash_password(payload.password),
            "role": assigned_role,
            "is_active": True,
            "is_verified": True,
            "last_login_at": now,
            "last_login_ip": client_ip,
            "preferences_json": {"timezone_name": payload.timezone_name},
        },
        flush=True,
    )

    token_response = _issue_session_tokens(
        db,
        user,
        client_ip=client_ip,
        user_agent=user_agent,
        settings=settings,
    )
    _record_auth_audit(
        db,
        action=AuditAction.CREATE,
        org_id=org.id,
        user_id=user.id,
        email=user.email,
        summary=f"User '{user.email}' registered with role '{user.role}'",
        client_ip=client_ip,
        user_agent=user_agent,
        after_state={"role": user.role, "org_slug": org.slug, "created_org": creating_new_org},
    )
    db.commit()
    return token_response


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_dependency(30, scope="auth:login"))],
    summary="Authenticate with email/username and password to receive JWT tokens",
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db_session),
) -> TokenResponse:
    """Validate credentials, enforce brute-force lockout, and issue a JWT token pair."""
    settings = get_settings()
    user_repo = UserRepository(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    identifier = payload.identifier.strip()
    user: User | None = (
        user_repo.get_by_email(identifier)
        if "@" in identifier
        else (user_repo.get_by_username(identifier) or user_repo.get_by_email(identifier))
    )

    if user is None:
        raise AuthenticationError(
            "Invalid email/username or password",
            error_code="INVALID_CREDENTIALS",
        )

    if not user.is_active or bool(user.is_deleted):
        raise AuthenticationError(
            "User account is disabled. Contact an administrator.",
            error_code="ACCOUNT_DISABLED",
        )

    if user.is_locked():
        raise AuthenticationError(
            "Account is temporarily locked due to repeated failed login attempts",
            error_code="ACCOUNT_LOCKED",
            details={
                "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            },
        )

    if not verify_password(payload.password, user.password_hash):
        locked = user.record_failed_login(
            max_attempts=settings.security.max_login_attempts,
            lockout_minutes=settings.security.lockout_minutes,
        )
        db.flush()
        _record_auth_audit(
            db,
            action=AuditAction.LOGIN_FAILED,
            org_id=user.org_id,
            user_id=user.id,
            email=user.email,
            summary=f"Failed login attempt for '{user.email}' (attempts={user.failed_login_attempts})",
            client_ip=client_ip,
            user_agent=user_agent,
            after_state={"failed_login_attempts": user.failed_login_attempts, "locked": locked},
        )
        db.commit()
        if locked:
            raise AuthenticationError(
                "Account temporarily locked due to too many failed login attempts",
                error_code="ACCOUNT_LOCKED",
                details={
                    "locked_until": user.locked_until.isoformat() if user.locked_until else None,
                },
            )
        raise AuthenticationError(
            "Invalid email/username or password",
            error_code="INVALID_CREDENTIALS",
        )

    # Transparently upgrade legacy PBKDF2 iteration counts upon valid login
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    user.record_successful_login(ip_address=client_ip)
    db.flush()

    token_response = _issue_session_tokens(
        db,
        user,
        client_ip=client_ip,
        user_agent=user_agent,
        remember_me=payload.remember_me,
        settings=settings,
    )
    _record_auth_audit(
        db,
        action=AuditAction.LOGIN,
        org_id=user.org_id,
        user_id=user.id,
        email=user.email,
        summary=f"User '{user.email}' logged in",
        client_ip=client_ip,
        user_agent=user_agent,
        after_state={"remember_me": payload.remember_me},
    )
    db.commit()
    return token_response


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_dependency(45, scope="auth:refresh"))],
    summary="Rotate a valid refresh token for a new access and refresh token pair",
)
def refresh_tokens(
    payload: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db_session),
) -> TokenResponse:
    """Verify and rotate an active refresh token session."""
    settings = get_settings()
    token_payload = verify_refresh_token(payload.refresh_token, settings=settings.security)
    session_repo = UserSessionRepository(db)
    user_repo = UserRepository(db)

    token_hash = _hash_token(payload.refresh_token)
    active_session = session_repo.get_active_by_token_hash(token_hash)
    if active_session is None or not active_session.is_valid():
        raise AuthenticationError(
            "Refresh session is expired or has been revoked",
            error_code="SESSION_INVALID",
        )

    user = user_repo.get_by_id(token_payload.sub)
    if user is None or not user.can_authenticate():
        raise AuthenticationError(
            "User account is not eligible for token refresh",
            error_code="ACCOUNT_UNAVAILABLE",
        )

    # Rotate: revoke prior refresh session & JTI before minting fresh pair
    active_session.revoke()
    get_revocation_store().revoke(token_payload.jti, token_payload.exp)
    db.flush()

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent")
    token_response = _issue_session_tokens(
        db,
        user,
        client_ip=client_ip,
        user_agent=user_agent,
        settings=settings,
    )
    _record_auth_audit(
        db,
        action=AuditAction.TOKEN_REFRESH,
        org_id=user.org_id,
        user_id=user.id,
        email=user.email,
        summary=f"Rotated refresh session for '{user.email}'",
        client_ip=client_ip,
        user_agent=user_agent,
        resource_id=active_session.id,
    )
    db.commit()
    return token_response


@router.post(
    "/logout",
    response_model=ActionStatusResponse,
    summary="Revoke the active access token and refresh session(s)",
)
def logout(
    request: Request,
    payload: LogoutRequest | None = None,
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db_session),
) -> ActionStatusResponse:
    """Invalidate the caller's current JWT and optionally revoke all active sessions."""
    revocation_store = get_revocation_store()
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_access = auth_header.split(" ", 1)[1].strip()
        if raw_access:
            try:
                revoke_token(raw_access, revocation_store=revocation_store)
            except AuthenticationError:
                pass

    session_repo = UserSessionRepository(db)
    revoked_count = 0

    if payload is not None and payload.revoke_all_sessions and auth.user_id:
        revoked_count = session_repo.revoke_all_for_user(auth.user_id)
        if auth.token_jti:
            revocation_store.revoke(auth.token_jti)
        # Use whole-second cutoff minus 1s so a subsequent same-second re-login
        # (whose JWT iat is integer-truncated) is not falsely rejected.
        cutoff = datetime.fromtimestamp(int(utcnow().timestamp()) - 1, tz=timezone.utc)
        revocation_store.revoke_subject(auth.user_id, before=cutoff)
    elif payload is not None and payload.refresh_token:
        refresh_hash = _hash_token(payload.refresh_token)
        sess = session_repo.get_by_token_hash(refresh_hash)
        if sess is not None and (auth.user_id is None or sess.user_id == auth.user_id):
            sess.revoke()
            revoked_count = 1
        try:
            revoke_token(payload.refresh_token, revocation_store=revocation_store)
        except AuthenticationError:
            pass

    _record_auth_audit(
        db,
        action=AuditAction.LOGOUT,
        org_id=auth.org_id,
        user_id=auth.user_id,
        email=auth.email,
        summary=f"User '{auth.email}' logged out (revoked_sessions={revoked_count})",
        client_ip=auth.client_ip,
        user_agent=auth.user_agent,
        after_state={
            "revoke_all_sessions": bool(payload and payload.revoke_all_sessions),
            "revoked_sessions": revoked_count,
        },
    )
    db.commit()

    return ActionStatusResponse(
        status="ok",
        message="Successfully logged out and revoked token",
        revoked_sessions=revoked_count,
    )


@router.get(
    "/me",
    response_model=AuthMeResponse,
    summary="Return the currently authenticated user, organization, and effective permissions",
)
def get_me(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db_session),
) -> AuthMeResponse:
    """Return profile, tenant summary, and effective RBAC permissions for the caller."""
    user_read: UserRead | None = None
    if auth.user_id:
        user = UserRepository(db).get_by_id(auth.user_id, org_id=auth.org_id)
        if user is not None:
            user_read = user_to_read(user)

    org = OrganizationRepository(db).get_by_id(auth.org_id)
    org_summary = org_to_summary(org) if org is not None else None

    return AuthMeResponse(
        authenticated=auth.is_authenticated,
        auth_method=auth.auth_method,
        api_key_id=auth.api_key_id,
        user=user_read,
        organization=org_summary,
        role=auth.schema_role,
        is_admin=auth.is_admin,
        permissions=auth.permission_codes(),
    )


@router.post(
    "/change-password",
    response_model=ActionStatusResponse,
    dependencies=[Depends(rate_limit_dependency(10, scope="auth:change_password"))],
    summary="Change the authenticated user's password and revoke existing sessions",
)
def change_password(
    payload: PasswordChangeRequest,
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db_session),
) -> ActionStatusResponse:
    """Verify current password, enforce complexity, update hash, and revoke prior sessions."""
    if auth.auth_method != "jwt" or not auth.user_id:
        raise AuthorizationError(
            "Password changes require interactive JWT user authentication",
            error_code="JWT_REQUIRED",
        )

    user_repo = UserRepository(db)
    user = user_repo.get_by_id(auth.user_id, org_id=auth.org_id)
    if user is None:
        raise NotFoundError("Authenticated user account was not found")

    if not verify_password(payload.current_password, user.password_hash):
        raise AuthenticationError(
            "Current password is incorrect",
            error_code="INVALID_CURRENT_PASSWORD",
        )

    validate_password_strength(
        payload.new_password,
        forbidden_substrings=(user.username, user.email.split("@")[0]),
        raise_on_error=True,
    )

    user_repo.update_password_hash(user.id, hash_password(payload.new_password))
    revoked_count = UserSessionRepository(db).revoke_all_for_user(user.id)
    store = get_revocation_store()
    if auth.token_jti:
        store.revoke(auth.token_jti)
    cutoff = datetime.fromtimestamp(int(utcnow().timestamp()) - 1, tz=timezone.utc)
    store.revoke_subject(user.id, before=cutoff)

    _record_auth_audit(
        db,
        action=AuditAction.PASSWORD_CHANGE,
        org_id=auth.org_id,
        user_id=user.id,
        email=user.email,
        summary=f"User '{user.email}' rotated account password",
        client_ip=auth.client_ip,
        user_agent=auth.user_agent,
        after_state={"revoked_sessions": revoked_count},
    )
    db.commit()

    return ActionStatusResponse(
        status="ok",
        message="Password updated successfully. Please sign in again with your new password.",
        revoked_sessions=revoked_count,
    )


@router.get(
    "/permissions",
    response_model=RbacPermissionsResponse,
    summary="Inspect effective permissions, permission catalog, and role-permission matrix",
)
def get_permissions(
    auth: AuthContext = Depends(get_current_auth),
) -> RbacPermissionsResponse:
    """Return the caller's effective RBAC permissions along with the full platform matrix."""
    catalog = [_describe_permission(perm) for perm in sorted(Permission, key=lambda p: p.value)]

    seen_schema_roles: set[SchemaUserRole] = set()
    role_matrix: list[RolePermissionMatrix] = []
    for sec_role, perms in ROLE_PERMISSIONS.items():
        schema_role = normalize_schema_role(sec_role)
        if schema_role in seen_schema_roles:
            continue
        seen_schema_roles.add(schema_role)
        display_name, description = _ROLE_METADATA.get(
            sec_role, (sec_role.value.replace("_", " ").title(), "")
        )
        role_matrix.append(
            RolePermissionMatrix(
                role=schema_role,
                display_name=display_name,
                description=description,
                permissions=sorted(p.value for p in perms),
            )
        )

    return RbacPermissionsResponse(
        user_id=auth.user_id,
        org_id=auth.org_id,
        current_role=auth.schema_role,
        effective_permissions=auth.permission_codes(),
        is_admin=auth.is_admin,
        catalog=catalog,
        role_matrix=role_matrix,
    )


@router.post(
    "/demo-token",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_dependency(30, scope="auth:demo_token"))],
    summary="Issue a demo JWT token pair for seeded demo personas (demo/Vercel/dev mode)",
)
def issue_demo_token(
    request: Request,
    payload: DemoTokenRequest | None = None,
    profile: str | None = Query(
        default=None,
        description="Demo persona profile: admin, netops, operator, or viewer",
    ),
    db: Session = Depends(get_db_session),
) -> TokenResponse:
    """Mint a valid JWT token pair for a seeded NetPulse Global Corp demo persona."""
    settings = get_settings()
    if not _demo_token_allowed(settings):
        raise AuthorizationError(
            "Demo token issuance is disabled in this environment",
            error_code="DEMO_TOKEN_DISABLED",
        )

    chosen_profile = (profile or (payload.profile if payload else "admin")).strip().lower()
    target_email = _DEMO_PROFILE_EMAILS.get(chosen_profile)
    if target_email is None:
        raise ValidationError(
            f"Unsupported demo profile '{chosen_profile}'",
            details={"supported_profiles": sorted(_DEMO_PROFILE_EMAILS.keys())},
        )

    org_repo = OrganizationRepository(db)
    org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
    if org is None:
        ensure_database_ready(db, auto_seed=True)
        org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
    if org is None:
        raise NotFoundError("Demo organization has not been seeded")

    user_repo = UserRepository(db)
    user = user_repo.get_by_email(target_email, org_id=org.id)
    if user is None:
        user = user_repo.get_by_email(DEFAULT_ADMIN_EMAIL, org_id=org.id)
    if user is None:
        raise NotFoundError(f"Demo user '{target_email}' was not found")

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent")
    user.record_successful_login(ip_address=client_ip)
    db.flush()

    token_response = _issue_session_tokens(
        db,
        user,
        client_ip=client_ip,
        user_agent=user_agent,
        settings=settings,
    )
    _record_auth_audit(
        db,
        action=AuditAction.LOGIN,
        org_id=user.org_id,
        user_id=user.id,
        email=user.email,
        summary=f"Issued demo JWT token for profile '{chosen_profile}' ({user.email})",
        client_ip=client_ip,
        user_agent=user_agent,
        after_state={"demo_profile": chosen_profile, "role": user.role},
    )
    db.commit()
    return token_response
