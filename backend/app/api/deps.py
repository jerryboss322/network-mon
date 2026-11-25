"""FastAPI dependencies for database lifecycle, auth, RBAC, rate limiting, and query parsing.

Designed to operate seamlessly in both persistent self-hosted deployments and
ephemeral serverless runtimes (e.g. Vercel):
- Lazy schema initialization and idempotent demo-dataset seeding on cold starts.
- Unified :class:`AuthContext` resolved from JWT Bearer tokens, prefixed API keys
  (``npm_...``), or read-only demo fallback when demo/Vercel mode is enabled.
- Composable RBAC dependencies (:func:`require_auth`, :func:`require_permission`,
  :func:`require_any_permission`, :func:`require_role`).
- Per-principal / per-IP sliding-window rate limiting via :class:`SlidingWindowRateLimiter`.
- Reusable pagination and time-window query dependencies.
"""

from __future__ import annotations

import fnmatch
import os
import threading
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, Query, Request, Response
from sqlalchemy import func, inspect as sa_inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.cache import SlidingWindowRateLimiter
from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
)
from app.core.logging import bind_context, get_logger
from app.core.security import (
    Permission,
    Role,
    extract_client_ip,
    get_role_permissions,
    hash_api_key,
    verify_access_token,
)
from app.db.repositories.identity import (
    ApiKeyRepository,
    OrganizationRepository,
    UserRepository,
)
from app.db.seed import DEFAULT_ADMIN_EMAIL, DEFAULT_ORG_SLUG, seed_enterprise_demo
from app.db.session import get_engine, get_session_factory, init_database
from app.models.enums import UserRole as OrmUserRole
from app.models.identity import Organization, User
from app.schemas.common import (
    PaginationParams,
    SortOrder,
    TimeGranularity,
    TimeRangeQuery,
    ensure_utc,
    parse_relative_duration,
    utcnow,
)
from app.schemas.identity import UserRole as SchemaUserRole

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Role Normalization & Permission Mapping
# ---------------------------------------------------------------------------

# Maps ORM / schema / JWT role strings to the canonical security.Role enum.
_ROLE_ALIAS_TO_SECURITY_ROLE: dict[str, Role] = {
    "super_admin": Role.SUPER_ADMIN,
    "org_admin": Role.ORG_ADMIN,
    "admin": Role.ORG_ADMIN,
    "netops": Role.NETOPS_ENGINEER,
    "netops_engineer": Role.NETOPS_ENGINEER,
    "operator": Role.SRE_OPERATOR,
    "sre_operator": Role.SRE_OPERATOR,
    "analyst": Role.SECURITY_AUDITOR,
    "auditor": Role.SECURITY_AUDITOR,
    "security_auditor": Role.SECURITY_AUDITOR,
    "viewer": Role.VIEWER,
    "service_account": Role.AGENT,
    "agent": Role.AGENT,
}

# Maps ORM / security role strings to the Pydantic schemas.identity.UserRole enum.
_ROLE_ALIAS_TO_SCHEMA_ROLE: dict[str, SchemaUserRole] = {
    "super_admin": SchemaUserRole.SUPER_ADMIN,
    "org_admin": SchemaUserRole.ORG_ADMIN,
    "admin": SchemaUserRole.ORG_ADMIN,
    "netops": SchemaUserRole.NETOPS_ENGINEER,
    "netops_engineer": SchemaUserRole.NETOPS_ENGINEER,
    "operator": SchemaUserRole.OPERATOR,
    "sre_operator": SchemaUserRole.OPERATOR,
    "analyst": SchemaUserRole.AUDITOR,
    "auditor": SchemaUserRole.AUDITOR,
    "security_auditor": SchemaUserRole.AUDITOR,
    "viewer": SchemaUserRole.VIEWER,
    "service_account": SchemaUserRole.OPERATOR,
    "agent": SchemaUserRole.OPERATOR,
}

# Maps Pydantic schema role values to ORM models.enums.UserRole values.
_ROLE_ALIAS_TO_ORM_ROLE: dict[str, OrmUserRole] = {
    "super_admin": OrmUserRole.SUPER_ADMIN,
    "org_admin": OrmUserRole.ORG_ADMIN,
    "admin": OrmUserRole.ADMIN,
    "netops": OrmUserRole.NETOPS,
    "netops_engineer": OrmUserRole.NETOPS,
    "operator": OrmUserRole.OPERATOR,
    "sre_operator": OrmUserRole.OPERATOR,
    "analyst": OrmUserRole.ANALYST,
    "auditor": OrmUserRole.ANALYST,
    "security_auditor": OrmUserRole.ANALYST,
    "viewer": OrmUserRole.VIEWER,
    "service_account": OrmUserRole.SERVICE_ACCOUNT,
    "agent": OrmUserRole.SERVICE_ACCOUNT,
}

# Maps ApiKeyScope / short scopes to equivalent Permission enums.
_SCOPE_PERMISSION_EXPANSIONS: dict[str, frozenset[Permission]] = {
    "inventory:read": frozenset({Permission.DEVICES_READ, Permission.ORG_READ}),
    "inventory:write": frozenset(
        {
            Permission.DEVICES_READ,
            Permission.DEVICES_CREATE,
            Permission.DEVICES_UPDATE,
            Permission.DEVICES_DELETE,
            Permission.DEVICES_POLL,
            Permission.DEVICES_DISCOVER,
        }
    ),
    "devices:write": frozenset(
        {
            Permission.DEVICES_READ,
            Permission.DEVICES_CREATE,
            Permission.DEVICES_UPDATE,
            Permission.DEVICES_DELETE,
            Permission.DEVICES_POLL,
        }
    ),
    "telemetry:ingest": frozenset({Permission.TELEMETRY_WRITE, Permission.TELEMETRY_READ}),
    "topology:write": frozenset(
        {Permission.TOPOLOGY_READ, Permission.TOPOLOGY_EDIT, Permission.TOPOLOGY_DISCOVER}
    ),
    "alerting:read": frozenset({Permission.ALERTS_READ, Permission.INCIDENTS_READ}),
    "alerting:write": frozenset(
        {
            Permission.ALERTS_READ,
            Permission.ALERTS_CREATE,
            Permission.ALERTS_UPDATE,
            Permission.ALERTS_DELETE,
            Permission.ALERTS_ACKNOWLEDGE,
            Permission.ALERTS_SILENCE,
            Permission.ALERTS_RESOLVE,
            Permission.INCIDENTS_READ,
            Permission.INCIDENTS_CREATE,
            Permission.INCIDENTS_UPDATE,
            Permission.INCIDENTS_RESOLVE,
        }
    ),
    "alerts:write": frozenset(
        {
            Permission.ALERTS_READ,
            Permission.ALERTS_CREATE,
            Permission.ALERTS_UPDATE,
            Permission.ALERTS_DELETE,
            Permission.ALERTS_ACKNOWLEDGE,
            Permission.ALERTS_SILENCE,
            Permission.ALERTS_RESOLVE,
        }
    ),
    "automation:read": frozenset(
        {Permission.PLAYBOOKS_READ, Permission.COMPLIANCE_READ, Permission.CONFIG_BACKUP_READ}
    ),
    "automation:execute": frozenset(
        {
            Permission.PLAYBOOKS_READ,
            Permission.PLAYBOOKS_EXECUTE,
            Permission.COMPLIANCE_AUDIT,
            Permission.CONFIG_BACKUP_CREATE,
        }
    ),
    "audit:read": frozenset({Permission.ADMIN_AUDIT_LOGS_READ}),
    "admin:*": frozenset(Permission),
    "*": frozenset(Permission),
}


def normalize_security_role(role: str | Role | OrmUserRole | SchemaUserRole | None) -> Role:
    """Resolve any ORM, schema, or raw string role into a canonical :class:`Role`."""
    if isinstance(role, Role):
        return role
    if role is None:
        return Role.VIEWER
    key = (role.value if hasattr(role, "value") else str(role)).strip().lower()
    if key in _ROLE_ALIAS_TO_SECURITY_ROLE:
        return _ROLE_ALIAS_TO_SECURITY_ROLE[key]
    try:
        return Role(key.upper())
    except ValueError:
        return Role.VIEWER


def normalize_schema_role(role: str | Role | OrmUserRole | SchemaUserRole | None) -> SchemaUserRole:
    """Resolve any ORM, security, or raw string role into :class:`app.schemas.identity.UserRole`."""
    if isinstance(role, SchemaUserRole):
        return role
    if role is None:
        return SchemaUserRole.VIEWER
    key = (role.value if hasattr(role, "value") else str(role)).strip().lower()
    return _ROLE_ALIAS_TO_SCHEMA_ROLE.get(key, SchemaUserRole.VIEWER)


def normalize_orm_role(role: str | Role | OrmUserRole | SchemaUserRole | None) -> OrmUserRole:
    """Resolve any schema, security, or raw string role into :class:`app.models.enums.UserRole`."""
    if isinstance(role, OrmUserRole):
        return role
    if role is None:
        return OrmUserRole.VIEWER
    key = (role.value if hasattr(role, "value") else str(role)).strip().lower()
    return _ROLE_ALIAS_TO_ORM_ROLE.get(key, OrmUserRole.VIEWER)


def expand_scopes_to_permissions(scopes: Iterable[str]) -> frozenset[Permission]:
    """Expand API key or token scopes (including wildcards/aliases) to :class:`Permission`."""
    resolved: set[Permission] = set()
    all_perms = tuple(Permission)
    for raw_scope in scopes:
        scope = str(raw_scope).strip().lower()
        if not scope:
            continue
        if scope in _SCOPE_PERMISSION_EXPANSIONS:
            resolved.update(_SCOPE_PERMISSION_EXPANSIONS[scope])
            continue
        # Direct Permission enum value match
        try:
            resolved.add(Permission(scope))
            continue
        except ValueError:
            pass
        # Glob/wildcard matching (e.g. "devices:*", "*:read")
        if "*" in scope:
            for perm in all_perms:
                if fnmatch.fnmatchcase(perm.value, scope):
                    resolved.add(perm)
    return frozenset(resolved)


def resolve_permissions_for_role(role: str | Role | OrmUserRole | SchemaUserRole) -> frozenset[Permission]:
    """Return all permissions granted to the given role."""
    sec_role = normalize_security_role(role)
    return get_role_permissions(sec_role)


# ---------------------------------------------------------------------------
# AuthContext Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Authenticated principal context injected into FastAPI route handlers."""

    user_id: str | None
    org_id: str
    email: str | None
    role: str
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    auth_method: str = "jwt"  # "jwt" | "api_key" | "demo_fallback"
    api_key_id: str | None = None
    token_jti: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None

    @property
    def security_role(self) -> Role:
        """Return the canonical security :class:`Role` enum."""
        return normalize_security_role(self.role)

    @property
    def schema_role(self) -> SchemaUserRole:
        """Return the API schema :class:`SchemaUserRole` enum."""
        return normalize_schema_role(self.role)

    @property
    def orm_role(self) -> OrmUserRole:
        """Return the ORM :class:`OrmUserRole` enum."""
        return normalize_orm_role(self.role)

    @property
    def is_authenticated(self) -> bool:
        """Return ``True`` when authenticated via an explicit JWT or API key."""
        return self.auth_method in {"jwt", "api_key"}

    @property
    def is_demo_fallback(self) -> bool:
        """Return ``True`` when operating under the read-only demo fallback context."""
        return self.auth_method == "demo_fallback"

    @property
    def is_admin(self) -> bool:
        """Return ``True`` if the principal holds org-admin or super-admin role."""
        return self.security_role in {Role.SUPER_ADMIN, Role.ORG_ADMIN}

    def has_permission(self, permission: Permission | str) -> bool:
        """Check whether this principal possesses ``permission``."""
        try:
            target = permission if isinstance(permission, Permission) else Permission(permission)
        except ValueError:
            return False
        return target in self.permissions

    def has_any_permission(self, permissions: Iterable[Permission | str]) -> bool:
        """Check whether this principal possesses at least one of ``permissions``."""
        return any(self.has_permission(perm) for perm in permissions)

    def has_all_permissions(self, permissions: Iterable[Permission | str]) -> bool:
        """Check whether this principal possesses every permission in ``permissions``."""
        return all(self.has_permission(perm) for perm in permissions)

    def permission_codes(self) -> list[str]:
        """Return sorted string codes for all effective permissions."""
        return sorted(perm.value for perm in self.permissions)

    def to_dict(self) -> dict[str, Any]:
        """Return a safe serializable representation for diagnostics or responses."""
        return {
            "user_id": self.user_id,
            "org_id": self.org_id,
            "email": self.email,
            "role": self.role,
            "auth_method": self.auth_method,
            "api_key_id": self.api_key_id,
            "is_admin": self.is_admin,
            "permissions": self.permission_codes(),
        }


# ---------------------------------------------------------------------------
# Lazy Database Initialization & Serverless Auto-Seeding
# ---------------------------------------------------------------------------

_db_init_lock = threading.RLock()
_initialized_engines: set[int] = set()


def _auto_seed_enabled(settings: Settings) -> bool:
    """Return True when empty databases should automatically seed the demo dataset."""
    explicit_disable = os.getenv("NETMON_DISABLE_AUTO_SEED", "").strip().lower()
    if explicit_disable in {"1", "true", "yes", "on"}:
        return False
    explicit_enable = os.getenv("NETMON_AUTO_SEED", "").strip().lower()
    if explicit_enable in {"0", "false", "no", "off"}:
        return False
    return True


def _demo_fallback_enabled(settings: Settings) -> bool:
    """Return True when unauthenticated read-only demo fallback is permitted."""
    raw = os.getenv("NETMON_DEMO_FALLBACK")
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return bool(
        settings.is_vercel
        or settings.collectors.simulate_demo_telemetry
        or settings.environment in {"development", "test"}
    )


def reset_db_init_state() -> None:
    """Clear the cached engine-initialization registry (helpful in unit tests)."""
    with _db_init_lock:
        _initialized_engines.clear()


def ensure_database_ready(
    session: Session | None = None,
    *,
    auto_seed: bool | None = None,
) -> dict[str, Any]:
    """Ensure all ORM tables exist and optionally seed an empty database.

    Safe to invoke concurrently during Vercel serverless cold starts: uses a
    re-entrant lock per engine identity, imports all ORM models before running
    ``Base.metadata.create_all``, and handles concurrent seed races gracefully.
    """
    settings = get_settings()
    engine = session.get_bind() if session is not None else get_engine()
    engine_key = id(engine)
    should_seed = _auto_seed_enabled(settings) if auto_seed is None else auto_seed

    if engine_key in _initialized_engines:
        # Fast-path: verify organizations table wasn't wiped out under us in serverless /tmp
        try:
            inspector = sa_inspect(engine)
            if inspector.has_table("organizations"):
                return {"initialized": True, "seeded": False}
        except Exception:
            pass

    with _db_init_lock:
        # Register all ORM models on Base.metadata prior to DDL creation
        import app.models  # noqa: F401

        init_database(engine=engine)  # type: ignore[arg-type]

        seeded = False
        if should_seed:
            own_session = session is None
            active_session = session or get_session_factory()()
            try:
                org_count = int(
                    active_session.execute(select(func.count()).select_from(Organization)).scalar_one()
                )
                if org_count == 0:
                    logger.info(
                        "Empty database detected; auto-seeding NetPulse enterprise demo dataset",
                        extra={"is_vercel": settings.is_vercel, "db_sqlite": settings.is_sqlite},
                    )
                    try:
                        seed_result = seed_enterprise_demo(active_session, commit=True, force=False)
                        seeded = bool(seed_result.get("seeded"))
                    except IntegrityError:
                        # Another concurrent cold-start worker seeded simultaneously
                        active_session.rollback()
                        logger.warning("Concurrent demo seed detected; continuing with existing rows")
            finally:
                if own_session:
                    active_session.close()

        _initialized_engines.add(engine_key)
        return {"initialized": True, "seeded": seeded}


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped SQLAlchemy session.

    Automatically initializes the schema and seeds the demo organization when
    running against an empty database (critical for Vercel serverless cold starts).
    """
    ensure_database_ready()
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Client Metadata & Token Extraction Helpers
# ---------------------------------------------------------------------------


def get_client_ip(request: Request) -> str | None:
    """Resolve client IP from request connection or forwarded headers."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first_hop = xff.split(",")[0].strip()
        if first_hop:
            return "127.0.0.1" if first_hop == "testclient" else first_hop
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        cleaned = real_ip.strip()
        return "127.0.0.1" if cleaned == "testclient" else cleaned
    direct_ip = request.client.host if request.client else None
    if direct_ip == "testclient":
        return "127.0.0.1"
    return extract_client_ip(direct_ip)


def _extract_bearer_token(request: Request) -> str | None:
    """Extract a Bearer JWT from the Authorization header, if present."""
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return None
    parts = auth_header.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1].strip()
        return token or None
    return None


def _extract_api_key(request: Request) -> str | None:
    """Extract a prefixed API key from ``X-API-Key`` or ``Authorization: ApiKey ...``."""
    header_key = request.headers.get("x-api-key")
    if header_key and header_key.strip():
        return header_key.strip()
    auth_header = request.headers.get("authorization")
    if auth_header:
        parts = auth_header.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in {"apikey", "api-key"}:
            return parts[1].strip() or None
    return None


def _resolve_jwt_auth(
    token: str,
    db: Session,
    *,
    client_ip: str | None,
    user_agent: str | None,
) -> AuthContext:
    """Validate a JWT access token and resolve its active :class:`AuthContext`."""
    payload = verify_access_token(token)
    user_repo = UserRepository(db)
    user: User | None = user_repo.get_by_id(payload.sub)
    if user is None:
        raise AuthenticationError(
            "Authenticated user no longer exists",
            error_code="USER_NOT_FOUND",
        )
    if not user.is_active or bool(user.is_deleted):
        raise AuthenticationError(
            "User account is disabled",
            error_code="ACCOUNT_DISABLED",
        )
    if user.is_locked():
        raise AuthenticationError(
            "User account is temporarily locked",
            error_code="ACCOUNT_LOCKED",
        )

    org_id = user.org_id or payload.org_id
    if not org_id:
        raise AuthenticationError("Token is missing tenant organization scope")

    role_perms = resolve_permissions_for_role(user.role)
    if payload.scopes:
        token_perms = expand_scopes_to_permissions(payload.scopes)
        # Keep effective permissions bounded to the user's current role permissions
        effective_perms = role_perms & token_perms if token_perms else role_perms
    else:
        effective_perms = role_perms

    return AuthContext(
        user_id=user.id,
        org_id=org_id,
        email=user.email,
        role=user.role,
        permissions=effective_perms,
        auth_method="jwt",
        api_key_id=None,
        token_jti=payload.jti,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def _resolve_api_key_auth(
    raw_key: str,
    db: Session,
    *,
    client_ip: str | None,
    user_agent: str | None,
    settings: Settings,
) -> AuthContext:
    """Validate an ``npm_...`` API key and construct a scoped :class:`AuthContext`."""
    expected_prefix = settings.security.api_key_prefix
    if not raw_key.startswith(expected_prefix):
        raise AuthenticationError(
            "Invalid API key format",
            error_code="INVALID_API_KEY",
        )

    key_hash = hash_api_key(raw_key)
    key_repo = ApiKeyRepository(db)
    api_key = key_repo.get_valid_by_hash(key_hash)
    if api_key is None or not api_key.is_valid():
        raise AuthenticationError(
            "Invalid, expired, or revoked API key",
            error_code="INVALID_API_KEY",
        )

    allowed_cidrs = set(api_key.allowed_cidrs_json or [])
    wildcard_ip_allowed = "0.0.0.0/0" in allowed_cidrs or "::/0" in allowed_cidrs
    if client_ip and not wildcard_ip_allowed and not api_key.is_ip_allowed(client_ip):
        raise AuthorizationError(
            "API key is not authorized for this source IP address",
            error_code="API_KEY_IP_DENIED",
            details={"client_ip": client_ip, "api_key_id": api_key.id},
        )

    # Best-effort last_used_at update without disrupting caller transaction semantics
    try:
        api_key.mark_used()
        db.flush()
        db.commit()
    except Exception:
        db.rollback()

    permissions = expand_scopes_to_permissions(api_key.scopes_json or [])
    creator_email: str | None = None
    if api_key.created_by_user_id:
        creator = UserRepository(db).get_by_id(api_key.created_by_user_id)
        if creator is not None:
            creator_email = creator.email

    return AuthContext(
        user_id=api_key.created_by_user_id,
        org_id=api_key.org_id,
        email=creator_email or f"apikey:{api_key.key_prefix}@netpulse.local",
        role=OrmUserRole.SERVICE_ACCOUNT.value,
        permissions=permissions,
        auth_method="api_key",
        api_key_id=api_key.id,
        token_jti=None,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def _resolve_demo_fallback_auth(
    request: Request,
    db: Session,
    *,
    client_ip: str | None,
    user_agent: str | None,
) -> AuthContext:
    """Resolve a read-only demo :class:`AuthContext` bound to the default organization."""
    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        raise AuthenticationError(
            "Authentication is required for state-changing requests",
            error_code="AUTHENTICATION_REQUIRED",
        )

    org_repo = OrganizationRepository(db)
    org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
    if org is None:
        active_orgs = org_repo.list_active(limit=1)
        org = active_orgs[0] if active_orgs else None
    if org is None:
        ensure_database_ready(db, auto_seed=True)
        org = org_repo.get_by_slug(DEFAULT_ORG_SLUG)
    if org is None:
        raise AuthenticationError(
            "No active organization available for demo fallback",
            error_code="AUTHENTICATION_REQUIRED",
        )

    user_repo = UserRepository(db)
    demo_user = (
        user_repo.get_by_email("viewer@netpulse.io", org_id=org.id)
        or user_repo.get_by_email(DEFAULT_ADMIN_EMAIL, org_id=org.id)
    )

    # Read-only demo permissions (Viewer permissions + audit/system read for dashboard previews)
    read_only_perms = resolve_permissions_for_role(Role.VIEWER) | frozenset(
        {Permission.ADMIN_SYSTEM_READ}
    )

    return AuthContext(
        user_id=demo_user.id if demo_user is not None else None,
        org_id=org.id,
        email=demo_user.email if demo_user is not None else "demo-viewer@netpulse.io",
        role=OrmUserRole.VIEWER.value,
        permissions=read_only_perms,
        auth_method="demo_fallback",
        api_key_id=None,
        token_jti=None,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def get_current_auth(
    request: Request,
    db: Session = Depends(get_db_session),
) -> AuthContext:
    """Resolve the active :class:`AuthContext` for an incoming HTTP request.

    Authentication precedence:
    1. ``Authorization: Bearer <jwt>``
    2. ``X-API-Key: npm_...`` (or ``Authorization: ApiKey npm_...``)
    3. Read-only demo fallback when demo/Vercel mode is enabled and no credentials
       were supplied. Explicit invalid credentials always return HTTP 401.
    """
    settings = get_settings()
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    bearer_token = _extract_bearer_token(request)
    api_key = _extract_api_key(request)

    if bearer_token is not None:
        ctx = _resolve_jwt_auth(
            bearer_token,
            db,
            client_ip=client_ip,
            user_agent=user_agent,
        )
    elif api_key is not None:
        ctx = _resolve_api_key_auth(
            api_key,
            db,
            client_ip=client_ip,
            user_agent=user_agent,
            settings=settings,
        )
    else:
        auth_header = request.headers.get("authorization")
        if auth_header:
            raise AuthenticationError(
                "Unsupported Authorization header scheme; use Bearer <jwt> or X-API-Key",
                error_code="INVALID_AUTH_SCHEME",
            )
        if not _demo_fallback_enabled(settings):
            raise AuthenticationError(
                "Authentication credentials were not provided",
                error_code="AUTHENTICATION_REQUIRED",
            )
        ctx = _resolve_demo_fallback_auth(
            request,
            db,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    # Bind tenant and actor metadata into structured logging context and request.state
    bind_context(org_id=ctx.org_id, user_id=ctx.user_id)
    request.state.auth = ctx
    return ctx


def require_auth(
    auth: AuthContext = Depends(get_current_auth),
) -> AuthContext:
    """Strictly require an authenticated JWT or API-key principal (disallows demo fallback)."""
    if not auth.is_authenticated:
        raise AuthenticationError(
            "Explicit authentication (Bearer JWT or X-API-Key) is required for this endpoint",
            error_code="AUTHENTICATION_REQUIRED",
        )
    return auth


def require_permission(
    *perms: Permission,
    strict_auth: bool = False,
) -> Callable[..., AuthContext]:
    """Dependency factory enforcing that the caller holds all specified permissions."""
    required = tuple(perms)
    base_dep = require_auth if strict_auth else get_current_auth

    def _checker(auth: AuthContext = Depends(base_dep)) -> AuthContext:
        missing = [perm.value for perm in required if perm not in auth.permissions]
        if missing:
            raise AuthorizationError(
                f"Insufficient permissions; missing: {', '.join(missing)}",
                error_code="INSUFFICIENT_PERMISSIONS",
                details={
                    "role": auth.role,
                    "auth_method": auth.auth_method,
                    "missing_permissions": missing,
                },
            )
        return auth

    return _checker


def require_any_permission(
    *perms: Permission,
    strict_auth: bool = False,
) -> Callable[..., AuthContext]:
    """Dependency factory enforcing that the caller holds at least one listed permission."""
    required = tuple(perms)
    base_dep = require_auth if strict_auth else get_current_auth

    def _checker(auth: AuthContext = Depends(base_dep)) -> AuthContext:
        if required and not auth.has_any_permission(required):
            raise AuthorizationError(
                "Insufficient permissions for requested operation",
                error_code="INSUFFICIENT_PERMISSIONS",
                details={
                    "role": auth.role,
                    "auth_method": auth.auth_method,
                    "required_any": [p.value for p in required],
                },
            )
        return auth

    return _checker


def require_role(*roles: Role | str) -> Callable[..., AuthContext]:
    """Dependency factory enforcing membership in one of the allowed RBAC roles."""
    allowed = frozenset(normalize_security_role(r) for r in roles)

    def _checker(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        if auth.security_role not in allowed:
            raise AuthorizationError(
                f"Role '{auth.role}' is not authorized for this resource",
                error_code="ROLE_REQUIRED",
                details={
                    "role": auth.role,
                    "allowed_roles": sorted(r.value for r in allowed),
                },
            )
        return auth

    return _checker


# ---------------------------------------------------------------------------
# Sliding-Window Rate Limiting Dependency
# ---------------------------------------------------------------------------

_rate_limiters_lock = threading.RLock()
_rate_limiters: dict[tuple[str, int], SlidingWindowRateLimiter] = {}


def _get_rate_limiter(scope: str, limit_per_minute: int) -> SlidingWindowRateLimiter:
    key = (scope, limit_per_minute)
    with _rate_limiters_lock:
        limiter = _rate_limiters.get(key)
        if limiter is None:
            limiter = SlidingWindowRateLimiter(
                max_requests=max(1, limit_per_minute),
                window_seconds=60.0,
            )
            _rate_limiters[key] = limiter
        return limiter


def reset_rate_limiters() -> None:
    """Clear all in-process sliding-window rate limiter state (useful in tests)."""
    with _rate_limiters_lock:
        for limiter in _rate_limiters.values():
            limiter.reset()


def rate_limit_dependency(
    limit_per_minute: int,
    *,
    scope: str | None = None,
) -> Callable[..., None]:
    """FastAPI dependency factory enforcing a per-minute sliding-window rate limit."""
    if limit_per_minute < 1:
        raise ValueError("limit_per_minute must be >= 1")

    def _enforce(request: Request, response: Response) -> None:
        bucket_scope = scope or f"{request.method}:{request.url.path}"
        limiter = _get_rate_limiter(bucket_scope, limit_per_minute)

        auth: AuthContext | None = getattr(request.state, "auth", None)
        if auth is not None and auth.api_key_id:
            identity_key = f"apikey:{auth.api_key_id}"
        elif auth is not None and auth.user_id and auth.is_authenticated:
            identity_key = f"user:{auth.user_id}"
        else:
            identity_key = f"ip:{get_client_ip(request) or 'unknown'}"

        decision = limiter.allow(identity_key)
        for header_name, header_val in decision.to_headers().items():
            response.headers[header_name] = header_val

        if not decision.allowed:
            raise RateLimitError(
                f"Rate limit exceeded ({limit_per_minute} requests/minute). Please retry later.",
                details={
                    "limit": decision.limit,
                    "window_seconds": 60,
                    "retry_after_seconds": decision.retry_after_seconds,
                    "scope": bucket_scope,
                },
            )

    return _enforce


# ---------------------------------------------------------------------------
# Pagination & Time-Range Query Dependencies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedTimeRange:
    """Resolved UTC time-window bounds passed to analytics and audit endpoints."""

    start: datetime
    end: datetime
    window: str | None = None
    granularity: TimeGranularity = TimeGranularity.RAW

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.end - self.start).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "window": self.window,
            "granularity": self.granularity.value,
            "duration_seconds": round(self.duration_seconds, 2),
        }


def parse_pagination(
    page: Annotated[int, Query(ge=1, le=100_000, description="1-indexed page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=500, description="Items per page (1-500)")] = 50,
    sort_by: Annotated[str | None, Query(max_length=64, description="Field name to sort by")] = None,
    sort_order: Annotated[SortOrder, Query(description="Sort direction (asc or desc)")] = SortOrder.DESC,
) -> PaginationParams:
    """FastAPI dependency returning validated :class:`PaginationParams`."""
    return PaginationParams(
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _auto_select_granularity(delta: timedelta) -> TimeGranularity:
    total_hours = delta.total_seconds() / 3600.0
    if total_hours <= 2:
        return TimeGranularity.RAW
    if total_hours <= 12:
        return TimeGranularity.ONE_MINUTE
    if total_hours <= 48:
        return TimeGranularity.FIVE_MINUTES
    if total_hours <= 24 * 7:
        return TimeGranularity.FIFTEEN_MINUTES
    if total_hours <= 24 * 30:
        return TimeGranularity.ONE_HOUR
    return TimeGranularity.ONE_DAY


def parse_time_range(
    start: Annotated[
        datetime | None,
        Query(description="Inclusive UTC start timestamp (ISO-8601)"),
    ] = None,
    end: Annotated[
        datetime | None,
        Query(description="Inclusive UTC end timestamp (ISO-8601)"),
    ] = None,
    window: Annotated[
        str | None,
        Query(description="Relative lookback window such as 15m, 1h, 6h, 24h, 7d, 30d"),
    ] = None,
    granularity: Annotated[
        TimeGranularity | None,
        Query(description="Optional time-series aggregation bucket override"),
    ] = None,
) -> ResolvedTimeRange:
    """FastAPI dependency parsing absolute or relative time ranges into UTC bounds."""
    try:
        query = TimeRangeQuery(
            start=start,
            end=end,
            relative=window,
            granularity=granularity,
        )
    except ValueError as exc:
        raise ValidationError(
            f"Invalid time range parameters: {exc}",
            details={"start": str(start), "end": str(end), "window": window},
        ) from exc

    now = utcnow()
    resolved_start, resolved_end = query.resolve(now=now)
    resolved_start = ensure_utc(resolved_start)
    resolved_end = ensure_utc(resolved_end)

    if resolved_start >= resolved_end:
        raise ValidationError(
            "'start' timestamp must be earlier than 'end'",
            details={"start": resolved_start.isoformat(), "end": resolved_end.isoformat()},
        )

    effective_window = window.strip().lower() if window else None
    if effective_window is not None:
        # Validate syntax explicitly (already validated by TimeRangeQuery)
        parse_relative_duration(effective_window)

    selected_granularity = granularity or _auto_select_granularity(resolved_end - resolved_start)
    return ResolvedTimeRange(
        start=resolved_start,
        end=resolved_end,
        window=effective_window,
        granularity=selected_granularity,
    )


__all__ = [
    "AuthContext",
    "ResolvedTimeRange",
    "ensure_database_ready",
    "expand_scopes_to_permissions",
    "get_client_ip",
    "get_current_auth",
    "get_db_session",
    "normalize_orm_role",
    "normalize_schema_role",
    "normalize_security_role",
    "parse_pagination",
    "parse_time_range",
    "rate_limit_dependency",
    "require_any_permission",
    "require_auth",
    "require_permission",
    "require_role",
    "reset_db_init_state",
    "reset_rate_limiters",
    "resolve_permissions_for_role",
]
