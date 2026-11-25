"""Security primitives: passwords, JWTs, API keys, Fernet vault, RBAC, and CIDR ACLs.

Provides all cryptographic, authentication, authorization, and secret-storage
building blocks for the NetPulse Observability Platform:
- PBKDF2-HMAC-SHA256 password hashing with per-password salt & constant-time compare.
- Comprehensive password strength validation with entropy estimation.
- JWT access and refresh token lifecycle powered by PyJWT plus JTI revocation store.
- Prefixed API key generation (``npm_<prefix>_<secret>``) and SHA-256 verification.
- Fernet-based :class:`CredentialVault` for encrypting device SNMP/SSH/API credentials
  at rest, including zero-downtime key rotation.
- Granular RBAC :class:`Permission` enum (55 permissions), :class:`Role` matrix,
  and authorization enforcement helpers.
- IPv4/IPv6 CIDR allowlist/denylist evaluation for network-layer access control.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import SecuritySettings, get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    VaultDecryptionError,
)

# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

PBKDF2_ALGORITHM = "pbkdf2_sha256"
DEFAULT_PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16
DK_LEN = 32


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Hash a plaintext password using PBKDF2-HMAC-SHA256 with a random salt.

    Stored format: ``pbkdf2_sha256$<iterations>$<urlsafe_b64_salt>$<urlsafe_b64_dk>``.
    """
    if not isinstance(password, str) or not password:
        raise ValidationError("Password must be a non-empty string")
    if iterations < 10_000:
        raise ValidationError("PBKDF2 iteration count must be at least 10,000")

    raw_salt = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        raw_salt,
        iterations,
        dklen=DK_LEN,
    )
    salt_b64 = base64.urlsafe_b64encode(raw_salt).decode("ascii")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii")
    return f"{PBKDF2_ALGORITHM}${iterations}${salt_b64}${dk_b64}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a PBKDF2 hash in constant time."""
    if not password or not password_hash:
        return False
    try:
        algorithm, iter_str, salt_b64, expected_dk_b64 = password_hash.split("$", 3)
        if algorithm != PBKDF2_ALGORITHM:
            return False
        iterations = int(iter_str)
        if iterations <= 0:
            return False
        raw_salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected_dk = base64.urlsafe_b64decode(expected_dk_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        raw_salt,
        iterations,
        dklen=len(expected_dk),
    )
    return hmac.compare_digest(derived, expected_dk)


def needs_rehash(password_hash: str, *, target_iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bool:
    """Return True if a stored hash uses fewer iterations or a legacy algorithm."""
    try:
        algorithm, iter_str, _, _ = password_hash.split("$", 3)
        return algorithm != PBKDF2_ALGORITHM or int(iter_str) < target_iterations
    except (ValueError, TypeError):
        return True


# ---------------------------------------------------------------------------
# Password strength validation
# ---------------------------------------------------------------------------

_COMMON_WEAK_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "admin123",
        "administrator",
        "letmein",
        "welcome1",
        "changeme",
        "cisco123",
        "netpulse",
        "netpulse123",
        "root1234",
        "default1",
        "iloveyou",
        "monkey123",
        "abc12345",
    }
)


@dataclass(frozen=True)
class PasswordStrengthReport:
    """Detailed result of evaluating a candidate password."""

    valid: bool
    score: int  # 0 (very weak) to 4 (very strong)
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def validate_password_strength(
    password: str,
    *,
    min_length: int | None = None,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digit: bool = True,
    require_special: bool = True,
    forbidden_substrings: Iterable[str] = (),
    raise_on_error: bool = False,
) -> PasswordStrengthReport:
    """Validate password complexity and compute a 0..4 strength score."""
    cfg = get_settings().security
    effective_min = min_length if min_length is not None else cfg.password_min_length
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(password, str):
        errors.append("Password must be a string.")
        report = PasswordStrengthReport(valid=False, score=0, errors=tuple(errors))
        if raise_on_error:
            raise ValidationError("Invalid password", details={"errors": errors})
        return report

    if len(password) < effective_min:
        errors.append(f"Password must be at least {effective_min} characters long.")
    if len(password) > 128:
        errors.append("Password must not exceed 128 characters.")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if require_uppercase and not has_upper:
        errors.append("Password must contain at least one uppercase letter.")
    if require_lowercase and not has_lower:
        errors.append("Password must contain at least one lowercase letter.")
    if require_digit and not has_digit:
        errors.append("Password must contain at least one digit.")
    if require_special and not has_special:
        errors.append("Password must contain at least one special character.")

    lowered = password.lower()
    if lowered in _COMMON_WEAK_PASSWORDS:
        errors.append("Password is too common and easily guessed.")

    if re.search(r"(.)\1{3,}", password):
        warnings.append("Password contains 4 or more repeated identical characters.")

    for sub in forbidden_substrings:
        cleaned = sub.strip().lower()
        if len(cleaned) >= 3 and cleaned in lowered:
            errors.append("Password must not contain personal or account identifiers.")
            break

    # Compute heuristic score 0..4
    score = 0
    char_classes = sum([has_upper, has_lower, has_digit, has_special])
    if len(password) >= effective_min:
        score += 1
    if len(password) >= 12:
        score += 1
    if char_classes >= 3:
        score += 1
    if char_classes == 4 and len(set(password)) >= 8 and not warnings:
        score += 1
    if lowered in _COMMON_WEAK_PASSWORDS:
        score = 0

    report = PasswordStrengthReport(
        valid=len(errors) == 0,
        score=min(4, score),
        errors=tuple(errors),
        warnings=tuple(warnings),
    )
    if raise_on_error and not report.valid:
        raise ValidationError(
            "Password does not meet security requirements",
            details={"errors": list(report.errors), "score": report.score},
        )
    return report


# ---------------------------------------------------------------------------
# Token revocation store
# ---------------------------------------------------------------------------


class TokenRevocationStore:
    """Thread-safe in-memory store tracking revoked JWT IDs (JTIs) and subject cutoffs."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._revoked_jtis: dict[str, float] = {}
        self._subject_cutoffs: dict[str, float] = {}

    def revoke(self, jti: str, expires_at: datetime | float | None = None) -> None:
        """Revoke a specific token by JTI until its natural expiration."""
        if not jti:
            return
        if isinstance(expires_at, datetime):
            exp_ts = expires_at.timestamp()
        elif isinstance(expires_at, (int, float)):
            exp_ts = float(expires_at)
        else:
            # Default retention: 30 days
            exp_ts = datetime.now(timezone.utc).timestamp() + 30 * 86400
        with self._lock:
            self._revoked_jtis[jti] = exp_ts

    def revoke_subject(self, subject: str, *, before: datetime | None = None) -> None:
        """Revoke all tokens issued for ``subject`` at or before ``before`` (default now)."""
        cutoff = (before or datetime.now(timezone.utc)).timestamp()
        with self._lock:
            self._subject_cutoffs[subject] = cutoff

    def is_revoked(
        self,
        jti: str | None,
        *,
        subject: str | None = None,
        issued_at: datetime | float | None = None,
    ) -> bool:
        """Return True if the JTI is revoked or issued prior to a subject-wide revocation."""
        now_ts = datetime.now(timezone.utc).timestamp()
        with self._lock:
            if jti and jti in self._revoked_jtis:
                if self._revoked_jtis[jti] >= now_ts:
                    return True
                self._revoked_jtis.pop(jti, None)
            if subject and subject in self._subject_cutoffs and issued_at is not None:
                iat_ts = issued_at.timestamp() if isinstance(issued_at, datetime) else float(issued_at)
                if iat_ts <= self._subject_cutoffs[subject]:
                    return True
        return False

    def prune_expired(self) -> int:
        """Remove revoked JTI entries whose natural expiration has already passed."""
        now_ts = datetime.now(timezone.utc).timestamp()
        removed = 0
        with self._lock:
            expired = [jti for jti, exp in self._revoked_jtis.items() if exp < now_ts]
            for jti in expired:
                del self._revoked_jtis[jti]
                removed += 1
        return removed

    def clear(self) -> None:
        """Clear all revocation records (primarily for tests)."""
        with self._lock:
            self._revoked_jtis.clear()
            self._subject_cutoffs.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._revoked_jtis)


_default_revocation_store = TokenRevocationStore()


def get_revocation_store() -> TokenRevocationStore:
    """Return the process-wide default :class:`TokenRevocationStore`."""
    return _default_revocation_store


# ---------------------------------------------------------------------------
# JWT Access & Refresh Tokens
# ---------------------------------------------------------------------------


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(frozen=True)
class TokenPayload:
    """Decoded and validated JWT claims."""

    sub: str
    token_type: TokenType
    jti: str
    iat: datetime
    exp: datetime
    org_id: str | None = None
    role: str | None = None
    scopes: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenPair:
    """Bundled access and refresh token pair returned on authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_expires_in: int = 1_209_600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    subject: str,
    *,
    org_id: str | None = None,
    role: str | Role | None = None,
    scopes: Sequence[str] = (),
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
    settings: SecuritySettings | None = None,
) -> str:
    """Create a signed JWT access token."""
    cfg = settings or get_settings().security
    now = _utcnow()
    delta = expires_delta or timedelta(minutes=cfg.access_token_expire_minutes)
    exp = now + delta
    role_val = role.value if isinstance(role, Role) else role

    claims: dict[str, Any] = {
        "sub": subject,
        "type": TokenType.ACCESS.value,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": "netpulse",
    }
    if org_id is not None:
        claims["org_id"] = org_id
    if role_val is not None:
        claims["role"] = role_val
    if scopes:
        claims["scopes"] = list(scopes)
    if extra_claims:
        for k, v in extra_claims.items():
            if k not in {"sub", "type", "jti", "iat", "exp", "iss"}:
                claims[k] = v

    return jwt.encode(claims, cfg.secret_key, algorithm=cfg.jwt_algorithm)


def create_refresh_token(
    subject: str,
    *,
    org_id: str | None = None,
    role: str | Role | None = None,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
    settings: SecuritySettings | None = None,
) -> str:
    """Create a signed JWT refresh token."""
    cfg = settings or get_settings().security
    now = _utcnow()
    delta = expires_delta or timedelta(days=cfg.refresh_token_expire_days)
    exp = now + delta
    role_val = role.value if isinstance(role, Role) else role

    claims: dict[str, Any] = {
        "sub": subject,
        "type": TokenType.REFRESH.value,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": "netpulse",
    }
    if org_id is not None:
        claims["org_id"] = org_id
    if role_val is not None:
        claims["role"] = role_val
    if extra_claims:
        for k, v in extra_claims.items():
            if k not in {"sub", "type", "jti", "iat", "exp", "iss"}:
                claims[k] = v

    return jwt.encode(claims, cfg.secret_key, algorithm=cfg.jwt_algorithm)


def create_token_pair(
    subject: str,
    *,
    org_id: str | None = None,
    role: str | Role | None = None,
    scopes: Sequence[str] = (),
    settings: SecuritySettings | None = None,
) -> TokenPair:
    """Mint both an access token and a refresh token for a subject."""
    cfg = settings or get_settings().security
    access = create_access_token(
        subject, org_id=org_id, role=role, scopes=scopes, settings=cfg
    )
    refresh = create_refresh_token(subject, org_id=org_id, role=role, settings=cfg)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=cfg.access_token_expire_minutes * 60,
        refresh_expires_in=cfg.refresh_token_expire_days * 86400,
    )


def decode_token(
    token: str,
    *,
    expected_type: TokenType | None = None,
    check_revocation: bool = True,
    revocation_store: TokenRevocationStore | None = None,
    settings: SecuritySettings | None = None,
    leeway_seconds: int = 10,
) -> TokenPayload:
    """Decode, validate signature/expiry/type, and check revocation of a JWT."""
    if not token or not isinstance(token, str):
        raise AuthenticationError("Missing authentication token")

    cfg = settings or get_settings().security
    try:
        raw: dict[str, Any] = jwt.decode(
            token,
            cfg.secret_key,
            algorithms=[cfg.jwt_algorithm],
            leeway=leeway_seconds,
            options={"require": ["sub", "exp", "iat", "jti", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError(
            "Authentication token has expired",
            error_code="TOKEN_EXPIRED",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError(
            "Invalid authentication token",
            error_code="TOKEN_INVALID",
            details={"reason": str(exc)},
        ) from exc

    try:
        token_type = TokenType(raw["type"])
    except ValueError as exc:
        raise AuthenticationError("Unsupported token type", error_code="TOKEN_INVALID") from exc

    if expected_type is not None and token_type != expected_type:
        raise AuthenticationError(
            f"Expected {expected_type.value} token, received {token_type.value}",
            error_code="TOKEN_TYPE_MISMATCH",
        )

    sub = str(raw["sub"])
    jti = str(raw["jti"])
    iat_dt = datetime.fromtimestamp(float(raw["iat"]), tz=timezone.utc)
    exp_dt = datetime.fromtimestamp(float(raw["exp"]), tz=timezone.utc)

    if check_revocation:
        store = revocation_store or _default_revocation_store
        if store.is_revoked(jti, subject=sub, issued_at=iat_dt):
            raise AuthenticationError(
                "Authentication token has been revoked",
                error_code="TOKEN_REVOKED",
            )

    standard_keys = {"sub", "type", "jti", "iat", "exp", "iss", "org_id", "role", "scopes"}
    extra = {k: v for k, v in raw.items() if k not in standard_keys}
    raw_scopes = raw.get("scopes") or []

    return TokenPayload(
        sub=sub,
        token_type=token_type,
        jti=jti,
        iat=iat_dt,
        exp=exp_dt,
        org_id=raw.get("org_id"),
        role=raw.get("role"),
        scopes=tuple(str(s) for s in raw_scopes),
        extra=extra,
    )


def verify_access_token(
    token: str,
    *,
    revocation_store: TokenRevocationStore | None = None,
    settings: SecuritySettings | None = None,
) -> TokenPayload:
    """Verify and decode a JWT access token."""
    return decode_token(
        token,
        expected_type=TokenType.ACCESS,
        revocation_store=revocation_store,
        settings=settings,
    )


def verify_refresh_token(
    token: str,
    *,
    revocation_store: TokenRevocationStore | None = None,
    settings: SecuritySettings | None = None,
) -> TokenPayload:
    """Verify and decode a JWT refresh token."""
    return decode_token(
        token,
        expected_type=TokenType.REFRESH,
        revocation_store=revocation_store,
        settings=settings,
    )


def revoke_token(
    token: str,
    *,
    revocation_store: TokenRevocationStore | None = None,
    settings: SecuritySettings | None = None,
) -> str:
    """Decode a token (even if already near expiry) and add its JTI to the revocation store."""
    payload = decode_token(token, check_revocation=False, settings=settings)
    store = revocation_store or _default_revocation_store
    store.revoke(payload.jti, payload.exp)
    return payload.jti


# ---------------------------------------------------------------------------
# API Key generation & SHA-256 verification
# ---------------------------------------------------------------------------

_API_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


@dataclass(frozen=True)
class GeneratedAPIKey:
    """Newly generated API key; ``raw_key`` is shown once and never stored."""

    raw_key: str
    prefix: str
    key_hash: str
    display_hint: str


def hash_api_key(raw_key: str) -> str:
    """Return the hex-encoded SHA-256 digest of a raw API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key(
    *,
    prefix_length: int = 8,
    secret_length: int = 32,
    namespace: str | None = None,
) -> GeneratedAPIKey:
    """Generate a high-entropy API key formatted as ``npm_<prefix>_<secret>``."""
    ns = namespace if namespace is not None else get_settings().security.api_key_prefix
    if not ns.endswith("_"):
        ns = f"{ns}_"
    prefix_part = "".join(secrets.choice(_API_KEY_ALPHABET) for _ in range(prefix_length))
    secret_part = "".join(secrets.choice(_API_KEY_ALPHABET) for _ in range(secret_length))
    raw_key = f"{ns}{prefix_part}_{secret_part}"
    full_prefix = f"{ns}{prefix_part}"
    return GeneratedAPIKey(
        raw_key=raw_key,
        prefix=full_prefix,
        key_hash=hash_api_key(raw_key),
        display_hint=f"{full_prefix}_...{secret_part[-4:]}",
    )


def verify_api_key(raw_key: str, expected_hash: str) -> bool:
    """Verify a raw API key against its stored SHA-256 hex digest in constant time."""
    if not raw_key or not expected_hash:
        return False
    computed = hash_api_key(raw_key)
    return hmac.compare_digest(computed, expected_hash.lower())


def parse_api_key(raw_key: str, *, expected_namespace: str | None = None) -> tuple[str, str, str]:
    """Parse ``npm_<prefix>_<secret>`` into ``(namespace, prefix, secret)``."""
    ns = expected_namespace if expected_namespace is not None else get_settings().security.api_key_prefix
    if not ns.endswith("_"):
        ns = f"{ns}_"
    if not raw_key or not raw_key.startswith(ns):
        raise AuthenticationError("Malformed API key prefix", error_code="INVALID_API_KEY")
    remainder = raw_key[len(ns) :]
    if "_" not in remainder:
        raise AuthenticationError("Malformed API key structure", error_code="INVALID_API_KEY")
    prefix_part, secret_part = remainder.split("_", 1)
    if len(prefix_part) < 4 or len(secret_part) < 16:
        raise AuthenticationError("API key segment too short", error_code="INVALID_API_KEY")
    return ns.rstrip("_"), f"{ns}{prefix_part}", secret_part


# ---------------------------------------------------------------------------
# Fernet CredentialVault
# ---------------------------------------------------------------------------


def derive_fernet_key(secret: str | bytes) -> bytes:
    """Derive a valid 32-byte URL-safe base64 Fernet key via SHA-256."""
    raw_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    digest = hashlib.sha256(raw_bytes).digest()
    return base64.urlsafe_b64encode(digest)


class CredentialVault:
    """Fernet-backed encrypted secret vault for device credentials & sensitive payloads.

    Supports single-key encryption as well as multi-key decryption and seamless
    token rotation via :class:`cryptography.fernet.MultiFernet`.
    """

    def __init__(
        self,
        encryption_key: str | None = None,
        *,
        previous_keys: Sequence[str] = (),
    ) -> None:
        primary_secret = (
            encryption_key
            if encryption_key is not None
            else get_settings().security.encryption_key
        )
        if not primary_secret:
            raise VaultDecryptionError("Vault encryption key must not be empty")

        fernets = [Fernet(derive_fernet_key(primary_secret))]
        for old_secret in previous_keys:
            if old_secret:
                fernets.append(Fernet(derive_fernet_key(old_secret)))
        self._fernet = MultiFernet(fernets) if len(fernets) > 1 else fernets[0]
        self._is_multi = len(fernets) > 1

    def encrypt_str(self, plaintext: str) -> str:
        """Encrypt a UTF-8 string and return a URL-safe base64 Fernet token."""
        if not isinstance(plaintext, str):
            raise ValidationError("Plaintext must be a string")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt_str(self, ciphertext: str, *, ttl: int | None = None) -> str:
        """Decrypt a Fernet token back to a UTF-8 string."""
        if not ciphertext or not isinstance(ciphertext, str):
            raise VaultDecryptionError("Ciphertext must be a non-empty string")
        try:
            plaintext_bytes = self._fernet.decrypt(ciphertext.encode("ascii"), ttl=ttl)
            return plaintext_bytes.decode("utf-8")
        except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
            raise VaultDecryptionError(
                "Failed to decrypt vaulted credential",
                details={"reason": type(exc).__name__},
            ) from exc

    def encrypt_json(self, payload: dict[str, Any]) -> str:
        """Serialize a JSON dictionary and encrypt it with Fernet."""
        try:
            serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                "Credential payload is not JSON-serializable",
                details={"reason": str(exc)},
            ) from exc
        return self.encrypt_str(serialized)

    def decrypt_json(self, ciphertext: str, *, ttl: int | None = None) -> dict[str, Any]:
        """Decrypt a Fernet token and deserialize the underlying JSON object."""
        raw = self.decrypt_str(ciphertext, ttl=ttl)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VaultDecryptionError(
                "Decrypted credential payload is corrupted JSON",
                details={"reason": str(exc)},
            ) from exc
        if not isinstance(parsed, dict):
            raise VaultDecryptionError("Decrypted credential payload must be a JSON object")
        return parsed

    def rotate_token(self, ciphertext: str, *, target_vault: CredentialVault | None = None) -> str:
        """Re-encrypt an existing ciphertext under a new primary key.

        If ``target_vault`` is provided, decrypts using ``self`` and encrypts with
        ``target_vault``. Otherwise re-encrypts in-place using ``MultiFernet.rotate``
        (or decrypt+encrypt for single-key vaults).
        """
        if target_vault is not None:
            plaintext = self.decrypt_str(ciphertext)
            return target_vault.encrypt_str(plaintext)
        try:
            if self._is_multi and isinstance(self._fernet, MultiFernet):
                return self._fernet.rotate(ciphertext.encode("ascii")).decode("ascii")
            plaintext = self.decrypt_str(ciphertext)
            return self.encrypt_str(plaintext)
        except InvalidToken as exc:
            raise VaultDecryptionError("Failed to rotate vaulted token") from exc


_default_vault: CredentialVault | None = None


def get_credential_vault() -> CredentialVault:
    """Return a cached default :class:`CredentialVault` initialized from settings."""
    global _default_vault
    if _default_vault is None:
        _default_vault = CredentialVault()
    return _default_vault


def rotate_encrypted_payload(ciphertext: str, *, old_key: str, new_key: str) -> str:
    """One-shot key rotation helper transitioning ciphertext from ``old_key`` to ``new_key``."""
    old_vault = CredentialVault(encryption_key=old_key)
    new_vault = CredentialVault(encryption_key=new_key)
    return old_vault.rotate_token(ciphertext, target_vault=new_vault)


# ---------------------------------------------------------------------------
# RBAC Permissions & Role Matrix
# ---------------------------------------------------------------------------


class Permission(str, Enum):
    """Granular platform permissions across all NetPulse functional domains."""

    # Organization & IAM (7)
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    ORG_MANAGE_USERS = "org:manage_users"
    ORG_MANAGE_ROLES = "org:manage_roles"
    ORG_MANAGE_API_KEYS = "org:manage_api_keys"
    ORG_VIEW_BILLING = "org:view_billing"

    # Devices & Inventory (9)
    DEVICES_READ = "devices:read"
    DEVICES_CREATE = "devices:create"
    DEVICES_UPDATE = "devices:update"
    DEVICES_DELETE = "devices:delete"
    DEVICES_POLL = "devices:poll"
    DEVICES_DISCOVER = "devices:discover"
    DEVICES_MANAGE_CREDENTIALS = "devices:manage_credentials"
    DEVICES_EXECUTE_COMMANDS = "devices:execute_commands"
    DEVICES_EXPORT = "devices:export"

    # Telemetry, Logs & Flows (8)
    TELEMETRY_READ = "telemetry:read"
    TELEMETRY_WRITE = "telemetry:write"
    TELEMETRY_QUERY = "telemetry:query"
    TELEMETRY_EXPORT = "telemetry:export"
    TELEMETRY_MANAGE_RETENTION = "telemetry:manage_retention"
    SYSLOG_READ = "syslog:read"
    NETFLOW_READ = "netflow:read"
    SYNTHETICS_MANAGE = "synthetics:manage"

    # Alerts & Incidents (11)
    ALERTS_READ = "alerts:read"
    ALERTS_CREATE = "alerts:create"
    ALERTS_UPDATE = "alerts:update"
    ALERTS_DELETE = "alerts:delete"
    ALERTS_ACKNOWLEDGE = "alerts:acknowledge"
    ALERTS_SILENCE = "alerts:silence"
    ALERTS_RESOLVE = "alerts:resolve"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_RESOLVE = "incidents:resolve"
    NOTIFICATION_CHANNELS_MANAGE = "notifications:manage"

    # Topology & Discovery (4)
    TOPOLOGY_READ = "topology:read"
    TOPOLOGY_EDIT = "topology:edit"
    TOPOLOGY_DISCOVER = "topology:discover"
    TOPOLOGY_EXPORT = "topology:export"

    # Compliance & Configuration Management (8)
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_CREATE = "compliance:create"
    COMPLIANCE_UPDATE = "compliance:update"
    COMPLIANCE_DELETE = "compliance:delete"
    COMPLIANCE_AUDIT = "compliance:audit"
    COMPLIANCE_REMEDIATE = "compliance:remediate"
    CONFIG_BACKUP_READ = "config_backup:read"
    CONFIG_BACKUP_CREATE = "config_backup:create"

    # Playbooks & Automation (6)
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_CREATE = "playbooks:create"
    PLAYBOOKS_UPDATE = "playbooks:update"
    PLAYBOOKS_DELETE = "playbooks:delete"
    PLAYBOOKS_EXECUTE = "playbooks:execute"
    PLAYBOOKS_APPROVE = "playbooks:approve"

    # Platform Administration (6)
    ADMIN_SYSTEM_READ = "admin:system_read"
    ADMIN_SYSTEM_CONFIG = "admin:system_config"
    ADMIN_AUDIT_LOGS_READ = "admin:audit_logs_read"
    ADMIN_COLLECTORS_MANAGE = "admin:collectors_manage"
    ADMIN_TENANTS_MANAGE = "admin:tenants_manage"
    ADMIN_VAULT_ROTATE = "admin:vault_rotate"


class Role(str, Enum):
    """Built-in RBAC roles ordered from highest to most specialized privilege."""

    SUPER_ADMIN = "SUPER_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    NETOPS_ENGINEER = "NETOPS_ENGINEER"
    SRE_OPERATOR = "SRE_OPERATOR"
    SECURITY_AUDITOR = "SECURITY_AUDITOR"
    VIEWER = "VIEWER"
    AGENT = "AGENT"


_ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)

_VIEWER_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.ORG_READ,
        Permission.DEVICES_READ,
        Permission.TELEMETRY_READ,
        Permission.TELEMETRY_QUERY,
        Permission.SYSLOG_READ,
        Permission.NETFLOW_READ,
        Permission.ALERTS_READ,
        Permission.INCIDENTS_READ,
        Permission.TOPOLOGY_READ,
        Permission.COMPLIANCE_READ,
        Permission.CONFIG_BACKUP_READ,
        Permission.PLAYBOOKS_READ,
    }
)

_SECURITY_AUDITOR_PERMISSIONS: frozenset[Permission] = _VIEWER_PERMISSIONS | frozenset(
    {
        Permission.DEVICES_EXPORT,
        Permission.TELEMETRY_EXPORT,
        Permission.TOPOLOGY_EXPORT,
        Permission.COMPLIANCE_AUDIT,
        Permission.ADMIN_AUDIT_LOGS_READ,
        Permission.ADMIN_SYSTEM_READ,
    }
)

_SRE_OPERATOR_PERMISSIONS: frozenset[Permission] = _VIEWER_PERMISSIONS | frozenset(
    {
        Permission.DEVICES_POLL,
        Permission.TELEMETRY_EXPORT,
        Permission.SYNTHETICS_MANAGE,
        Permission.ALERTS_ACKNOWLEDGE,
        Permission.ALERTS_SILENCE,
        Permission.ALERTS_RESOLVE,
        Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE,
        Permission.INCIDENTS_RESOLVE,
        Permission.PLAYBOOKS_EXECUTE,
        Permission.CONFIG_BACKUP_CREATE,
        Permission.ADMIN_SYSTEM_READ,
    }
)

_NETOPS_ENGINEER_PERMISSIONS: frozenset[Permission] = _SRE_OPERATOR_PERMISSIONS | frozenset(
    {
        Permission.DEVICES_CREATE,
        Permission.DEVICES_UPDATE,
        Permission.DEVICES_DELETE,
        Permission.DEVICES_DISCOVER,
        Permission.DEVICES_MANAGE_CREDENTIALS,
        Permission.DEVICES_EXECUTE_COMMANDS,
        Permission.DEVICES_EXPORT,
        Permission.ALERTS_CREATE,
        Permission.ALERTS_UPDATE,
        Permission.ALERTS_DELETE,
        Permission.NOTIFICATION_CHANNELS_MANAGE,
        Permission.TOPOLOGY_EDIT,
        Permission.TOPOLOGY_DISCOVER,
        Permission.TOPOLOGY_EXPORT,
        Permission.COMPLIANCE_CREATE,
        Permission.COMPLIANCE_UPDATE,
        Permission.COMPLIANCE_DELETE,
        Permission.COMPLIANCE_AUDIT,
        Permission.COMPLIANCE_REMEDIATE,
        Permission.PLAYBOOKS_CREATE,
        Permission.PLAYBOOKS_UPDATE,
        Permission.PLAYBOOKS_DELETE,
        Permission.PLAYBOOKS_APPROVE,
        Permission.ADMIN_COLLECTORS_MANAGE,
    }
)

_ORG_ADMIN_PERMISSIONS: frozenset[Permission] = _NETOPS_ENGINEER_PERMISSIONS | frozenset(
    {
        Permission.ORG_UPDATE,
        Permission.ORG_MANAGE_USERS,
        Permission.ORG_MANAGE_ROLES,
        Permission.ORG_MANAGE_API_KEYS,
        Permission.ORG_VIEW_BILLING,
        Permission.TELEMETRY_WRITE,
        Permission.TELEMETRY_MANAGE_RETENTION,
        Permission.ADMIN_AUDIT_LOGS_READ,
    }
)

_AGENT_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.DEVICES_READ,
        Permission.DEVICES_POLL,
        Permission.DEVICES_DISCOVER,
        Permission.TELEMETRY_WRITE,
        Permission.TOPOLOGY_EDIT,
        Permission.CONFIG_BACKUP_CREATE,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SUPER_ADMIN: _ALL_PERMISSIONS,
    Role.ORG_ADMIN: _ORG_ADMIN_PERMISSIONS,
    Role.NETOPS_ENGINEER: _NETOPS_ENGINEER_PERMISSIONS,
    Role.SRE_OPERATOR: _SRE_OPERATOR_PERMISSIONS,
    Role.SECURITY_AUDITOR: _SECURITY_AUDITOR_PERMISSIONS,
    Role.VIEWER: _VIEWER_PERMISSIONS,
    Role.AGENT: _AGENT_PERMISSIONS,
}


def _coerce_role(role: Role | str) -> Role:
    if isinstance(role, Role):
        return role
    try:
        return Role(role.strip().upper())
    except ValueError as exc:
        raise AuthorizationError(
            f"Unknown RBAC role: {role!r}",
            details={"role": role},
        ) from exc


def _coerce_permission(permission: Permission | str) -> Permission:
    if isinstance(permission, Permission):
        return permission
    try:
        return Permission(permission)
    except ValueError as exc:
        raise AuthorizationError(
            f"Unknown permission: {permission!r}",
            details={"permission": permission},
        ) from exc


def get_role_permissions(role: Role | str) -> frozenset[Permission]:
    """Return the immutable permission set granted to ``role``."""
    return ROLE_PERMISSIONS[_coerce_role(role)]


def has_permission(
    role: Role | str,
    permission: Permission | str,
    *,
    extra_permissions: Iterable[Permission | str] = (),
) -> bool:
    """Return True if ``role`` (plus optional explicit grants) holds ``permission``."""
    try:
        target = _coerce_permission(permission)
        granted = set(get_role_permissions(role))
        for item in extra_permissions:
            granted.add(_coerce_permission(item))
        return target in granted
    except AuthorizationError:
        return False


def check_permission(
    role: Role | str,
    permission: Permission | str,
    *,
    extra_permissions: Iterable[Permission | str] = (),
    resource: str | None = None,
) -> None:
    """Assert ``role`` has ``permission`` or raise :class:`AuthorizationError`."""
    resolved_role = _coerce_role(role)
    resolved_perm = _coerce_permission(permission)
    if not has_permission(resolved_role, resolved_perm, extra_permissions=extra_permissions):
        details: dict[str, Any] = {
            "role": resolved_role.value,
            "required_permission": resolved_perm.value,
        }
        if resource:
            details["resource"] = resource
        raise AuthorizationError(
            f"Role '{resolved_role.value}' lacks required permission '{resolved_perm.value}'",
            details=details,
        )


def check_any_permission(
    role: Role | str,
    permissions: Sequence[Permission | str],
    *,
    extra_permissions: Iterable[Permission | str] = (),
) -> None:
    """Assert ``role`` has at least one of ``permissions``."""
    resolved_role = _coerce_role(role)
    resolved_perms = [_coerce_permission(p) for p in permissions]
    for perm in resolved_perms:
        if has_permission(resolved_role, perm, extra_permissions=extra_permissions):
            return
    raise AuthorizationError(
        f"Role '{resolved_role.value}' lacks any of the required permissions",
        details={
            "role": resolved_role.value,
            "required_any": [p.value for p in resolved_perms],
        },
    )


def check_all_permissions(
    role: Role | str,
    permissions: Sequence[Permission | str],
    *,
    extra_permissions: Iterable[Permission | str] = (),
) -> None:
    """Assert ``role`` holds every permission in ``permissions``."""
    resolved_role = _coerce_role(role)
    missing = [
        _coerce_permission(p).value
        for p in permissions
        if not has_permission(resolved_role, p, extra_permissions=extra_permissions)
    ]
    if missing:
        raise AuthorizationError(
            f"Role '{resolved_role.value}' is missing required permissions",
            details={"role": resolved_role.value, "missing_permissions": missing},
        )


# ---------------------------------------------------------------------------
# CIDR Allowlist / Denylist IP Checker
# ---------------------------------------------------------------------------

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_network_entry(entry: str) -> IPNetwork:
    cleaned = entry.strip()
    if not cleaned:
        raise ValidationError("CIDR entry must not be empty")
    try:
        return ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValidationError(
            f"Invalid IP or CIDR entry: {entry!r}",
            details={"entry": entry},
        ) from exc


class CIDRAllowlist:
    """IPv4/IPv6 CIDR allowlist with optional explicit denylist overrides.

    Evaluation precedence:
    1. If the IP matches any ``denylist`` network -> denied (``False``).
    2. If ``allowlist`` is empty -> ``default_allow`` (defaults to ``False``).
    3. Otherwise -> ``True`` iff the IP matches at least one ``allowlist`` network.
    """

    def __init__(
        self,
        allowlist: Iterable[str] = (),
        *,
        denylist: Iterable[str] = (),
        default_allow: bool = False,
    ) -> None:
        self._allow: tuple[IPNetwork, ...] = tuple(_parse_network_entry(e) for e in allowlist)
        self._deny: tuple[IPNetwork, ...] = tuple(_parse_network_entry(e) for e in denylist)
        self.default_allow = default_allow

    @property
    def allow_networks(self) -> tuple[str, ...]:
        return tuple(str(net) for net in self._allow)

    @property
    def deny_networks(self) -> tuple[str, ...]:
        return tuple(str(net) for net in self._deny)

    def is_allowed(self, ip_str: str) -> bool:
        """Return True if ``ip_str`` is permitted by this ACL."""
        try:
            addr: IPAddress = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.0.1 -> 10.0.0.1)
        candidates: list[IPAddress] = [addr]
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            candidates.append(addr.ipv4_mapped)

        for candidate in candidates:
            for denied_net in self._deny:
                if candidate.version == denied_net.version and candidate in denied_net:
                    return False

        if not self._allow:
            return self.default_allow

        for candidate in candidates:
            for allowed_net in self._allow:
                if candidate.version == allowed_net.version and candidate in allowed_net:
                    return True
        return False

    def assert_allowed(self, ip_str: str) -> None:
        """Raise :class:`AuthorizationError` if ``ip_str`` is not permitted."""
        if not self.is_allowed(ip_str):
            raise AuthorizationError(
                f"Client IP {ip_str!r} is not allowed by CIDR access policy",
                details={"client_ip": ip_str},
            )


def is_ip_allowed(
    ip_str: str,
    allowlist: Sequence[str],
    *,
    denylist: Sequence[str] = (),
    default_allow_when_empty: bool = True,
) -> bool:
    """Convenience helper checking whether ``ip_str`` matches ``allowlist`` (and not ``denylist``)."""
    acl = CIDRAllowlist(
        allowlist=allowlist,
        denylist=denylist,
        default_allow=default_allow_when_empty,
    )
    return acl.is_allowed(ip_str)


def extract_client_ip(
    direct_ip: str | None,
    *,
    x_forwarded_for: str | None = None,
    trusted_proxies: Sequence[str] = (),
) -> str | None:
    """Safely resolve client IP from ``X-Forwarded-For`` only when direct peer is trusted."""
    if not direct_ip:
        return None
    if not x_forwarded_for or not trusted_proxies:
        return direct_ip.strip()
    proxy_acl = CIDRAllowlist(allowlist=trusted_proxies, default_allow=False)
    if not proxy_acl.is_allowed(direct_ip):
        return direct_ip.strip()
    hops = [hop.strip() for hop in x_forwarded_for.split(",") if hop.strip()]
    for hop in reversed(hops):
        if not proxy_acl.is_allowed(hop):
            return hop
    return hops[0] if hops else direct_ip.strip()
