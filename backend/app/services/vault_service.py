"""Encrypted credential vault service for SNMP, SSH, API, NETCONF, and WMI profiles.

Implements :class:`VaultService` on top of :class:`~app.core.security.CredentialVault`
and :class:`~app.db.repositories.inventory.CredentialRepository`:

- **Encrypted CRUD**: Persists Fernet-encrypted JSON credential bundles in
  :class:`~app.models.inventory.CredentialProfile` with strict per-protocol
  schema validation (`snmp_v1`, `snmp_v2c`, `snmp_v3`, `ssh` / `ssh_password` /
  `ssh_key`, `api_token`, `netconf`, `wmi`, `winrm`, `basic_auth`, `oauth2`).
- **Zero-Leak Redaction**: All public read/list/create/update APIs return
  :meth:`VaultService.mask_credential_summary` dictionaries that NEVER expose
  plaintext secrets, SNMP communities, passphrases, SSH private keys, API tokens,
  or raw Fernet ciphertext.
- **Internal Collector Resolution**: :meth:`VaultService.resolve_decrypted_payload`
  decrypts credentials strictly within tenant scope for internal collectors and
  automation engines while recording an audit trail entry.
- **Batch Key Rotation**: :meth:`VaultService.rotate_org_credentials` performs
  verified re-encryption of an organization's vaulted profiles under a new master
  key with optional ``dry_run`` validation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ValidationError, VaultDecryptionError
from app.core.security import CredentialVault, get_credential_vault
from app.db.base import utcnow
from app.db.repositories.identity import AuditLogRepository
from app.db.repositories.inventory import CredentialRepository, DeviceRepository
from app.models.enums import (
    AuditAction,
    CredentialType,
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpVersion,
)
from app.models.inventory import CredentialProfile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Protocol Validation Rules
# ---------------------------------------------------------------------------

_META_KEY = "_vault_meta"

SECRET_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "community",
        "snmp_community",
        "password",
        "enable_secret",
        "auth_passphrase",
        "auth_password",
        "snmp_auth_password",
        "priv_passphrase",
        "priv_password",
        "snmp_priv_password",
        "private_key",
        "ssh_private_key",
        "passphrase",
        "ssh_passphrase",
        "token",
        "api_token",
        "client_secret",
        "secret_access_key",
        "private_key_pem",
    }
)

_SNMP_AUTH_ALIASES: dict[str, str] = {
    "none": SnmpAuthProtocol.NONE.value,
    "md5": SnmpAuthProtocol.MD5.value,
    "sha": SnmpAuthProtocol.SHA.value,
    "sha1": SnmpAuthProtocol.SHA.value,
    "sha224": SnmpAuthProtocol.SHA224.value,
    "sha256": SnmpAuthProtocol.SHA256.value,
    "sha384": SnmpAuthProtocol.SHA384.value,
    "sha512": SnmpAuthProtocol.SHA512.value,
}

_SNMP_PRIV_ALIASES: dict[str, str] = {
    "none": SnmpPrivProtocol.NONE.value,
    "des": SnmpPrivProtocol.DES.value,
    "3des": SnmpPrivProtocol.TRIPLE_DES.value,
    "triple_des": SnmpPrivProtocol.TRIPLE_DES.value,
    "aes": SnmpPrivProtocol.AES128.value,
    "aes128": SnmpPrivProtocol.AES128.value,
    "aes192": SnmpPrivProtocol.AES192.value,
    "aes256": SnmpPrivProtocol.AES256.value,
}

_SNMP_TYPE_TO_VERSION: dict[str, str] = {
    CredentialType.SNMP_V1.value: SnmpVersion.V1.value,
    CredentialType.SNMP_V2C.value: SnmpVersion.V2C.value,
    CredentialType.SNMP_V3.value: SnmpVersion.V3.value,
}


@dataclass(frozen=True)
class KeyRotationReport:
    """Outcome summary of an organization credential vault key rotation batch."""

    org_id: str
    dry_run: bool
    total_profiles: int
    rotated_count: int
    failed_count: int
    rotated_profile_ids: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    rotated_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "dry_run": self.dry_run,
            "total_profiles": self.total_profiles,
            "rotated_count": self.rotated_count,
            "failed_count": self.failed_count,
            "rotated_profile_ids": list(self.rotated_profile_ids),
            "errors": list(self.errors),
            "rotated_at": self.rotated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Pure Helpers (Fingerprinting, Redaction, Protocol Schema Validation)
# ---------------------------------------------------------------------------


def compute_secret_fingerprint(payload: Mapping[str, Any]) -> str:
    """Compute a non-reversible 16-hex SHA-256 fingerprint over secret fields for rotation tracking."""
    secret_subset = {
        k: v
        for k, v in sorted(payload.items())
        if k in SECRET_FIELD_NAMES and v is not None and str(v) != ""
    }
    canonical = json.dumps(secret_subset, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _mask_secret_hint(value: Any) -> str:
    """Return a strictly redacted mask string; never leaks short secrets."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    # Never expose hints for PEM private keys or short secrets
    if "PRIVATE KEY" in text or len(text) < 12:
        return "********"
    return f"****{text[-4:]}"


def resolve_credential_type(
    raw_type: str | CredentialType,
    payload: Mapping[str, Any] | None = None,
) -> CredentialType:
    """Normalize a credential type string, mapping generic ``ssh`` to ``ssh_key`` or ``ssh_password``."""
    if isinstance(raw_type, CredentialType):
        return raw_type
    cleaned = str(raw_type).strip().lower()
    if cleaned == "ssh":
        data = payload or {}
        if data.get("private_key") or data.get("ssh_private_key") or data.get("private_key_id"):
            return CredentialType.SSH_KEY
        return CredentialType.SSH_PASSWORD
    try:
        return CredentialType(cleaned)
    except ValueError as exc:
        valid = [c.value for c in CredentialType] + ["ssh"]
        raise ValidationError(
            f"Unsupported credential_type {raw_type!r}",
            details={"credential_type": raw_type, "allowed": valid},
        ) from exc


def validate_credential_payload(
    credential_type: str | CredentialType,
    raw_payload: Mapping[str, Any],
) -> tuple[CredentialType, dict[str, Any]]:
    """Validate and canonicalize a credential payload according to its protocol schema.

    Supports:
    - ``snmp_v1`` / ``snmp_v2c``: requires ``community`` (alias ``snmp_community``)
    - ``snmp_v3``: requires ``username``, validates ``auth_protocol`` / ``auth_passphrase``
      and ``priv_protocol`` / ``priv_passphrase`` consistency
    - ``ssh`` / ``ssh_password`` / ``ssh_key``: requires ``username`` plus ``password`` or key
    - ``api_token``: requires ``token`` (alias ``api_token``)
    - ``netconf``: requires ``username`` plus ``password`` or ``private_key``
    - ``wmi`` / ``winrm``: requires ``username`` and ``password``
    - ``basic_auth`` / ``oauth2`` / ``certificate``
    """
    if not isinstance(raw_payload, Mapping):
        raise ValidationError("Credential payload must be a JSON object")

    data = {k: v for k, v in raw_payload.items() if k != _META_KEY}
    resolved_type = resolve_credential_type(credential_type, data)
    errors: list[str] = []
    normalized: dict[str, Any] = {}

    if resolved_type in {CredentialType.SNMP_V1, CredentialType.SNMP_V2C}:
        community = str(data.get("community") or data.get("snmp_community") or "").strip()
        if not community:
            errors.append(f"{resolved_type.value} requires non-empty 'community' (or 'snmp_community')")
        normalized["community"] = community
        if data.get("context_name") or data.get("snmp_context_name"):
            normalized["context_name"] = str(data.get("context_name") or data.get("snmp_context_name")).strip()

    elif resolved_type == CredentialType.SNMP_V3:
        username = str(data.get("username") or "").strip()
        if not username:
            errors.append("snmp_v3 requires non-empty 'username'")

        auth_raw = str(data.get("auth_protocol") or data.get("snmp_auth_protocol") or "none").strip().lower()
        if auth_raw not in _SNMP_AUTH_ALIASES:
            errors.append(f"Unsupported SNMPv3 auth_protocol {auth_raw!r}")
            auth_proto = SnmpAuthProtocol.NONE.value
        else:
            auth_proto = _SNMP_AUTH_ALIASES[auth_raw]

        auth_pass = str(
            data.get("auth_passphrase")
            or data.get("snmp_auth_password")
            or data.get("auth_password")
            or ""
        )

        priv_raw = str(data.get("priv_protocol") or data.get("snmp_priv_protocol") or "none").strip().lower()
        if priv_raw not in _SNMP_PRIV_ALIASES:
            errors.append(f"Unsupported SNMPv3 priv_protocol {priv_raw!r}")
            priv_proto = SnmpPrivProtocol.NONE.value
        else:
            priv_proto = _SNMP_PRIV_ALIASES[priv_raw]

        priv_pass = str(
            data.get("priv_passphrase")
            or data.get("snmp_priv_password")
            or data.get("priv_password")
            or ""
        )

        if auth_proto != SnmpAuthProtocol.NONE.value:
            if not auth_pass:
                errors.append("snmp_v3 auth_protocol requires 'auth_passphrase'")
            elif len(auth_pass) < 8:
                errors.append("snmp_v3 'auth_passphrase' must be at least 8 characters (RFC 3414)")

        if priv_proto != SnmpPrivProtocol.NONE.value:
            if auth_proto == SnmpAuthProtocol.NONE.value:
                errors.append("snmp_v3 privacy encryption requires an auth_protocol (authPriv)")
            if not priv_pass:
                errors.append("snmp_v3 priv_protocol requires 'priv_passphrase'")
            elif len(priv_pass) < 8:
                errors.append("snmp_v3 'priv_passphrase' must be at least 8 characters (RFC 3414)")

        if priv_proto != SnmpPrivProtocol.NONE.value:
            security_level = "authPriv"
        elif auth_proto != SnmpAuthProtocol.NONE.value:
            security_level = "authNoPriv"
        else:
            security_level = "noAuthNoPriv"

        normalized.update(
            {
                "username": username,
                "security_level": security_level,
                "auth_protocol": auth_proto,
                "priv_protocol": priv_proto,
            }
        )
        if auth_pass:
            normalized["auth_passphrase"] = auth_pass
        if priv_pass:
            normalized["priv_passphrase"] = priv_pass
        ctx = data.get("context_name") or data.get("snmp_context_name")
        if ctx:
            normalized["context_name"] = str(ctx).strip()
        if data.get("engine_id"):
            normalized["engine_id"] = str(data["engine_id"]).strip()

    elif resolved_type == CredentialType.SSH_PASSWORD:
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        if not username:
            errors.append("ssh_password requires non-empty 'username'")
        if not password:
            errors.append("ssh_password requires non-empty 'password'")
        normalized["username"] = username
        normalized["password"] = password
        if data.get("enable_secret"):
            normalized["enable_secret"] = str(data["enable_secret"])
        if data.get("device_type"):
            normalized["device_type"] = str(data["device_type"]).strip()

    elif resolved_type == CredentialType.SSH_KEY:
        username = str(data.get("username") or "").strip()
        private_key = str(data.get("private_key") or data.get("ssh_private_key") or "").strip()
        private_key_id = str(data.get("private_key_id") or "").strip()
        if not username:
            errors.append("ssh_key requires non-empty 'username'")
        if not private_key and not private_key_id:
            errors.append("ssh_key requires 'private_key' (or 'ssh_private_key' / 'private_key_id')")
        normalized["username"] = username
        if private_key:
            normalized["private_key"] = private_key
        if private_key_id:
            normalized["private_key_id"] = private_key_id
        passphrase = data.get("passphrase") or data.get("ssh_passphrase")
        if passphrase:
            normalized["passphrase"] = str(passphrase)
        if data.get("enable_secret"):
            normalized["enable_secret"] = str(data["enable_secret"])

    elif resolved_type == CredentialType.API_TOKEN:
        token = str(data.get("token") or data.get("api_token") or "").strip()
        if not token:
            errors.append("api_token requires non-empty 'token' (or 'api_token')")
        normalized["token"] = token
        normalized["header_name"] = str(data.get("header_name") or "Authorization").strip()
        normalized["token_prefix"] = str(data.get("token_prefix", "Bearer")).strip()
        normalized["verify_ssl"] = bool(data.get("verify_ssl", True))
        if data.get("base_url"):
            normalized["base_url"] = str(data["base_url"]).strip()

    elif resolved_type == CredentialType.NETCONF:
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        private_key = str(data.get("private_key") or data.get("ssh_private_key") or "").strip()
        if not username:
            errors.append("netconf requires non-empty 'username'")
        if not password and not private_key:
            errors.append("netconf requires either 'password' or 'private_key'")
        normalized["username"] = username
        if password:
            normalized["password"] = password
        if private_key:
            normalized["private_key"] = private_key
        normalized["hostkey_verify"] = bool(data.get("hostkey_verify", False))
        if data.get("device_params"):
            normalized["device_params"] = dict(data["device_params"])

    elif resolved_type in {CredentialType.WMI, CredentialType.WINRM}:
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        if not username:
            errors.append(f"{resolved_type.value} requires non-empty 'username'")
        if not password:
            errors.append(f"{resolved_type.value} requires non-empty 'password'")
        normalized["username"] = username
        normalized["password"] = password
        if data.get("domain"):
            normalized["domain"] = str(data["domain"]).strip()
        if resolved_type == CredentialType.WMI:
            normalized["namespace"] = str(data.get("namespace") or r"root\cimv2").strip()
        else:
            transport = str(data.get("transport") or "ntlm").strip().lower()
            if transport not in {"ntlm", "kerberos", "basic", "credssp", "certificate"}:
                errors.append(f"Unsupported WinRM transport {transport!r}")
            normalized["transport"] = transport
            normalized["use_ssl"] = bool(data.get("use_ssl", True))

    elif resolved_type == CredentialType.BASIC_AUTH:
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        if not username or not password:
            errors.append("basic_auth requires both 'username' and 'password'")
        normalized["username"] = username
        normalized["password"] = password
        normalized["verify_ssl"] = bool(data.get("verify_ssl", True))

    elif resolved_type == CredentialType.OAUTH2:
        client_id = str(data.get("client_id") or "").strip()
        client_secret = str(data.get("client_secret") or "").strip()
        token_url = str(data.get("token_url") or "").strip()
        if not client_id or not client_secret or not token_url:
            errors.append("oauth2 requires 'client_id', 'client_secret', and 'token_url'")
        normalized.update(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "token_url": token_url,
            }
        )
        if data.get("scope"):
            normalized["scope"] = str(data["scope"]).strip()

    else:
        # Remaining cloud / certificate credential types: require at least one non-empty field
        if not any(v not in (None, "", []) for v in data.values()):
            errors.append(f"{resolved_type.value} requires at least one credential attribute")
        normalized = dict(data)

    if errors:
        raise ValidationError(
            f"Invalid {resolved_type.value} credential payload: {'; '.join(errors)}",
            details={"credential_type": resolved_type.value, "errors": errors},
        )

    return resolved_type, normalized


# ---------------------------------------------------------------------------
# VaultService
# ---------------------------------------------------------------------------


class VaultService:
    """Tenant-scoped encrypted credential vault service.

    Security guarantees:
    1. Secrets are always encrypted with Fernet before touching the database.
    2. Public metadata views (:meth:`mask_credential_summary`) strip all secret
       values and ``encrypted_payload``.
    3. Collector decryption (:meth:`resolve_decrypted_payload`) enforces tenant
       isolation and records an audit trail entry.
    """

    def __init__(
        self,
        db: Session,
        *,
        vault: CredentialVault | None = None,
    ) -> None:
        self.db = db
        self._vault = vault or get_credential_vault()
        self.credentials = CredentialRepository(db)
        self.devices = DeviceRepository(db)
        self.audit_logs = AuditLogRepository(db)

    def _record_audit(
        self,
        *,
        org_id: str,
        action: AuditAction,
        profile_id: str | None,
        summary: str,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self.audit_logs.record(
                org_id=org_id,
                action=action.value,
                resource_type="credential_profile",
                resource_id=profile_id,
                summary=summary,
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                details=details,
                flush=False,
            )
        except Exception as exc:  # pragma: no cover
            logger.debug("Skipping credential audit log: %s", exc)

    def _clear_defaults_for_type(
        self,
        org_id: str,
        credential_type: str,
        *,
        exclude_profile_id: str | None = None,
    ) -> None:
        """Ensure at most one default profile exists per credential type within an org."""
        profiles = self.credentials.list(
            filters={"credential_type": credential_type, "is_default": True},
            org_id=org_id,
        )
        for prof in profiles:
            if exclude_profile_id is not None and prof.id == exclude_profile_id:
                continue
            self.credentials.update(prof, {"is_default": False}, org_id=org_id, flush=False)

    # -----------------------------------------------------------------------
    # Redacted Metadata View (NEVER returns secrets!)
    # -----------------------------------------------------------------------

    def mask_credential_summary(
        self,
        profile: CredentialProfile,
        *,
        attached_device_count: int | None = None,
        decrypt_metadata: bool = True,
    ) -> dict[str, Any]:
        """Build a safe, redacted metadata representation of a credential profile.

        SECURITY INVARIANT: This method NEVER includes ``encrypted_payload`` or any
        plaintext secret values (passwords, SNMP communities, auth/priv passphrases,
        SSH private keys, or API tokens).
        """
        device_count = (
            attached_device_count
            if attached_device_count is not None
            else self.credentials.count_assigned_devices(profile.id, org_id=profile.org_id)
        )

        summary: dict[str, Any] = {
            "id": profile.id,
            "org_id": profile.org_id,
            "name": profile.name,
            "description": profile.description,
            "credential_type": profile.credential_type,
            "snmp_version": profile.snmp_version,
            "port": profile.port,
            "timeout_seconds": profile.timeout_seconds,
            "retries": profile.retries,
            "is_default": profile.is_default,
            "has_secret": bool(profile.encrypted_payload),
            "username": None,
            "snmp_auth_protocol": SnmpAuthProtocol.NONE.value,
            "snmp_priv_protocol": SnmpPrivProtocol.NONE.value,
            "snmp_security_level": None,
            "snmp_context_name": None,
            "has_password": False,
            "has_enable_secret": False,
            "has_snmp_community": False,
            "has_snmp_auth_password": False,
            "has_snmp_priv_password": False,
            "has_ssh_private_key": False,
            "has_api_token": False,
            "masked_fields": {},
            "secret_fingerprint": None,
            "last_rotated_at": None,
            "rotation_count": 0,
            "attached_device_count": device_count,
            "decryption_status": "ok",
            "created_at": profile.created_at.isoformat() if profile.created_at else None,
            "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
        }

        if not decrypt_metadata or not profile.encrypted_payload:
            return summary

        try:
            payload = self._vault.decrypt_json(profile.encrypted_payload)
        except VaultDecryptionError:
            summary["decryption_status"] = "unavailable"
            return summary

        meta = payload.get(_META_KEY) if isinstance(payload.get(_META_KEY), Mapping) else {}
        summary["username"] = payload.get("username")
        summary["snmp_auth_protocol"] = payload.get("auth_protocol", SnmpAuthProtocol.NONE.value)
        summary["snmp_priv_protocol"] = payload.get("priv_protocol", SnmpPrivProtocol.NONE.value)
        summary["snmp_security_level"] = payload.get("security_level")
        summary["snmp_context_name"] = payload.get("context_name")

        summary["has_password"] = bool(payload.get("password"))
        summary["has_enable_secret"] = bool(payload.get("enable_secret"))
        summary["has_snmp_community"] = bool(payload.get("community") or payload.get("snmp_community"))
        summary["has_snmp_auth_password"] = bool(
            payload.get("auth_passphrase") or payload.get("snmp_auth_password")
        )
        summary["has_snmp_priv_password"] = bool(
            payload.get("priv_passphrase") or payload.get("snmp_priv_password")
        )
        summary["has_ssh_private_key"] = bool(
            payload.get("private_key") or payload.get("ssh_private_key") or payload.get("private_key_id")
        )
        summary["has_api_token"] = bool(payload.get("token") or payload.get("api_token"))

        masked: dict[str, str] = {}
        for key, val in payload.items():
            if key == _META_KEY or val in (None, ""):
                continue
            if key in SECRET_FIELD_NAMES:
                masked[key] = _mask_secret_hint(val)
        summary["masked_fields"] = masked

        # Include safe non-secret connection hints
        for safe_key in ("domain", "namespace", "transport", "header_name", "token_prefix", "verify_ssl", "use_ssl"):
            if safe_key in payload:
                summary[safe_key] = payload[safe_key]

        summary["secret_fingerprint"] = meta.get("fingerprint") or compute_secret_fingerprint(payload)
        summary["last_rotated_at"] = meta.get("last_rotated_at")
        summary["rotation_count"] = int(meta.get("rotation_count", 0))
        return summary

    # -----------------------------------------------------------------------
    # Encrypted CredentialProfile CRUD
    # -----------------------------------------------------------------------

    def create_profile(
        self,
        org_id: str,
        *,
        name: str,
        credential_type: str | CredentialType,
        payload: Mapping[str, Any],
        description: str | None = None,
        snmp_version: str | SnmpVersion | None = None,
        port: int | None = None,
        timeout_seconds: float = 3.0,
        retries: int = 2,
        is_default: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> dict[str, Any]:
        """Validate, encrypt, and persist a new credential profile, returning a redacted summary."""
        cleaned_name = name.strip()
        if len(cleaned_name) < 2:
            raise ValidationError("Credential profile name must be at least 2 characters long")

        if self.credentials.get_by_name(cleaned_name, org_id=org_id) is not None:
            raise ConflictError(
                f"Credential profile '{cleaned_name}' already exists in this organization",
                details={"name": cleaned_name, "org_id": org_id},
            )

        resolved_type, validated_payload = validate_credential_payload(credential_type, payload)

        effective_port = int(port) if port is not None else resolved_type.default_port
        if not (1 <= effective_port <= 65535):
            raise ValidationError("Credential port must be between 1 and 65535", details={"port": effective_port})
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValidationError("timeout_seconds must be between 0 and 300")
        if not (0 <= retries <= 10):
            raise ValidationError("retries must be between 0 and 10")

        effective_snmp_version: str | None = None
        if resolved_type.value in _SNMP_TYPE_TO_VERSION:
            effective_snmp_version = _SNMP_TYPE_TO_VERSION[resolved_type.value]
        elif snmp_version is not None:
            effective_snmp_version = (
                snmp_version.value if isinstance(snmp_version, SnmpVersion) else str(snmp_version).strip().lower()
            )

        now_iso = utcnow().isoformat()
        envelope = dict(validated_payload)
        envelope[_META_KEY] = {
            "schema_version": 1,
            "created_at": now_iso,
            "last_rotated_at": now_iso,
            "rotation_count": 0,
            "fingerprint": compute_secret_fingerprint(validated_payload),
        }
        ciphertext = self._vault.encrypt_json(envelope)

        if is_default:
            self._clear_defaults_for_type(org_id, resolved_type.value)

        profile = self.credentials.create(
            {
                "name": cleaned_name,
                "description": description,
                "credential_type": resolved_type.value,
                "snmp_version": effective_snmp_version,
                "encrypted_payload": ciphertext,
                "port": effective_port,
                "timeout_seconds": float(timeout_seconds),
                "retries": int(retries),
                "is_default": bool(is_default),
            },
            org_id=org_id,
        )

        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREATE,
            profile_id=profile.id,
            summary=f"Created encrypted credential profile '{profile.name}' ({profile.credential_type})",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            details={"credential_type": profile.credential_type, "port": profile.port},
        )
        return self.mask_credential_summary(profile, attached_device_count=0)

    def get_profile(self, profile_id: str, org_id: str) -> dict[str, Any]:
        """Fetch a single credential profile as a redacted metadata summary."""
        profile = self.credentials.get_by_id_or_raise(profile_id, org_id=org_id)
        return self.mask_credential_summary(profile)

    def get_profile_model(self, profile_id: str, org_id: str) -> CredentialProfile:
        """Fetch the underlying ORM model (internal helper)."""
        return self.credentials.get_by_id_or_raise(profile_id, org_id=org_id)

    def list_profiles(
        self,
        org_id: str,
        *,
        credential_type: str | CredentialType | None = None,
    ) -> list[dict[str, Any]]:
        """List all credential profiles for an organization as redacted metadata views."""
        if credential_type is not None:
            resolved = resolve_credential_type(credential_type)
            profiles = self.credentials.list(
                filters={"credential_type": resolved.value},
                org_id=org_id,
            )
        else:
            profiles = self.credentials.list(org_id=org_id)
        return [self.mask_credential_summary(p) for p in profiles]

    def update_profile(
        self,
        profile_id: str,
        org_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        payload_patch: Mapping[str, Any] | None = None,
        port: int | None = None,
        timeout_seconds: float | None = None,
        retries: int | None = None,
        is_default: bool | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> dict[str, Any]:
        """Partially update a credential profile; omitted secret fields remain unchanged."""
        profile = self.credentials.get_by_id_or_raise(profile_id, org_id=org_id)
        patch: dict[str, Any] = {}
        secret_changed = False

        if name is not None:
            cleaned = name.strip()
            if len(cleaned) < 2:
                raise ValidationError("Credential profile name must be at least 2 characters long")
            existing = self.credentials.get_by_name(cleaned, org_id=org_id)
            if existing is not None and existing.id != profile.id:
                raise ConflictError(f"Credential profile '{cleaned}' already exists")
            patch["name"] = cleaned

        if description is not None:
            patch["description"] = description
        if port is not None:
            if not (1 <= int(port) <= 65535):
                raise ValidationError("Port must be between 1 and 65535")
            patch["port"] = int(port)
        if timeout_seconds is not None:
            if timeout_seconds <= 0 or timeout_seconds > 300:
                raise ValidationError("timeout_seconds must be between 0 and 300")
            patch["timeout_seconds"] = float(timeout_seconds)
        if retries is not None:
            if not (0 <= int(retries) <= 10):
                raise ValidationError("retries must be between 0 and 10")
            patch["retries"] = int(retries)
        if is_default is not None:
            if is_default:
                self._clear_defaults_for_type(org_id, profile.credential_type, exclude_profile_id=profile.id)
            patch["is_default"] = bool(is_default)

        if payload_patch is not None:
            current_raw = self._vault.decrypt_json(profile.encrypted_payload)
            old_meta = dict(current_raw.get(_META_KEY) or {})
            merged = {k: v for k, v in current_raw.items() if k != _META_KEY}
            for k, v in payload_patch.items():
                if k == _META_KEY:
                    continue
                if v is not None:
                    merged[k] = v

            _, validated = validate_credential_payload(profile.credential_type, merged)
            old_fp = old_meta.get("fingerprint") or compute_secret_fingerprint(current_raw)
            new_fp = compute_secret_fingerprint(validated)
            secret_changed = old_fp != new_fp

            now_iso = utcnow().isoformat()
            envelope = dict(validated)
            envelope[_META_KEY] = {
                "schema_version": 1,
                "created_at": old_meta.get("created_at", now_iso),
                "last_rotated_at": now_iso if secret_changed else old_meta.get("last_rotated_at", now_iso),
                "rotation_count": int(old_meta.get("rotation_count", 0)) + (1 if secret_changed else 0),
                "fingerprint": new_fp,
            }
            patch["encrypted_payload"] = self._vault.encrypt_json(envelope)

        updated = self.credentials.update(profile, patch, org_id=org_id) if patch else profile
        self._record_audit(
            org_id=org_id,
            action=AuditAction.CREDENTIAL_ROTATE if secret_changed else AuditAction.UPDATE,
            profile_id=updated.id,
            summary=f"Updated credential profile '{updated.name}'",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            details={"secret_changed": secret_changed},
        )
        return self.mask_credential_summary(updated)

    def delete_profile(
        self,
        profile_id: str,
        org_id: str,
        *,
        force: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> bool:
        """Soft-delete a credential profile; rejects if devices reference it unless ``force=True``."""
        profile = self.credentials.get_by_id_or_raise(profile_id, org_id=org_id)
        assigned = self.credentials.count_assigned_devices(profile.id, org_id=org_id)
        if assigned > 0 and not force:
            raise ConflictError(
                f"Credential profile '{profile.name}' is still assigned to {assigned} active device(s)",
                details={"profile_id": profile.id, "assigned_devices": assigned},
            )
        if assigned > 0 and force:
            for dev in self.devices.list(filters={"credential_profile_id": profile.id}, org_id=org_id):
                self.devices.update(dev, {"credential_profile_id": None}, org_id=org_id)

        self.credentials.soft_delete(profile, org_id=org_id)
        self._record_audit(
            org_id=org_id,
            action=AuditAction.DELETE,
            profile_id=profile.id,
            summary=f"Deleted credential profile '{profile.name}'",
            actor_user_id=actor_user_id,
            actor_email=actor_email,
        )
        return True

    # -----------------------------------------------------------------------
    # Internal-Only Collector Decryption
    # -----------------------------------------------------------------------

    def resolve_decrypted_payload(
        self,
        profile_id: str,
        org_id: str,
        *,
        caller: str = "collector",
        audit: bool = True,
    ) -> dict[str, Any]:
        """INTERNAL-ONLY: Decrypt a credential profile for collector/automation execution.

        NEVER expose the returned dictionary directly through HTTP API responses.
        """
        profile = self.credentials.get_by_id_or_raise(profile_id, org_id=org_id)
        decrypted = self._vault.decrypt_json(profile.encrypted_payload)
        clean_secrets = {k: v for k, v in decrypted.items() if k != _META_KEY}

        if audit:
            self._record_audit(
                org_id=org_id,
                action=AuditAction.CREDENTIAL_ACCESS,
                profile_id=profile.id,
                summary=f"Resolved vaulted credential '{profile.name}' for {caller}",
                details={"caller": caller, "credential_type": profile.credential_type},
            )

        return {
            "profile_id": profile.id,
            "org_id": profile.org_id,
            "name": profile.name,
            "credential_type": profile.credential_type,
            "snmp_version": profile.snmp_version,
            "port": profile.port,
            "timeout_seconds": profile.timeout_seconds,
            "retries": profile.retries,
            "credentials": clean_secrets,
        }

    # -----------------------------------------------------------------------
    # Key Rotation Batch Utility & Vault Health Check
    # -----------------------------------------------------------------------

    def rotate_org_credentials(
        self,
        org_id: str,
        *,
        new_encryption_key: str,
        old_encryption_key: str | None = None,
        dry_run: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> KeyRotationReport:
        """Batch re-encrypt all credential profiles in an organization under ``new_encryption_key``.

        Each rotated payload is round-trip verified against ``new_encryption_key``
        before persistence. When ``dry_run=True``, verifies decryptability and
        re-encryption in memory without mutating database records.
        """
        if not new_encryption_key or len(new_encryption_key.strip()) < 16:
            raise ValidationError("new_encryption_key must be at least 16 characters long")

        source_vault = (
            CredentialVault(encryption_key=old_encryption_key)
            if old_encryption_key is not None
            else self._vault
        )
        target_vault = CredentialVault(encryption_key=new_encryption_key)

        profiles = self.credentials.list(org_id=org_id)
        rotated_ids: list[str] = []
        errors: list[dict[str, str]] = []
        now = utcnow()
        now_iso = now.isoformat()

        for profile in profiles:
            try:
                decrypted = source_vault.decrypt_json(profile.encrypted_payload)
                meta = dict(decrypted.get(_META_KEY) or {})
                clean_payload = {k: v for k, v in decrypted.items() if k != _META_KEY}
                meta["last_rotated_at"] = now_iso
                meta["rotation_count"] = int(meta.get("rotation_count", 0)) + 1
                meta["fingerprint"] = compute_secret_fingerprint(clean_payload)
                envelope = {**clean_payload, _META_KEY: meta}

                new_ciphertext = target_vault.encrypt_json(envelope)
                # Round-trip integrity verification before saving
                verified = target_vault.decrypt_json(new_ciphertext)
                if verified.get(_META_KEY, {}).get("fingerprint") != meta["fingerprint"]:
                    raise VaultDecryptionError("Post-rotation fingerprint verification mismatch")

                if not dry_run:
                    self.credentials.mark_rotated(
                        profile.id,
                        encrypted_payload=new_ciphertext,
                        org_id=org_id,
                        flush=False,
                    )
                rotated_ids.append(profile.id)
            except Exception as exc:
                errors.append(
                    {
                        "profile_id": profile.id,
                        "name": profile.name,
                        "error": str(exc),
                    }
                )

        if not dry_run and rotated_ids:
            self.db.flush()
            self._record_audit(
                org_id=org_id,
                action=AuditAction.CREDENTIAL_ROTATE,
                profile_id=None,
                summary=f"Batch rotated {len(rotated_ids)}/{len(profiles)} credential profiles",
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                details={
                    "total_profiles": len(profiles),
                    "rotated_count": len(rotated_ids),
                    "failed_count": len(errors),
                },
            )

        return KeyRotationReport(
            org_id=org_id,
            dry_run=dry_run,
            total_profiles=len(profiles),
            rotated_count=len(rotated_ids),
            failed_count=len(errors),
            rotated_profile_ids=rotated_ids,
            errors=errors,
            rotated_at=now,
        )

    def verify_org_vault_health(self, org_id: str) -> dict[str, Any]:
        """Verify that every active credential profile in an organization decrypts cleanly."""
        profiles = self.credentials.list(org_id=org_id)
        healthy = 0
        unhealthy: list[dict[str, str]] = []
        for profile in profiles:
            try:
                self._vault.decrypt_json(profile.encrypted_payload)
                healthy += 1
            except VaultDecryptionError as exc:
                unhealthy.append({"profile_id": profile.id, "name": profile.name, "error": exc.message})
        return {
            "org_id": org_id,
            "total_profiles": len(profiles),
            "healthy_count": healthy,
            "unhealthy_count": len(unhealthy),
            "unhealthy_profiles": unhealthy,
        }


__all__ = [
    "KeyRotationReport",
    "SECRET_FIELD_NAMES",
    "VaultService",
    "compute_secret_fingerprint",
    "resolve_credential_type",
    "validate_credential_payload",
]
