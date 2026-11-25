"""Bulk CMDB inventory import/export service supporting JSON, CSV, and NetBox formats.

Implements :class:`ImportExportService`:
- **Bulk Device Importer**: Accepts JSON arrays/strings or CSV text with
  ``dry_run`` validation mode, configurable conflict resolution
  (``skip``, ``update``, ``error``), per-row validation error reporting,
  automatic site code / rack / credential profile resolution, IP/MAC
  normalization, OUI vendor inference, quota enforcement, and structured
  :class:`BulkImportReport`.
- **Bulk Subnet Importer**: Imports IPv4/IPv6 IPAM subnets from CSV or JSON
  with CIDR normalization, gateway containment checks, cross-DB & intra-batch
  overlap detection, site code resolution, and conflict handling.
- **Full Inventory Exporter**: Produces tenant-scoped inventory exports in
  ``json``, ``csv``, and ``netbox_json`` (NetBox v3/v4 DCIM + IPAM schema)
  formats while strictly omitting all vaulted credential secrets.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NetPulseError, ValidationError
from app.core.network_utils import (
    cidrs_overlap,
    format_mac,
    ip_in_cidr,
    is_valid_cidr,
    is_valid_ip,
    is_valid_mac,
    normalize_ip,
    parse_network,
)
from app.db.base import utcnow
from app.db.repositories.identity import AuditLogRepository
from app.models.enums import AuditAction, DeviceStatus, DeviceType, DeviceVendor, InterfaceType
from app.models.inventory import Device, DeviceInterface, IpAllocation, Rack, Site, Subnet, Vlan
from app.services.inventory_service import (
    InventoryService,
    infer_vendor_from_mac,
    normalize_device_status,
    normalize_device_type,
    normalize_device_vendor,
    normalize_tags,
)

logger = logging.getLogger(__name__)

ConflictStrategy = Literal["skip", "update", "error"]
ImportFormat = Literal["auto", "json", "csv"]
ExportFormat = Literal["json", "csv", "netbox_json"]
CsvExportEntity = Literal["devices", "subnets", "sites", "interfaces", "vlans", "ip_allocations"]

# ---------------------------------------------------------------------------
# Structured Report & Export Result Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BulkImportRowIssue:
    """Single-row validation, conflict, or persistence error encountered during bulk import."""

    row_index: int
    identifier: str | None
    error_code: str
    message: str
    field: str | None = None
    secondary_identifier: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_index": self.row_index,
            "identifier": self.identifier,
            "secondary_identifier": self.secondary_identifier,
            "error_code": self.error_code,
            "field": self.field,
            "message": self.message,
        }


@dataclass
class BulkImportReport:
    """Detailed outcome report for a bulk device or subnet import operation."""

    entity_type: str
    dry_run: bool
    conflict_strategy: ConflictStrategy
    total_submitted: int = 0
    created_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    created_ids: list[str] = field(default_factory=list)
    updated_ids: list[str] = field(default_factory=list)
    skipped_identifiers: list[str] = field(default_factory=list)
    errors: list[BulkImportRowIssue] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.failed_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "dry_run": self.dry_run,
            "conflict_strategy": self.conflict_strategy,
            "success": self.success,
            "total_submitted": self.total_submitted,
            "created_count": self.created_count,
            "updated_count": self.updated_count,
            "skipped_count": self.skipped_count,
            "failed_count": self.failed_count,
            "created_ids": list(self.created_ids),
            "updated_ids": list(self.updated_ids),
            "skipped_identifiers": list(self.skipped_identifiers),
            "errors": [e.to_dict() for e in self.errors],
            "warnings": list(self.warnings),
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass(frozen=True)
class ExportResult:
    """Rendered inventory export artifact ready for HTTP download or CLI serialization."""

    format: ExportFormat
    content_type: str
    filename: str
    content: str
    record_counts: dict[str, int]
    exported_at: datetime = field(default_factory=utcnow)
    data: dict[str, Any] | list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "content_type": self.content_type,
            "filename": self.filename,
            "record_counts": dict(self.record_counts),
            "exported_at": self.exported_at.isoformat(),
            "byte_length": len(self.content.encode("utf-8")),
        }


# ---------------------------------------------------------------------------
# CSV / JSON Parsing & Column Normalization Helpers
# ---------------------------------------------------------------------------

_DEVICE_COLUMN_ALIASES: dict[str, str] = {
    "name": "hostname",
    "host": "hostname",
    "device_name": "hostname",
    "ip": "management_ip",
    "ip_address": "management_ip",
    "mgmt_ip": "management_ip",
    "primary_ip": "management_ip",
    "primary_ip4": "management_ip",
    "mac": "mac_address",
    "type": "device_type",
    "role": "device_type",
    "category": "device_type",
    "manufacturer": "vendor",
    "os": "os_version",
    "firmware": "os_version",
    "serial": "serial_number",
    "site": "site_code",
    "location": "site_code",
    "rack": "rack_name",
    "u_position": "rack_unit_start",
    "rack_u_position": "rack_unit_start",
    "position": "rack_unit_start",
    "u_height": "rack_unit_height",
    "rack_u_height": "rack_unit_height",
    "poll_interval": "polling_interval_seconds",
    "poll_interval_seconds": "polling_interval_seconds",
    "credential_profile": "credential_profile_name",
    "tags_json": "tags",
    "secondary_ips_json": "secondary_ips",
    "custom_fields_json": "custom_fields",
}

_SUBNET_COLUMN_ALIASES: dict[str, str] = {
    "prefix": "cidr",
    "network": "cidr",
    "subnet": "cidr",
    "gateway": "gateway_ip",
    "gw": "gateway_ip",
    "vlan": "vlan_number",
    "vlan_id": "vlan_number",
    "vid": "vlan_number",
    "site": "site_code",
    "dns": "dns_servers",
    "dns_servers_json": "dns_servers",
    "dhcp": "dhcp_enabled",
    "scan": "scan_enabled",
}

_TRUTHY_STRINGS: frozenset[str] = frozenset({"1", "true", "yes", "y", "on", "enabled"})
_FALSY_STRINGS: frozenset[str] = frozenset({"0", "false", "no", "n", "off", "disabled"})


def _parse_bool(value: Any, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUTHY_STRINGS:
        return True
    if text in _FALSY_STRINGS:
        return False
    raise ValidationError(f"Invalid boolean value: {value!r}")


def _parse_optional_int(value: Any, field_name: str) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(str(value).strip())
    except ValueError as exc:
        raise ValidationError(f"Field '{field_name}' must be an integer, got {value!r}") from exc


def _parse_list_field(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    if isinstance(value, Mapping):
        return normalize_tags(value)
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(v).strip() for v in parsed if v is not None and str(v).strip()]
        except json.JSONDecodeError:
            pass
    return [part.strip() for part in re.split(r"[;|,]", text) if part.strip()]


def _parse_dict_field(value: Any, field_name: str) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    text = str(value).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Field '{field_name}' must be valid JSON object: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValidationError(f"Field '{field_name}' must decode to a JSON object")
    return parsed


def _normalize_row_keys(row: Mapping[str, Any], aliases: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw_k, raw_v in row.items():
        if raw_k is None:
            continue
        k = str(raw_k).strip().lower().replace(" ", "_").replace("-", "_")
        canonical = aliases.get(k, k)
        # Preserve canonical key if explicitly supplied alongside an alias
        if canonical not in out or out[canonical] in (None, ""):
            out[canonical] = raw_v
    return out


def _parse_tabular_payload(
    payload: Sequence[Mapping[str, Any]] | str,
    *,
    input_format: ImportFormat,
    wrapper_key: str,
) -> list[dict[str, Any]]:
    """Parse JSON list/object or CSV text into a uniform list of row dictionaries."""
    if not isinstance(payload, str):
        rows: list[dict[str, Any]] = []
        for idx, item in enumerate(payload):
            if isinstance(item, Mapping):
                rows.append(dict(item))
            elif hasattr(item, "model_dump"):
                rows.append(dict(item.model_dump()))
            else:
                raise ValidationError(f"Row {idx} must be a mapping or Pydantic schema")
        return rows

    text = payload.strip().lstrip("\ufeff")
    if not text:
        return []

    detected: Literal["json", "csv"]
    if input_format == "auto":
        detected = "json" if text[0] in {"[", "{"} else "csv"
    else:
        detected = input_format

    if detected == "json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Invalid JSON import payload: {exc}") from exc
        if isinstance(parsed, dict):
            if wrapper_key in parsed and isinstance(parsed[wrapper_key], list):
                parsed = parsed[wrapper_key]
            elif "items" in parsed and isinstance(parsed["items"], list):
                parsed = parsed["items"]
            else:
                raise ValidationError(
                    f"JSON object payload must contain a '{wrapper_key}' or 'items' array"
                )
        if not isinstance(parsed, list):
            raise ValidationError("JSON import payload must be an array of records")
        result: list[dict[str, Any]] = []
        for idx, item in enumerate(parsed):
            if not isinstance(item, Mapping):
                raise ValidationError(f"JSON item at index {idx} must be an object")
            result.append(dict(item))
        return result

    # CSV parsing (RFC 4180)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValidationError("CSV import payload is missing a header row")
    return [dict(row) for row in reader if any(v is not None and str(v).strip() != "" for v in row.values())]


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "item"


# ---------------------------------------------------------------------------
# NetBox Mapping Tables
# ---------------------------------------------------------------------------

_NETBOX_DEVICE_STATUS_MAP: dict[str, str] = {
    DeviceStatus.UP.value: "active",
    DeviceStatus.DEGRADED.value: "active",
    DeviceStatus.WARNING.value: "active",
    DeviceStatus.CRITICAL.value: "failed",
    DeviceStatus.DOWN.value: "offline",
    DeviceStatus.UNREACHABLE.value: "offline",
    DeviceStatus.MAINTENANCE.value: "staged",
    DeviceStatus.PROVISIONING.value: "planned",
    DeviceStatus.DECOMMISSIONED.value: "decommissioning",
    DeviceStatus.UNKNOWN.value: "inventory",
}

_NETBOX_INTERFACE_TYPE_MAP: dict[str, str] = {
    InterfaceType.HUNDRED_GIGABIT_ETHERNET.value: "100gbase-x-qsfp28",
    InterfaceType.FORTY_GIGABIT_ETHERNET.value: "40gbase-x-qsfpp",
    InterfaceType.TWENTY_FIVE_GIGABIT_ETHERNET.value: "25gbase-x-sfp28",
    InterfaceType.TEN_GIGABIT_ETHERNET.value: "10gbase-x-sfpp",
    InterfaceType.GIGABIT_ETHERNET.value: "1000base-t",
    InterfaceType.FAST_ETHERNET.value: "100base-tx",
    InterfaceType.ETHERNET.value: "1000base-t",
    InterfaceType.FIBER.value: "10gbase-x-sfpp",
    InterfaceType.SFP.value: "1000base-x-sfp",
    InterfaceType.QSFP.value: "40gbase-x-qsfpp",
    InterfaceType.LAG.value: "lag",
    InterfaceType.PORT_CHANNEL.value: "lag",
    InterfaceType.LOOPBACK.value: "virtual",
    InterfaceType.VLAN.value: "virtual",
    InterfaceType.SVI.value: "virtual",
    InterfaceType.BRIDGE.value: "bridge",
    InterfaceType.TUNNEL.value: "virtual",
    InterfaceType.GRE.value: "virtual",
    InterfaceType.IPSEC.value: "virtual",
    InterfaceType.VXLAN.value: "virtual",
    InterfaceType.VIRTUAL.value: "virtual",
    InterfaceType.WIRELESS.value: "ieee802.11ax",
    InterfaceType.MANAGEMENT.value: "1000base-t",
    InterfaceType.OTHER.value: "other",
}


# ---------------------------------------------------------------------------
# ImportExportService
# ---------------------------------------------------------------------------


class ImportExportService:
    """Bulk CMDB inventory importer (JSON/CSV) and exporter (JSON/CSV/NetBox)."""

    def __init__(
        self,
        db: Session,
        *,
        inventory_service: InventoryService | None = None,
    ) -> None:
        self.db = db
        self.inventory = inventory_service or InventoryService(db)
        self.audit_logs = AuditLogRepository(db)

    # -----------------------------------------------------------------------
    # Internal Lookup Caches
    # -----------------------------------------------------------------------

    def _build_site_lookup(self, org_id: str) -> tuple[dict[str, Site], dict[str, Site], dict[str, Site]]:
        sites = self.inventory.sites.list(org_id=org_id)
        by_id = {s.id: s for s in sites}
        by_code = {s.code.upper(): s for s in sites}
        by_name = {s.name.strip().lower(): s for s in sites}
        return by_id, by_code, by_name

    def _resolve_site_id(
        self,
        org_id: str,
        raw_row: Mapping[str, Any],
        *,
        sites_by_id: dict[str, Site],
        sites_by_code: dict[str, Site],
        sites_by_name: dict[str, Site],
        default_site_id: str | None,
        auto_create_sites: bool,
        dry_run: bool,
    ) -> str | None:
        explicit_id = raw_row.get("site_id")
        if explicit_id and str(explicit_id).strip():
            sid = str(explicit_id).strip()
            if sid not in sites_by_id:
                raise ValidationError(f"Unknown site_id '{sid}' in organization", details={"field": "site_id"})
            return sid

        site_ref = raw_row.get("site_code")
        if site_ref and str(site_ref).strip():
            code_key = str(site_ref).strip().upper()
            if code_key in sites_by_code:
                return sites_by_code[code_key].id
            name_key = str(site_ref).strip().lower()
            if name_key in sites_by_name:
                return sites_by_name[name_key].id
            if auto_create_sites:
                if dry_run:
                    return None
                created = self.inventory.create_site(org_id, {"name": str(site_ref).strip(), "code": code_key})
                sites_by_id[created.id] = created
                sites_by_code[created.code.upper()] = created
                sites_by_name[created.name.strip().lower()] = created
                return created.id
            raise ValidationError(
                f"Site code or name '{site_ref}' could not be resolved",
                details={"field": "site_code", "site_code": str(site_ref)},
            )

        return default_site_id

    # -----------------------------------------------------------------------
    # Bulk Device Importer
    # -----------------------------------------------------------------------

    def import_devices(
        self,
        org_id: str,
        payload: Sequence[Mapping[str, Any]] | str,
        *,
        input_format: ImportFormat = "auto",
        conflict_strategy: ConflictStrategy = "skip",
        dry_run: bool = False,
        default_site_id: str | None = None,
        default_credential_profile_id: str | None = None,
        auto_create_sites: bool = False,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> BulkImportReport:
        """Bulk-import devices from JSON list/text or CSV text with dry-run & conflict resolution."""
        started = time.perf_counter()
        if conflict_strategy not in {"skip", "update", "error"}:
            raise ValidationError(
                f"Unsupported conflict_strategy {conflict_strategy!r}; expected 'skip', 'update', or 'error'"
            )

        rows = _parse_tabular_payload(payload, input_format=input_format, wrapper_key="devices")
        report = BulkImportReport(
            entity_type="devices",
            dry_run=dry_run,
            conflict_strategy=conflict_strategy,
            total_submitted=len(rows),
        )
        if not rows:
            report.duration_ms = (time.perf_counter() - started) * 1000.0
            return report

        # Validate default foreign references upfront
        sites_by_id, sites_by_code, sites_by_name = self._build_site_lookup(org_id)
        if default_site_id is not None and default_site_id not in sites_by_id:
            raise ValidationError(f"default_site_id '{default_site_id}' was not found in organization")

        creds_all = self.inventory.credentials.list(org_id=org_id)
        creds_by_id = {c.id: c for c in creds_all}
        creds_by_name = {c.name.strip().lower(): c for c in creds_all}
        if default_credential_profile_id is not None and default_credential_profile_id not in creds_by_id:
            raise ValidationError(
                f"default_credential_profile_id '{default_credential_profile_id}' was not found"
            )

        racks_all = self.inventory.racks.list(org_id=org_id)
        racks_by_id = {r.id: r for r in racks_all}
        racks_by_site_name: dict[tuple[str, str], Rack] = {
            (r.site_id, r.name.strip().lower()): r for r in racks_all
        }

        # Existing org devices and quota baseline
        org = self.inventory.orgs.get_by_id(org_id)
        if org is None:
            raise ValidationError(f"Organization '{org_id}' was not found")
        max_devices = int(org.max_devices or 1000)

        existing_devices = self.inventory.devices.list(org_id=org_id)
        existing_by_hostname: dict[str, Device] = {d.hostname.lower(): d for d in existing_devices}
        current_device_count = len(existing_devices)
        seen_batch_hostnames: set[str] = set()

        for idx, raw_input in enumerate(rows):
            row = _normalize_row_keys(raw_input, _DEVICE_COLUMN_ALIASES)
            hostname_raw = str(row.get("hostname") or "").strip()
            mgmt_ip_raw = str(row.get("management_ip") or "").strip()

            try:
                if not hostname_raw:
                    raise ValidationError("Missing required 'hostname'", details={"field": "hostname"})
                if not mgmt_ip_raw:
                    raise ValidationError("Missing required 'management_ip'", details={"field": "management_ip"})
                if not is_valid_ip(mgmt_ip_raw):
                    raise ValidationError(
                        f"Invalid IP address: {mgmt_ip_raw!r}",
                        details={"field": "management_ip"},
                    )
                norm_ip = normalize_ip(mgmt_ip_raw)

                # MAC normalization & OUI inference
                mac_raw = row.get("mac_address")
                norm_mac: str | None = None
                if mac_raw is not None and str(mac_raw).strip():
                    if not is_valid_mac(str(mac_raw)):
                        raise ValidationError(
                            f"Invalid MAC address: {mac_raw!r}",
                            details={"field": "mac_address"},
                        )
                    norm_mac = format_mac(str(mac_raw))

                # Resolve site, rack, credential
                resolved_site_id = self._resolve_site_id(
                    org_id,
                    row,
                    sites_by_id=sites_by_id,
                    sites_by_code=sites_by_code,
                    sites_by_name=sites_by_name,
                    default_site_id=default_site_id,
                    auto_create_sites=auto_create_sites,
                    dry_run=dry_run,
                )

                resolved_rack_id: str | None = None
                if row.get("rack_id") and str(row["rack_id"]).strip():
                    rid = str(row["rack_id"]).strip()
                    if rid not in racks_by_id:
                        raise ValidationError(f"Unknown rack_id '{rid}'", details={"field": "rack_id"})
                    resolved_rack_id = rid
                elif row.get("rack_name") and str(row["rack_name"]).strip():
                    rname = str(row["rack_name"]).strip().lower()
                    if resolved_site_id and (resolved_site_id, rname) in racks_by_site_name:
                        resolved_rack_id = racks_by_site_name[(resolved_site_id, rname)].id
                    else:
                        # Fallback search across all org racks by unique name
                        matches = [r for r in racks_all if r.name.strip().lower() == rname]
                        if len(matches) == 1:
                            resolved_rack_id = matches[0].id
                            if resolved_site_id is None:
                                resolved_site_id = matches[0].site_id
                        else:
                            raise ValidationError(
                                f"Rack '{row['rack_name']}' could not be resolved",
                                details={"field": "rack_name"},
                            )

                resolved_cred_id: str | None = default_credential_profile_id
                if row.get("credential_profile_id") and str(row["credential_profile_id"]).strip():
                    cid = str(row["credential_profile_id"]).strip()
                    if cid not in creds_by_id:
                        raise ValidationError(
                            f"Unknown credential_profile_id '{cid}'",
                            details={"field": "credential_profile_id"},
                        )
                    resolved_cred_id = cid
                elif row.get("credential_profile_name") and str(row["credential_profile_name"]).strip():
                    cname = str(row["credential_profile_name"]).strip().lower()
                    if cname not in creds_by_name:
                        raise ValidationError(
                            f"Unknown credential profile '{row['credential_profile_name']}'",
                            details={"field": "credential_profile_name"},
                        )
                    resolved_cred_id = creds_by_name[cname].id

                # Normalize enum & structured fields
                device_type = normalize_device_type(row.get("device_type"))
                status = normalize_device_status(row.get("status") or DeviceStatus.UNKNOWN.value)

                raw_vendor = row.get("vendor")
                if raw_vendor and str(raw_vendor).strip().lower() not in {"", "unknown"}:
                    vendor = normalize_device_vendor(raw_vendor)
                elif norm_mac:
                    vendor, _ = infer_vendor_from_mac(norm_mac)
                else:
                    vendor = DeviceVendor.UNKNOWN.value

                rack_u_start = _parse_optional_int(row.get("rack_unit_start"), "rack_unit_start")
                rack_u_height = _parse_optional_int(row.get("rack_unit_height"), "rack_unit_height") or 1
                poll_interval = _parse_optional_int(row.get("polling_interval_seconds"), "polling_interval_seconds") or 60
                if poll_interval < 5:
                    raise ValidationError("polling_interval_seconds must be >= 5", details={"field": "polling_interval_seconds"})

                device_payload: dict[str, Any] = {
                    "hostname": hostname_raw,
                    "fqdn": str(row["fqdn"]).strip() if row.get("fqdn") else None,
                    "management_ip": norm_ip,
                    "secondary_ips_json": _parse_list_field(row.get("secondary_ips")),
                    "mac_address": norm_mac,
                    "site_id": resolved_site_id,
                    "rack_id": resolved_rack_id,
                    "rack_unit_start": rack_u_start,
                    "rack_unit_height": rack_u_height,
                    "credential_profile_id": resolved_cred_id,
                    "device_type": device_type,
                    "vendor": vendor,
                    "model": str(row["model"]).strip() if row.get("model") else None,
                    "os_version": str(row["os_version"]).strip() if row.get("os_version") else None,
                    "serial_number": str(row["serial_number"]).strip() if row.get("serial_number") else None,
                    "asset_tag": str(row["asset_tag"]).strip() if row.get("asset_tag") else None,
                    "status": status,
                    "polling_enabled": _parse_bool(row.get("polling_enabled"), default=True),
                    "snmp_enabled": _parse_bool(row.get("snmp_enabled"), default=True),
                    "icmp_enabled": _parse_bool(row.get("icmp_enabled"), default=True),
                    "polling_interval_seconds": poll_interval,
                    "tags_json": _parse_list_field(row.get("tags")),
                    "custom_fields_json": _parse_dict_field(row.get("custom_fields"), "custom_fields"),
                }

                # Check intra-batch duplicate hostname
                host_key = hostname_raw.lower()
                if host_key in seen_batch_hostnames:
                    if conflict_strategy == "skip":
                        report.skipped_count += 1
                        report.skipped_identifiers.append(hostname_raw)
                        report.warnings.append(f"Row {idx}: duplicate hostname '{hostname_raw}' within batch skipped")
                        continue
                    if conflict_strategy == "error":
                        raise ConflictError(
                            f"Duplicate hostname '{hostname_raw}' within import batch",
                            error_code="DUPLICATE_IN_BATCH",
                        )

                existing = existing_by_hostname.get(host_key)
                if existing is not None:
                    if conflict_strategy == "skip":
                        report.skipped_count += 1
                        report.skipped_identifiers.append(hostname_raw)
                        seen_batch_hostnames.add(host_key)
                        continue
                    if conflict_strategy == "error":
                        raise ConflictError(
                            f"Device with hostname '{hostname_raw}' already exists",
                            error_code="HOSTNAME_CONFLICT",
                        )
                    # conflict_strategy == "update"
                    if resolved_rack_id and rack_u_start is not None:
                        self.inventory.validate_rack_placement(
                            resolved_rack_id,
                            org_id,
                            rack_u_start,
                            rack_u_height,
                            exclude_device_id=existing.id,
                        )
                    if not dry_run:
                        updated = self.inventory.update_device(
                            existing.id,
                            org_id,
                            device_payload,
                            actor_user_id=actor_user_id,
                            actor_email=actor_email,
                            emit_event=False,
                        )
                        report.updated_ids.append(updated.id)
                    else:
                        report.updated_ids.append(existing.id)
                    report.updated_count += 1
                    seen_batch_hostnames.add(host_key)
                else:
                    # Enforce org quota across batch
                    if current_device_count + 1 > max_devices:
                        raise ConflictError(
                            f"Organization device quota exceeded ({current_device_count}/{max_devices})",
                            error_code="DEVICE_QUOTA_EXCEEDED",
                        )
                    if resolved_rack_id and rack_u_start is not None:
                        self.inventory.validate_rack_placement(
                            resolved_rack_id,
                            org_id,
                            rack_u_start,
                            rack_u_height,
                        )
                    if not dry_run:
                        created = self.inventory.create_device(
                            org_id,
                            device_payload,
                            actor_user_id=actor_user_id,
                            actor_email=actor_email,
                            check_quota=False,
                            emit_event=False,
                        )
                        existing_by_hostname[host_key] = created
                        report.created_ids.append(created.id)
                    current_device_count += 1
                    report.created_count += 1
                    seen_batch_hostnames.add(host_key)

            except NetPulseError as exc:
                report.failed_count += 1
                report.errors.append(
                    BulkImportRowIssue(
                        row_index=idx,
                        identifier=hostname_raw or None,
                        secondary_identifier=mgmt_ip_raw or None,
                        error_code=exc.error_code,
                        field=exc.details.get("field") if isinstance(exc.details, dict) else None,
                        message=exc.message,
                    )
                )
            except Exception as exc:
                report.failed_count += 1
                report.errors.append(
                    BulkImportRowIssue(
                        row_index=idx,
                        identifier=hostname_raw or None,
                        secondary_identifier=mgmt_ip_raw or None,
                        error_code="ROW_IMPORT_ERROR",
                        message=str(exc),
                    )
                )

        if not dry_run and (report.created_count > 0 or report.updated_count > 0):
            try:
                self.audit_logs.record(
                    org_id=org_id,
                    action=AuditAction.CREATE.value,
                    resource_type="device_bulk_import",
                    summary=(
                        f"Bulk imported devices: created={report.created_count}, "
                        f"updated={report.updated_count}, skipped={report.skipped_count}, failed={report.failed_count}"
                    ),
                    actor_user_id=actor_user_id,
                    actor_email=actor_email,
                    details=report.to_dict(),
                    flush=False,
                )
            except Exception:  # pragma: no cover
                pass

        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report

    def import_devices_from_csv(
        self,
        org_id: str,
        csv_text: str,
        **kwargs: Any,
    ) -> BulkImportReport:
        """Convenience wrapper to bulk-import devices from RFC 4180 CSV text."""
        return self.import_devices(org_id, csv_text, input_format="csv", **kwargs)

    def import_devices_from_json(
        self,
        org_id: str,
        json_payload: Sequence[Mapping[str, Any]] | str,
        **kwargs: Any,
    ) -> BulkImportReport:
        """Convenience wrapper to bulk-import devices from a JSON list or JSON string."""
        return self.import_devices(org_id, json_payload, input_format="json", **kwargs)

    # -----------------------------------------------------------------------
    # Bulk Subnet Importer
    # -----------------------------------------------------------------------

    def import_subnets(
        self,
        org_id: str,
        payload: Sequence[Mapping[str, Any]] | str,
        *,
        input_format: ImportFormat = "auto",
        conflict_strategy: ConflictStrategy = "skip",
        allow_overlap: bool = False,
        dry_run: bool = False,
        default_site_id: str | None = None,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> BulkImportReport:
        """Bulk-import IPAM subnets from CSV or JSON with CIDR validation and overlap checks."""
        started = time.perf_counter()
        if conflict_strategy not in {"skip", "update", "error"}:
            raise ValidationError(
                f"Unsupported conflict_strategy {conflict_strategy!r}; expected 'skip', 'update', or 'error'"
            )

        rows = _parse_tabular_payload(payload, input_format=input_format, wrapper_key="subnets")
        report = BulkImportReport(
            entity_type="subnets",
            dry_run=dry_run,
            conflict_strategy=conflict_strategy,
            total_submitted=len(rows),
        )
        if not rows:
            report.duration_ms = (time.perf_counter() - started) * 1000.0
            return report

        sites_by_id, sites_by_code, sites_by_name = self._build_site_lookup(org_id)
        if default_site_id is not None and default_site_id not in sites_by_id:
            raise ValidationError(f"default_site_id '{default_site_id}' was not found in organization")

        existing_subnets = self.inventory.subnets.list(org_id=org_id)
        existing_by_cidr: dict[str, Subnet] = {s.cidr: s for s in existing_subnets}
        tracked_cidrs: list[str] = [s.cidr for s in existing_subnets]
        seen_batch_cidrs: set[str] = set()

        for idx, raw_input in enumerate(rows):
            row = _normalize_row_keys(raw_input, _SUBNET_COLUMN_ALIASES)
            raw_cidr = str(row.get("cidr") or "").strip()
            raw_name = str(row.get("name") or "").strip()

            try:
                if not raw_cidr or not is_valid_cidr(raw_cidr, strict=False):
                    raise ValidationError(f"Invalid CIDR block: {raw_cidr!r}", details={"field": "cidr"})
                norm_cidr = str(parse_network(raw_cidr, strict=False))
                name = raw_name or f"Subnet {norm_cidr}"

                resolved_site_id = self._resolve_site_id(
                    org_id,
                    row,
                    sites_by_id=sites_by_id,
                    sites_by_code=sites_by_code,
                    sites_by_name=sites_by_name,
                    default_site_id=default_site_id,
                    auto_create_sites=False,
                    dry_run=dry_run,
                )

                gw_raw = row.get("gateway_ip")
                gateway_ip: str | None = None
                if gw_raw is not None and str(gw_raw).strip():
                    if not is_valid_ip(str(gw_raw)):
                        raise ValidationError(f"Invalid gateway_ip: {gw_raw!r}", details={"field": "gateway_ip"})
                    gateway_ip = normalize_ip(str(gw_raw))
                    if not ip_in_cidr(gateway_ip, norm_cidr):
                        raise ValidationError(
                            f"Gateway IP '{gateway_ip}' is outside subnet '{norm_cidr}'",
                            details={"field": "gateway_ip"},
                        )

                vlan_num = _parse_optional_int(row.get("vlan_number"), "vlan_number")
                if vlan_num is not None and not (1 <= vlan_num <= 4094):
                    raise ValidationError(
                        f"vlan_number must be between 1 and 4094, got {vlan_num}",
                        details={"field": "vlan_number"},
                    )

                dns_list: list[str] = []
                for raw_dns_ip in _parse_list_field(row.get("dns_servers")):
                    if not is_valid_ip(raw_dns_ip):
                        raise ValidationError(
                            f"Invalid DNS server IP: {raw_dns_ip!r}",
                            details={"field": "dns_servers"},
                        )
                    dns_list.append(normalize_ip(raw_dns_ip))

                subnet_payload: dict[str, Any] = {
                    "cidr": norm_cidr,
                    "name": name,
                    "description": str(row["description"]).strip() if row.get("description") else None,
                    "site_id": resolved_site_id,
                    "gateway_ip": gateway_ip,
                    "vlan_number": vlan_num,
                    "dns_servers_json": dns_list,
                    "dhcp_enabled": _parse_bool(row.get("dhcp_enabled"), default=False),
                    "scan_enabled": _parse_bool(row.get("scan_enabled"), default=True),
                }

                # Check intra-batch duplicate CIDR
                if norm_cidr in seen_batch_cidrs:
                    if conflict_strategy == "skip":
                        report.skipped_count += 1
                        report.skipped_identifiers.append(norm_cidr)
                        continue
                    if conflict_strategy == "error":
                        raise ConflictError(
                            f"Duplicate CIDR '{norm_cidr}' within import batch",
                            error_code="DUPLICATE_IN_BATCH",
                        )

                existing = existing_by_cidr.get(norm_cidr)
                if existing is not None:
                    if conflict_strategy == "skip":
                        report.skipped_count += 1
                        report.skipped_identifiers.append(norm_cidr)
                        seen_batch_cidrs.add(norm_cidr)
                        continue
                    if conflict_strategy == "error":
                        raise ConflictError(
                            f"Subnet '{norm_cidr}' already exists",
                            error_code="SUBNET_CONFLICT",
                        )
                    if not dry_run:
                        updated = self.inventory.update_subnet(
                            existing.id,
                            org_id,
                            subnet_payload,
                            allow_overlap=allow_overlap,
                        )
                        report.updated_ids.append(updated.id)
                    else:
                        report.updated_ids.append(existing.id)
                    report.updated_count += 1
                    seen_batch_cidrs.add(norm_cidr)
                else:
                    # Check overlap against both DB subnets and earlier rows in this batch
                    if not allow_overlap:
                        overlapping = [c for c in tracked_cidrs if cidrs_overlap(norm_cidr, c)]
                        if overlapping:
                            raise ConflictError(
                                f"Subnet '{norm_cidr}' overlaps existing/queued subnet(s): {', '.join(overlapping)}",
                                error_code="SUBNET_OVERLAP",
                                details={"field": "cidr", "overlapping_cidrs": overlapping},
                            )
                    if not dry_run:
                        created = self.inventory.create_subnet(
                            org_id,
                            subnet_payload,
                            allow_overlap=allow_overlap,
                            actor_user_id=actor_user_id,
                            actor_email=actor_email,
                        )
                        existing_by_cidr[norm_cidr] = created
                        report.created_ids.append(created.id)
                    tracked_cidrs.append(norm_cidr)
                    seen_batch_cidrs.add(norm_cidr)
                    report.created_count += 1

            except NetPulseError as exc:
                report.failed_count += 1
                report.errors.append(
                    BulkImportRowIssue(
                        row_index=idx,
                        identifier=raw_cidr or None,
                        secondary_identifier=raw_name or None,
                        error_code=exc.error_code,
                        field=exc.details.get("field") if isinstance(exc.details, dict) else None,
                        message=exc.message,
                    )
                )
            except Exception as exc:
                report.failed_count += 1
                report.errors.append(
                    BulkImportRowIssue(
                        row_index=idx,
                        identifier=raw_cidr or None,
                        secondary_identifier=raw_name or None,
                        error_code="ROW_IMPORT_ERROR",
                        message=str(exc),
                    )
                )

        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report

    # -----------------------------------------------------------------------
    # Full Inventory Exporter (JSON, CSV, NetBox JSON)
    # -----------------------------------------------------------------------

    def export_inventory(
        self,
        org_id: str,
        *,
        export_format: ExportFormat = "json",
        include_sites: bool = True,
        include_racks: bool = True,
        include_devices: bool = True,
        include_interfaces: bool = True,
        include_subnets: bool = True,
        include_vlans: bool = True,
        include_ip_allocations: bool = True,
        include_groups: bool = True,
        site_id: str | None = None,
        status: str | None = None,
        device_type: str | None = None,
        csv_entity: CsvExportEntity = "devices",
        actor_user_id: str | None = None,
        actor_email: str | None = None,
    ) -> ExportResult:
        """Export full or filtered tenant inventory in ``json``, ``csv``, or ``netbox_json`` format.

        SECURITY INVARIANT: Vaulted credential secrets are NEVER included in any export.
        """
        if export_format not in {"json", "csv", "netbox_json"}:
            raise ValidationError(
                f"Unsupported export_format {export_format!r}; expected 'json', 'csv', or 'netbox_json'"
            )

        now = utcnow()
        stamp = now.strftime("%Y%m%dT%H%M%SZ")

        sites = self.inventory.sites.list(org_id=org_id) if include_sites else []
        if site_id is not None:
            sites = [s for s in sites if s.id == site_id]
        sites_by_id = {s.id: s for s in self.inventory.sites.list(org_id=org_id)}

        racks = self.inventory.list_racks(org_id, site_id=site_id) if include_racks else []
        racks_by_id = {r.id: r for r in self.inventory.racks.list(org_id=org_id)}

        devices: list[Device] = []
        if include_devices:
            dev_filters: dict[str, Any] = {}
            if site_id is not None:
                dev_filters["site_id"] = site_id
            if status is not None:
                dev_filters["status"] = normalize_device_status(status)
            if device_type is not None:
                dev_filters["device_type"] = normalize_device_type(device_type)
            devices = self.inventory.devices.list(filters=dev_filters or None, org_id=org_id)
        devices_by_id = {d.id: d for d in devices}
        device_id_set = set(devices_by_id.keys())

        interfaces: list[DeviceInterface] = []
        if include_interfaces:
            all_ifaces = self.inventory.interfaces.list(org_id=org_id)
            interfaces = (
                [i for i in all_ifaces if i.device_id in device_id_set]
                if (site_id is not None or status is not None or device_type is not None)
                else all_ifaces
            )

        subnets = (
            self.inventory.subnets.list_by_site(site_id, org_id=org_id)
            if (include_subnets and site_id is not None)
            else (self.inventory.subnets.list(org_id=org_id) if include_subnets else [])
        )
        subnet_ids = {s.id for s in subnets}
        subnets_by_id = {s.id: s for s in subnets}

        vlans = (
            self.inventory.list_vlans(org_id, site_id=site_id)
            if include_vlans
            else []
        )

        ip_allocations: list[IpAllocation] = []
        if include_ip_allocations:
            all_allocs = self.inventory.allocations.list(order_by="ip_address", org_id=org_id)
            ip_allocations = (
                [a for a in all_allocs if a.subnet_id in subnet_ids]
                if site_id is not None
                else all_allocs
            )

        groups = self.inventory.list_device_groups_with_counts(org_id) if include_groups else []

        counts = {
            "sites": len(sites),
            "racks": len(racks),
            "devices": len(devices),
            "interfaces": len(interfaces),
            "subnets": len(subnets),
            "vlans": len(vlans),
            "ip_allocations": len(ip_allocations),
            "device_groups": len(groups),
        }

        if export_format == "json":
            snapshot = self._build_native_json_export(
                org_id=org_id,
                exported_at=now,
                sites=sites,
                racks=racks,
                devices=devices,
                interfaces=interfaces,
                subnets=subnets,
                vlans=vlans,
                ip_allocations=ip_allocations,
                groups=groups,
                sites_by_id=sites_by_id,
                racks_by_id=racks_by_id,
                counts=counts,
            )
            result = ExportResult(
                format="json",
                content_type="application/json",
                filename=f"netpulse-inventory-{stamp}.json",
                content=json.dumps(snapshot, indent=2, default=str),
                record_counts=counts,
                exported_at=now,
                data=snapshot,
            )
        elif export_format == "csv":
            csv_content = self._build_csv_export(
                entity=csv_entity,
                sites=sites,
                devices=devices,
                interfaces=interfaces,
                subnets=subnets,
                vlans=vlans,
                ip_allocations=ip_allocations,
                sites_by_id=sites_by_id,
                racks_by_id=racks_by_id,
                devices_by_id=devices_by_id,
                subnets_by_id=subnets_by_id,
            )
            result = ExportResult(
                format="csv",
                content_type="text/csv; charset=utf-8",
                filename=f"netpulse-{csv_entity}-{stamp}.csv",
                content=csv_content,
                record_counts=counts,
                exported_at=now,
            )
        else:
            netbox_doc = self._build_netbox_export(
                org_id=org_id,
                exported_at=now,
                sites=sites,
                racks=racks,
                devices=devices,
                interfaces=interfaces,
                subnets=subnets,
                vlans=vlans,
                ip_allocations=ip_allocations,
                sites_by_id=sites_by_id,
                racks_by_id=racks_by_id,
                devices_by_id=devices_by_id,
                subnets_by_id=subnets_by_id,
            )
            result = ExportResult(
                format="netbox_json",
                content_type="application/json",
                filename=f"netpulse-netbox-export-{stamp}.json",
                content=json.dumps(netbox_doc, indent=2, default=str),
                record_counts=counts,
                exported_at=now,
                data=netbox_doc,
            )

        try:
            self.audit_logs.record(
                org_id=org_id,
                action=AuditAction.EXPORT.value,
                resource_type="inventory_export",
                summary=f"Exported inventory in '{export_format}' format ({counts['devices']} devices)",
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                details={"format": export_format, "counts": counts},
                flush=False,
            )
        except Exception:  # pragma: no cover
            pass

        return result

    def _build_native_json_export(
        self,
        *,
        org_id: str,
        exported_at: datetime,
        sites: Sequence[Site],
        racks: Sequence[Rack],
        devices: Sequence[Device],
        interfaces: Sequence[DeviceInterface],
        subnets: Sequence[Subnet],
        vlans: Sequence[Vlan],
        ip_allocations: Sequence[IpAllocation],
        groups: Sequence[dict[str, Any]],
        sites_by_id: Mapping[str, Site],
        racks_by_id: Mapping[str, Rack],
        counts: Mapping[str, int],
    ) -> dict[str, Any]:
        return {
            "export_version": "2.0",
            "source": "netpulse",
            "org_id": org_id,
            "exported_at": exported_at.isoformat(),
            "counts": dict(counts),
            "sites": [
                {
                    **s.to_summary_dict(),
                    "address": s.address,
                    "contact_name": s.contact_name,
                    "contact_email": s.contact_email,
                    "metadata": dict(s.metadata_json or {}),
                }
                for s in sites
            ],
            "racks": [
                {
                    "id": r.id,
                    "site_id": r.site_id,
                    "site_code": sites_by_id[r.site_id].code if r.site_id in sites_by_id else None,
                    "name": r.name,
                    "aisle": r.aisle,
                    "row": r.row,
                    "total_u": r.total_u,
                    "power_capacity_watts": r.power_capacity_watts,
                    "cooling_zone": r.cooling_zone,
                    "notes": r.notes,
                }
                for r in racks
            ],
            "devices": [
                {
                    "id": d.id,
                    "hostname": d.hostname,
                    "fqdn": d.fqdn,
                    "management_ip": d.management_ip,
                    "secondary_ips": list(d.secondary_ips_json or []),
                    "mac_address": d.mac_address,
                    "device_type": d.device_type,
                    "vendor": d.vendor,
                    "model": d.model,
                    "os_version": d.os_version,
                    "serial_number": d.serial_number,
                    "asset_tag": d.asset_tag,
                    "site_id": d.site_id,
                    "site_code": sites_by_id[d.site_id].code if d.site_id and d.site_id in sites_by_id else None,
                    "rack_id": d.rack_id,
                    "rack_name": racks_by_id[d.rack_id].name if d.rack_id and d.rack_id in racks_by_id else None,
                    "rack_unit_start": d.rack_unit_start,
                    "rack_unit_height": d.rack_unit_height,
                    "status": d.status,
                    "polling_enabled": d.polling_enabled,
                    "snmp_enabled": d.snmp_enabled,
                    "icmp_enabled": d.icmp_enabled,
                    "polling_interval_seconds": d.polling_interval_seconds,
                    "tags": list(d.tags_json or []),
                    "custom_fields": dict(d.custom_fields_json or {}),
                    "uptime_seconds": d.uptime_seconds,
                    "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                }
                for d in devices
            ],
            "interfaces": [
                {
                    "id": i.id,
                    "device_id": i.device_id,
                    "if_index": i.if_index,
                    "name": i.name,
                    "alias": i.alias,
                    "interface_type": i.interface_type,
                    "mac_address": i.mac_address,
                    "ip_address": i.ip_address,
                    "vlan_id": i.vlan_id,
                    "speed_mbps": i.speed_mbps,
                    "mtu": i.mtu,
                    "admin_status": i.admin_status,
                    "oper_status": i.oper_status,
                    "is_uplink": i.is_uplink,
                    "utilization_in_pct": i.utilization_in_pct,
                    "utilization_out_pct": i.utilization_out_pct,
                }
                for i in interfaces
            ],
            "subnets": [
                {
                    "id": s.id,
                    "cidr": s.cidr,
                    "name": s.name,
                    "description": s.description,
                    "site_id": s.site_id,
                    "site_code": sites_by_id[s.site_id].code if s.site_id and s.site_id in sites_by_id else None,
                    "gateway_ip": s.gateway_ip,
                    "vlan_number": s.vlan_number,
                    "dns_servers": list(s.dns_servers_json or []),
                    "dhcp_enabled": s.dhcp_enabled,
                    "utilization_pct": s.utilization_pct,
                    "scan_enabled": s.scan_enabled,
                }
                for s in subnets
            ],
            "vlans": [
                {
                    "id": v.id,
                    "vlan_id_num": v.vlan_id_num,
                    "name": v.name,
                    "description": v.description,
                    "site_id": v.site_id,
                    "site_code": sites_by_id[v.site_id].code if v.site_id and v.site_id in sites_by_id else None,
                    "status": v.status,
                    "subnet_cidr": v.subnet_cidr,
                }
                for v in vlans
            ],
            "ip_allocations": [
                {
                    "id": a.id,
                    "subnet_id": a.subnet_id,
                    "device_id": a.device_id,
                    "ip_address": a.ip_address,
                    "mac_address": a.mac_address,
                    "hostname": a.hostname,
                    "allocation_type": a.allocation_type,
                    "status": a.status,
                    "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
                }
                for a in ip_allocations
            ],
            "device_groups": list(groups),
        }

    def _build_csv_export(
        self,
        *,
        entity: CsvExportEntity,
        sites: Sequence[Site],
        devices: Sequence[Device],
        interfaces: Sequence[DeviceInterface],
        subnets: Sequence[Subnet],
        vlans: Sequence[Vlan],
        ip_allocations: Sequence[IpAllocation],
        sites_by_id: Mapping[str, Site],
        racks_by_id: Mapping[str, Rack],
        devices_by_id: Mapping[str, Device],
        subnets_by_id: Mapping[str, Subnet],
    ) -> str:
        buf = io.StringIO()
        if entity == "devices":
            headers = [
                "hostname",
                "fqdn",
                "management_ip",
                "mac_address",
                "device_type",
                "vendor",
                "model",
                "os_version",
                "serial_number",
                "asset_tag",
                "site_code",
                "rack_name",
                "rack_unit_start",
                "rack_unit_height",
                "status",
                "polling_enabled",
                "snmp_enabled",
                "icmp_enabled",
                "polling_interval_seconds",
                "tags",
            ]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for d in devices:
                writer.writerow(
                    {
                        "hostname": d.hostname,
                        "fqdn": d.fqdn or "",
                        "management_ip": d.management_ip,
                        "mac_address": d.mac_address or "",
                        "device_type": d.device_type,
                        "vendor": d.vendor,
                        "model": d.model or "",
                        "os_version": d.os_version or "",
                        "serial_number": d.serial_number or "",
                        "asset_tag": d.asset_tag or "",
                        "site_code": sites_by_id[d.site_id].code if d.site_id and d.site_id in sites_by_id else "",
                        "rack_name": racks_by_id[d.rack_id].name if d.rack_id and d.rack_id in racks_by_id else "",
                        "rack_unit_start": d.rack_unit_start if d.rack_unit_start is not None else "",
                        "rack_unit_height": d.rack_unit_height if d.rack_unit_height is not None else 1,
                        "status": d.status,
                        "polling_enabled": str(d.polling_enabled).lower(),
                        "snmp_enabled": str(d.snmp_enabled).lower(),
                        "icmp_enabled": str(d.icmp_enabled).lower(),
                        "polling_interval_seconds": d.polling_interval_seconds,
                        "tags": ";".join(d.tags_json or []),
                    }
                )
        elif entity == "subnets":
            headers = [
                "cidr",
                "name",
                "description",
                "site_code",
                "gateway_ip",
                "vlan_number",
                "dns_servers",
                "dhcp_enabled",
                "utilization_pct",
                "scan_enabled",
            ]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for s in subnets:
                writer.writerow(
                    {
                        "cidr": s.cidr,
                        "name": s.name,
                        "description": s.description or "",
                        "site_code": sites_by_id[s.site_id].code if s.site_id and s.site_id in sites_by_id else "",
                        "gateway_ip": s.gateway_ip or "",
                        "vlan_number": s.vlan_number if s.vlan_number is not None else "",
                        "dns_servers": ";".join(s.dns_servers_json or []),
                        "dhcp_enabled": str(s.dhcp_enabled).lower(),
                        "utilization_pct": s.utilization_pct,
                        "scan_enabled": str(s.scan_enabled).lower(),
                    }
                )
        elif entity == "sites":
            headers = ["code", "name", "tier", "region", "country", "city", "timezone", "latitude", "longitude"]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for s in sites:
                writer.writerow(
                    {
                        "code": s.code,
                        "name": s.name,
                        "tier": s.tier,
                        "region": s.region or "",
                        "country": s.country or "",
                        "city": s.city or "",
                        "timezone": s.timezone,
                        "latitude": s.latitude if s.latitude is not None else "",
                        "longitude": s.longitude if s.longitude is not None else "",
                    }
                )
        elif entity == "interfaces":
            headers = [
                "device_hostname",
                "if_index",
                "name",
                "alias",
                "interface_type",
                "ip_address",
                "mac_address",
                "vlan_id",
                "speed_mbps",
                "mtu",
                "admin_status",
                "oper_status",
                "is_uplink",
                "utilization_in_pct",
                "utilization_out_pct",
            ]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for i in interfaces:
                dev = devices_by_id.get(i.device_id)
                writer.writerow(
                    {
                        "device_hostname": dev.hostname if dev else i.device_id,
                        "if_index": i.if_index,
                        "name": i.name,
                        "alias": i.alias or "",
                        "interface_type": i.interface_type,
                        "ip_address": i.ip_address or "",
                        "mac_address": i.mac_address or "",
                        "vlan_id": i.vlan_id if i.vlan_id is not None else "",
                        "speed_mbps": i.speed_mbps if i.speed_mbps is not None else "",
                        "mtu": i.mtu if i.mtu is not None else "",
                        "admin_status": i.admin_status,
                        "oper_status": i.oper_status,
                        "is_uplink": str(i.is_uplink).lower(),
                        "utilization_in_pct": i.utilization_in_pct,
                        "utilization_out_pct": i.utilization_out_pct,
                    }
                )
        elif entity == "vlans":
            headers = ["vlan_id_num", "name", "site_code", "status", "subnet_cidr", "description"]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for v in vlans:
                writer.writerow(
                    {
                        "vlan_id_num": v.vlan_id_num,
                        "name": v.name,
                        "site_code": sites_by_id[v.site_id].code if v.site_id and v.site_id in sites_by_id else "",
                        "status": v.status,
                        "subnet_cidr": v.subnet_cidr or "",
                        "description": v.description or "",
                    }
                )
        else:  # ip_allocations
            headers = ["ip_address", "subnet_cidr", "hostname", "mac_address", "allocation_type", "status"]
            writer = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            for a in ip_allocations:
                sub = subnets_by_id.get(a.subnet_id)
                writer.writerow(
                    {
                        "ip_address": a.ip_address,
                        "subnet_cidr": sub.cidr if sub else a.subnet_id,
                        "hostname": a.hostname or "",
                        "mac_address": a.mac_address or "",
                        "allocation_type": a.allocation_type,
                        "status": a.status,
                    }
                )
        return buf.getvalue()

    def _build_netbox_export(
        self,
        *,
        org_id: str,
        exported_at: datetime,
        sites: Sequence[Site],
        racks: Sequence[Rack],
        devices: Sequence[Device],
        interfaces: Sequence[DeviceInterface],
        subnets: Sequence[Subnet],
        vlans: Sequence[Vlan],
        ip_allocations: Sequence[IpAllocation],
        sites_by_id: Mapping[str, Site],
        racks_by_id: Mapping[str, Rack],
        devices_by_id: Mapping[str, Device],
        subnets_by_id: Mapping[str, Subnet],
    ) -> dict[str, Any]:
        """Build a NetBox v3/v4 compatible DCIM & IPAM JSON export document."""
        dcim_sites = [
            {
                "name": s.name,
                "slug": _slugify(s.code),
                "status": "active",
                "facility": s.code,
                "region": {"name": s.region, "slug": _slugify(s.region)} if s.region else None,
                "time_zone": s.timezone,
                "physical_address": s.address or "",
                "latitude": s.latitude,
                "longitude": s.longitude,
                "custom_fields": {
                    "netpulse_id": s.id,
                    "tier": s.tier,
                    "contact_name": s.contact_name,
                    "contact_email": s.contact_email,
                },
            }
            for s in sites
        ]

        dcim_racks = [
            {
                "name": r.name,
                "site": {"slug": _slugify(sites_by_id[r.site_id].code)} if r.site_id in sites_by_id else None,
                "status": "active",
                "u_height": r.total_u,
                "facility_id": r.aisle,
                "comments": r.notes or "",
                "custom_fields": {
                    "netpulse_id": r.id,
                    "row": r.row,
                    "power_capacity_watts": r.power_capacity_watts,
                    "cooling_zone": r.cooling_zone,
                },
            }
            for r in racks
        ]

        dcim_devices: list[dict[str, Any]] = []
        for d in devices:
            is_v6 = ":" in d.management_ip
            primary_cidr = f"{d.management_ip}/128" if is_v6 else f"{d.management_ip}/32"
            site_obj = sites_by_id.get(d.site_id) if d.site_id else None
            rack_obj = racks_by_id.get(d.rack_id) if d.rack_id else None
            dcim_devices.append(
                {
                    "name": d.hostname,
                    "status": _NETBOX_DEVICE_STATUS_MAP.get(d.status, "active"),
                    "role": {"name": d.device_type.replace("_", " ").title(), "slug": _slugify(d.device_type)},
                    "device_type": {
                        "manufacturer": {"name": d.vendor.replace("_", " ").title(), "slug": _slugify(d.vendor)},
                        "model": d.model or "Generic",
                        "slug": _slugify(f"{d.vendor}-{d.model or 'generic'}"),
                        "u_height": d.rack_unit_height or 1,
                    },
                    "site": {"name": site_obj.name, "slug": _slugify(site_obj.code)} if site_obj else None,
                    "rack": {"name": rack_obj.name} if rack_obj else None,
                    "position": d.rack_unit_start,
                    "face": "front" if d.rack_unit_start is not None else None,
                    "serial": d.serial_number or "",
                    "asset_tag": d.asset_tag,
                    "platform": {"name": d.os_version, "slug": _slugify(d.os_version)} if d.os_version else None,
                    "primary_ip4": {"address": primary_cidr} if not is_v6 else None,
                    "primary_ip6": {"address": primary_cidr} if is_v6 else None,
                    "tags": [{"name": t, "slug": _slugify(t)} for t in (d.tags_json or [])],
                    "custom_fields": {
                        "netpulse_id": d.id,
                        "fqdn": d.fqdn,
                        "mac_address": d.mac_address,
                        "polling_enabled": d.polling_enabled,
                        **dict(d.custom_fields_json or {}),
                    },
                }
            )

        dcim_interfaces = [
            {
                "device": {"name": devices_by_id[i.device_id].hostname} if i.device_id in devices_by_id else None,
                "name": i.name,
                "type": _NETBOX_INTERFACE_TYPE_MAP.get(i.interface_type, "other"),
                "enabled": i.admin_status == "up",
                "mtu": i.mtu,
                "mac_address": i.mac_address.upper() if i.mac_address else None,
                "speed": (i.speed_mbps * 1000) if i.speed_mbps is not None else None,
                "description": i.alias or i.description or "",
                "mgmt_only": i.interface_type == InterfaceType.MANAGEMENT.value,
                "custom_fields": {
                    "netpulse_id": i.id,
                    "if_index": i.if_index,
                    "is_uplink": i.is_uplink,
                    "oper_status": i.oper_status,
                },
            }
            for i in interfaces
        ]

        ipam_vlans = [
            {
                "vid": v.vlan_id_num,
                "name": v.name,
                "site": {"slug": _slugify(sites_by_id[v.site_id].code)} if v.site_id and v.site_id in sites_by_id else None,
                "status": v.status,
                "description": v.description or "",
                "custom_fields": {"netpulse_id": v.id, "subnet_cidr": v.subnet_cidr},
            }
            for v in vlans
        ]

        ipam_prefixes = [
            {
                "prefix": s.cidr,
                "site": {"slug": _slugify(sites_by_id[s.site_id].code)} if s.site_id and s.site_id in sites_by_id else None,
                "vlan": {"vid": s.vlan_number} if s.vlan_number is not None else None,
                "status": "active",
                "description": s.description or s.name,
                "custom_fields": {
                    "netpulse_id": s.id,
                    "name": s.name,
                    "gateway_ip": s.gateway_ip,
                    "dhcp_enabled": s.dhcp_enabled,
                    "utilization_pct": s.utilization_pct,
                },
            }
            for s in subnets
        ]

        ipam_ip_addresses: list[dict[str, Any]] = []
        for a in ip_allocations:
            sub = subnets_by_id.get(a.subnet_id)
            prefix_len = sub.network.prefixlen if sub else (128 if ":" in a.ip_address else 32)
            dev = devices_by_id.get(a.device_id) if a.device_id else None
            ipam_ip_addresses.append(
                {
                    "address": f"{a.ip_address}/{prefix_len}",
                    "status": a.status if a.status in {"active", "reserved", "deprecated", "dhcp"} else "active",
                    "dns_name": a.hostname or "",
                    "assigned_object": {"device": dev.hostname} if dev else None,
                    "custom_fields": {
                        "netpulse_id": a.id,
                        "mac_address": a.mac_address,
                        "allocation_type": a.allocation_type,
                    },
                }
            )

        return {
            "schema": "netbox-v4-export",
            "generator": "NetPulse CMDB Exporter",
            "org_id": org_id,
            "exported_at": exported_at.isoformat(),
            "dcim": {
                "sites": dcim_sites,
                "racks": dcim_racks,
                "devices": dcim_devices,
                "interfaces": dcim_interfaces,
            },
            "ipam": {
                "vlans": ipam_vlans,
                "prefixes": ipam_prefixes,
                "ip_addresses": ipam_ip_addresses,
            },
        }


__all__ = [
    "BulkImportReport",
    "BulkImportRowIssue",
    "ConflictStrategy",
    "CsvExportEntity",
    "ExportFormat",
    "ExportResult",
    "ImportExportService",
    "ImportFormat",
]
