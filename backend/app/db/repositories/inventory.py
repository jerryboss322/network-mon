"""Data-access repositories for network inventory, IPAM, sites, racks, credentials, and groups."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import String, and_, cast, delete as sa_delete, func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.db.base import utcnow
from app.db.repositories.base import BaseRepository, PageResult, SortSpec, resolve_model

if TYPE_CHECKING:
    from app.models.inventory import (
        CredentialProfile,
        Device,
        DeviceGroup,
        DeviceGroupMember,
        DeviceInterface,
        IpAllocation,
        Rack,
        Site,
        Subnet,
        Vlan,
    )


class SiteRepository(BaseRepository["Site"]):
    """Repository for physical data centers, POPs, and branch :class:`Site` entities."""

    _model_spec = ("app.models.inventory", "Site")
    default_order_by = ("name",)

    def get_by_code(self, code: str, *, org_id: str | None = None) -> Any | None:
        """Lookup a site by its short code (e.g. ``US-EAST-DC1``)."""
        col = self._resolve_column("code", "site_code", "slug")
        stmt = self._base_query(org_id=org_id).where(func.lower(col) == code.strip().lower())
        return self.session.execute(stmt).scalar_one_or_none()

    def list_by_region(self, region: str, *, org_id: str | None = None) -> list[Any]:
        """List all sites in a geographic region or country."""
        col = self._resolve_column("region", "country")
        return self.list(filters={col.key: region}, org_id=org_id)

    def search(
        self,
        *,
        query: str | None = None,
        region: str | None = None,
        tier: str | None = None,
        org_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[Any]:
        """Search sites by name, code, city, or region."""
        stmt = self._base_query(org_id=org_id)
        if region is not None and self._has_column("region"):
            stmt = stmt.where(self._get_column("region") == region)
        if tier is not None and self._has_column("tier"):
            stmt = stmt.where(self._get_column("tier") == tier)
        if query:
            pattern = f"%{query.strip()}%"
            clauses = [self._get_column("name").ilike(pattern)]
            for candidate in ("code", "site_code", "city", "country", "region", "address"):
                if self._has_column(candidate):
                    clauses.append(self._get_column(candidate).ilike(pattern))
            stmt = stmt.where(or_(*clauses))

        total = int(self.session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        ordered = self._apply_ordering(stmt, None).offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.execute(ordered).scalars().all())
        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def list_with_device_counts(self, *, org_id: str | None = None) -> list[dict[str, Any]]:
        """Return each site paired with total and online device counts."""
        sites = self.list(org_id=org_id)
        device_repo = DeviceRepository(self.session, org_id=self._effective_org_id(org_id))
        by_site = device_repo.count_by_site(org_id=org_id)
        online_by_site = device_repo.count_by_site(status="up", org_id=org_id)
        if not online_by_site:
            online_by_site = device_repo.count_by_site(status="online", org_id=org_id)
        results: list[dict[str, Any]] = []
        for site in sites:
            sid = getattr(site, "id")
            total = by_site.get(sid, 0)
            online = online_by_site.get(sid, 0)
            results.append(
                {
                    "site": site,
                    "site_id": sid,
                    "name": getattr(site, "name", ""),
                    "device_count": total,
                    "online_count": online,
                    "offline_count": max(0, total - online),
                }
            )
        return results


class RackRepository(BaseRepository["Rack"]):
    """Repository for physical server/network :class:`Rack` enclosures within sites."""

    _model_spec = ("app.models.inventory", "Rack")
    default_order_by = ("name",)

    def list_by_site(self, site_id: str, *, org_id: str | None = None) -> list[Any]:
        """List all racks belonging to a specific site."""
        return self.list(filters={"site_id": site_id}, org_id=org_id)

    def get_by_name_in_site(
        self,
        site_id: str,
        name: str,
        *,
        org_id: str | None = None,
    ) -> Any | None:
        """Fetch a rack by name inside a site."""
        stmt = self._base_query(org_id=org_id).where(
            and_(
                self._get_column("site_id") == site_id,
                func.lower(self._get_column("name")) == name.strip().lower(),
            )
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_utilization_summary(
        self,
        site_id: str | None = None,
        *,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compute per-rack device counts and rack-unit capacity utilization."""
        filters = {"site_id": site_id} if site_id is not None else None
        racks = self.list(filters=filters, org_id=org_id)
        device_model = resolve_model("app.models.inventory", "Device")

        dev_stmt = select(device_model.rack_id, func.count(device_model.id)).where(
            device_model.rack_id.is_not(None)
        )
        effective_org = self._effective_org_id(org_id)
        if effective_org is not None and hasattr(device_model, "org_id"):
            dev_stmt = dev_stmt.where(device_model.org_id == effective_org)
        if hasattr(device_model, "is_deleted"):
            dev_stmt = dev_stmt.where(device_model.is_deleted.is_(False))
        dev_stmt = dev_stmt.group_by(device_model.rack_id)
        counts = {str(rid): int(cnt) for rid, cnt in self.session.execute(dev_stmt).all()}

        summary: list[dict[str, Any]] = []
        for rack in racks:
            total_u = int(
                getattr(rack, "total_u", None)
                or getattr(rack, "u_height", None)
                or getattr(rack, "total_units", None)
                or 42
            )
            used_u = int(getattr(rack, "used_units", 0) or 0)
            dev_count = counts.get(rack.id, 0)
            if used_u == 0 and dev_count > 0:
                used_u = min(total_u, dev_count * 2)
            summary.append(
                {
                    "rack_id": rack.id,
                    "site_id": getattr(rack, "site_id", None),
                    "name": getattr(rack, "name", ""),
                    "total_units": total_u,
                    "used_units": used_u,
                    "utilization_pct": round((used_u / total_u) * 100.0, 1) if total_u > 0 else 0.0,
                    "device_count": dev_count,
                }
            )
        return summary


class CredentialRepository(BaseRepository["CredentialProfile"]):
    """Repository for encrypted SNMP/SSH/API :class:`CredentialProfile` vault items."""

    _model_spec = ("app.models.inventory", "CredentialProfile")
    default_order_by = ("name",)

    def get_by_name(self, name: str, *, org_id: str | None = None) -> Any | None:
        """Fetch a credential profile by unique name within an organization."""
        stmt = self._base_query(org_id=org_id).where(
            func.lower(self._get_column("name")) == name.strip().lower()
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_by_protocol(self, protocol: str, *, org_id: str | None = None) -> list[Any]:
        """List credential profiles matching a protocol (e.g. ``snmpv3``, ``ssh``, ``netconf``)."""
        col = self._resolve_column("protocol", "credential_type", "auth_type")
        return self.list(filters={col.key: protocol}, org_id=org_id)

    def list_default_profiles(self, *, org_id: str | None = None) -> list[Any]:
        """Return credential profiles flagged as organization defaults."""
        col = self._optional_column("is_default")
        if col is None:
            return self.list(org_id=org_id)
        return self.list(filters={col.key: True}, org_id=org_id)

    def mark_rotated(
        self,
        credential_id: str,
        *,
        encrypted_payload: Any | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Record a credential secret rotation and optionally replace encrypted ciphertext."""
        patch: dict[str, Any] = {}
        if self._has_column("last_rotated_at"):
            patch["last_rotated_at"] = utcnow()
        if encrypted_payload is not None:
            secret_col = self._optional_column("encrypted_payload", "encrypted_secret", "ciphertext")
            if secret_col is not None:
                patch[secret_col.key] = encrypted_payload
        return self.update(credential_id, patch, org_id=org_id, flush=flush)

    def count_assigned_devices(self, credential_id: str, *, org_id: str | None = None) -> int:
        """Count how many active devices reference this credential profile."""
        device_model = resolve_model("app.models.inventory", "Device")
        fk_col = getattr(device_model, "credential_profile_id", None) or getattr(
            device_model, "credential_id", None
        )
        if fk_col is None:
            return 0
        stmt = select(func.count(device_model.id)).where(fk_col == credential_id)
        effective_org = self._effective_org_id(org_id)
        if effective_org is not None and hasattr(device_model, "org_id"):
            stmt = stmt.where(device_model.org_id == effective_org)
        if hasattr(device_model, "is_deleted"):
            stmt = stmt.where(device_model.is_deleted.is_(False))
        return int(self.session.execute(stmt).scalar_one())


class DeviceRepository(BaseRepository["Device"]):
    """Repository for managed network :class:`Device` inventory, search, and fleet summaries."""

    _model_spec = ("app.models.inventory", "Device")
    default_order_by = ("hostname",)

    def get_by_hostname(self, hostname: str, *, org_id: str | None = None) -> Any | None:
        """Lookup a device by case-insensitive hostname."""
        col = self._resolve_column("hostname", "name")
        stmt = self._base_query(org_id=org_id).where(func.lower(col) == hostname.strip().lower())
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_ip(self, ip_address: str, *, org_id: str | None = None) -> Any | None:
        """Lookup a device by its management IP address."""
        col = self._resolve_column("management_ip", "ip_address", "ip")
        stmt = self._base_query(org_id=org_id).where(col == ip_address.strip())
        return self.session.execute(stmt).scalar_one_or_none()

    def search(
        self,
        *,
        query: str | None = None,
        status: str | Sequence[str] | None = None,
        device_type: str | Sequence[str] | None = None,
        vendor: str | None = None,
        site_id: str | None = None,
        rack_id: str | None = None,
        tag: str | None = None,
        snmp_enabled: bool | None = None,
        icmp_enabled: bool | None = None,
        group_id: str | None = None,
        order_by: Sequence[str | SortSpec] | str | None = None,
        page: int = 1,
        page_size: int = 50,
        org_id: str | None = None,
    ) -> PageResult[Any]:
        """Full-featured inventory search by hostname, IP, tag, vendor, type, site, group, and status."""
        if page < 1 or page_size < 1:
            raise ValidationError("page and page_size must be >= 1")

        stmt = self._base_query(org_id=org_id)

        if status is not None and self._has_column("status"):
            status_col = self._get_column("status")
            if isinstance(status, str):
                stmt = stmt.where(status_col == status)
            else:
                stmt = stmt.where(status_col.in_(list(status)))

        if device_type is not None:
            type_col = self._optional_column("device_type", "role", "category")
            if type_col is not None:
                if isinstance(device_type, str):
                    stmt = stmt.where(type_col == device_type)
                else:
                    stmt = stmt.where(type_col.in_(list(device_type)))

        if vendor is not None and self._has_column("vendor"):
            stmt = stmt.where(self._get_column("vendor").ilike(f"%{vendor.strip()}%"))

        if site_id is not None and self._has_column("site_id"):
            stmt = stmt.where(self._get_column("site_id") == site_id)

        if rack_id is not None and self._has_column("rack_id"):
            stmt = stmt.where(self._get_column("rack_id") == rack_id)

        if snmp_enabled is not None and self._has_column("snmp_enabled"):
            stmt = stmt.where(self._get_column("snmp_enabled").is_(snmp_enabled))

        if icmp_enabled is not None and self._has_column("icmp_enabled"):
            stmt = stmt.where(self._get_column("icmp_enabled").is_(icmp_enabled))

        if tag is not None:
            tags_col = self._optional_column("tags_json", "tags", "labels")
            if tags_col is not None:
                stmt = stmt.where(cast(tags_col, String).ilike(f"%{tag.strip()}%"))

        if group_id is not None:
            member_model = resolve_model("app.models.inventory", "DeviceGroupMember")
            member_sub = select(member_model.device_id).where(member_model.group_id == group_id)
            stmt = stmt.where(self._get_column("id").in_(member_sub))

        if query:
            pattern = f"%{query.strip()}%"
            text_fields = (
                "hostname",
                "display_name",
                "management_ip",
                "ip_address",
                "fqdn",
                "vendor",
                "model",
                "serial_number",
                "os_version",
                "sys_descr",
                "description",
            )
            predicates = [
                self._get_column(f).ilike(pattern) for f in text_fields if self._has_column(f)
            ]
            tags_col = self._optional_column("tags_json", "tags", "labels")
            if tags_col is not None:
                predicates.append(cast(tags_col, String).ilike(pattern))
            if predicates:
                stmt = stmt.where(or_(*predicates))

        total = int(self.session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        ordered = self._apply_ordering(stmt, order_by).offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.execute(ordered).scalars().all())

        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def list_by_site(
        self,
        site_id: str,
        *,
        status: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List all devices located at a specific site."""
        filters: dict[str, Any] = {"site_id": site_id}
        if status is not None and self._has_column("status"):
            filters["status"] = status
        return self.list(filters=filters, org_id=org_id)

    def list_by_tag(self, tag: str, *, org_id: str | None = None) -> list[Any]:
        """Return all devices carrying ``tag`` in their tags/labels collection."""
        tags_col = self._optional_column("tags_json", "tags", "labels")
        if tags_col is None:
            return []
        stmt = self._base_query(org_id=org_id).where(cast(tags_col, String).ilike(f"%{tag.strip()}%"))
        stmt = self._apply_ordering(stmt, None)
        return list(self.session.execute(stmt).scalars().all())

    def list_by_group(self, group_id: str, *, org_id: str | None = None) -> list[Any]:
        """Return all devices that are members of ``group_id``."""
        member_model = resolve_model("app.models.inventory", "DeviceGroupMember")
        sub = select(member_model.device_id).where(member_model.group_id == group_id)
        stmt = self._base_query(org_id=org_id).where(self._get_column("id").in_(sub))
        stmt = self._apply_ordering(stmt, None)
        return list(self.session.execute(stmt).scalars().all())

    def list_pollable(
        self,
        *,
        protocol: Literal["snmp", "icmp", "host", "all"] = "all",
        site_id: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List active devices eligible for polling by the specified collector protocol."""
        stmt = self._base_query(org_id=org_id)
        poll_col = self._optional_column("polling_enabled", "is_monitored")
        if poll_col is not None:
            stmt = stmt.where(poll_col.is_(True))
        if self._has_column("status"):
            stmt = stmt.where(self._get_column("status") != "decommissioned")
        if site_id is not None and self._has_column("site_id"):
            stmt = stmt.where(self._get_column("site_id") == site_id)
        if protocol == "snmp" and self._has_column("snmp_enabled"):
            stmt = stmt.where(self._get_column("snmp_enabled").is_(True))
        elif protocol == "icmp" and self._has_column("icmp_enabled"):
            stmt = stmt.where(self._get_column("icmp_enabled").is_(True))
        elif protocol == "host" and self._has_column("agent_enabled"):
            stmt = stmt.where(self._get_column("agent_enabled").is_(True))
        stmt = self._apply_ordering(stmt, None)
        return list(self.session.execute(stmt).scalars().all())

    def update_status(
        self,
        device_id: str,
        status: str,
        *,
        last_seen_at: datetime | None = None,
        latency_ms: float | None = None,
        packet_loss_pct: float | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Update operational reachability status and last-seen telemetry metadata."""
        patch: dict[str, Any] = {}
        if self._has_column("status"):
            patch["status"] = status
        if self._has_column("last_seen_at"):
            patch["last_seen_at"] = last_seen_at or utcnow()
        if self._has_column("last_polled_at"):
            patch["last_polled_at"] = utcnow()
        if latency_ms is not None and self._has_column("last_rtt_ms"):
            patch["last_rtt_ms"] = latency_ms
        if packet_loss_pct is not None and self._has_column("last_packet_loss_pct"):
            patch["last_packet_loss_pct"] = packet_loss_pct
        return self.update(device_id, patch, org_id=org_id, flush=flush)

    def count_by_status(self, *, org_id: str | None = None) -> dict[str, int]:
        """Return device counts grouped by operational status."""
        col = self._resolve_column("status")
        sub = self._base_query(org_id=org_id).subquery()
        stmt = select(sub.c[col.key], func.count()).group_by(sub.c[col.key])
        return {str(val or "unknown"): int(cnt) for val, cnt in self.session.execute(stmt).all()}

    def count_by_type(self, *, org_id: str | None = None) -> dict[str, int]:
        """Return device counts grouped by device type/role."""
        col = self._resolve_column("device_type", "role", "category")
        sub = self._base_query(org_id=org_id).subquery()
        stmt = select(sub.c[col.key], func.count()).group_by(sub.c[col.key])
        return {str(val or "unknown"): int(cnt) for val, cnt in self.session.execute(stmt).all()}

    def count_by_vendor(self, *, org_id: str | None = None) -> dict[str, int]:
        """Return device counts grouped by hardware/software vendor."""
        col = self._optional_column("vendor")
        if col is None:
            return {}
        sub = self._base_query(org_id=org_id).subquery()
        stmt = select(sub.c[col.key], func.count()).group_by(sub.c[col.key])
        return {str(val or "unknown"): int(cnt) for val, cnt in self.session.execute(stmt).all()}

    def count_by_site(
        self,
        *,
        status: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Return device counts grouped by ``site_id``."""
        if not self._has_column("site_id"):
            return {}
        base = self._base_query(org_id=org_id)
        if status is not None and self._has_column("status"):
            base = base.where(self._get_column("status") == status)
        sub = base.subquery()
        stmt = select(sub.c.site_id, func.count()).group_by(sub.c.site_id)
        return {str(sid or "unassigned"): int(cnt) for sid, cnt in self.session.execute(stmt).all()}

    def summary_counts(self, *, org_id: str | None = None) -> dict[str, Any]:
        """Return fleet-wide aggregate device counts by status, type, site, and vendor."""
        by_status = self.count_by_status(org_id=org_id)
        by_type = self.count_by_type(org_id=org_id)
        by_site = self.count_by_site(org_id=org_id)
        by_vendor = self.count_by_vendor(org_id=org_id)
        total = sum(by_status.values())
        return {
            "total": total,
            "by_status": by_status,
            "by_type": by_type,
            "by_site": by_site,
            "by_vendor": by_vendor,
        }

    def get_stale_devices(
        self,
        *,
        older_than_minutes: int = 15,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return monitored devices that have not reported telemetry within ``older_than_minutes``."""
        ts_col = self._optional_column("last_seen_at", "last_polled_at", "updated_at")
        if ts_col is None:
            return []
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        stmt = self._base_query(org_id=org_id).where(or_(ts_col.is_(None), ts_col < cutoff))
        return list(self.session.execute(stmt).scalars().all())


class InterfaceRepository(BaseRepository["DeviceInterface"]):
    """Repository for physical/logical network :class:`DeviceInterface` ports and counters."""

    _model_spec = ("app.models.inventory", "DeviceInterface")
    default_order_by = ("if_index", "name")

    def list_by_device(
        self,
        device_id: str,
        *,
        oper_status: str | None = None,
        admin_status: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List all interfaces on a specific device."""
        filters: dict[str, Any] = {"device_id": device_id}
        if oper_status is not None and self._has_column("oper_status"):
            filters["oper_status"] = oper_status
        if admin_status is not None and self._has_column("admin_status"):
            filters["admin_status"] = admin_status
        return self.list(filters=filters, org_id=org_id)

    def get_by_device_and_name(
        self,
        device_id: str,
        name: str,
        *,
        org_id: str | None = None,
    ) -> Any | None:
        """Fetch an interface by device ID and interface name (e.g. ``GigabitEthernet0/0/1``)."""
        stmt = self._base_query(org_id=org_id).where(
            and_(
                self._get_column("device_id") == device_id,
                func.lower(self._get_column("name")) == name.strip().lower(),
            )
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_device_and_index(
        self,
        device_id: str,
        if_index: int,
        *,
        org_id: str | None = None,
    ) -> Any | None:
        """Fetch an interface by SNMP ``ifIndex`` on a device."""
        return self.get_one_by(filters={"device_id": device_id, "if_index": if_index}, org_id=org_id)

    def list_down_uplinks(self, *, org_id: str | None = None) -> list[Any]:
        """Return administratively up interfaces whose operational state is down."""
        stmt = self._base_query(org_id=org_id)
        if self._has_column("admin_status"):
            stmt = stmt.where(self._get_column("admin_status") == "up")
        if self._has_column("oper_status"):
            stmt = stmt.where(self._get_column("oper_status") != "up")
        if self._has_column("is_uplink"):
            stmt = stmt.where(self._get_column("is_uplink").is_(True))
        return list(self.session.execute(stmt).scalars().all())

    def list_high_error_interfaces(
        self,
        *,
        min_errors: int = 10,
        limit: int = 50,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return interfaces whose combined input/output error counter exceeds ``min_errors``."""
        in_col = self._optional_column("in_errors_last", "in_errors")
        out_col = self._optional_column("out_errors_last", "out_errors")
        if in_col is None and out_col is None:
            return []
        total_err = func.coalesce(in_col, 0) + func.coalesce(out_col, 0) if (in_col is not None and out_col is not None) else func.coalesce(in_col or out_col, 0)
        stmt = (
            self._base_query(org_id=org_id)
            .where(total_err >= min_errors)
            .order_by(total_err.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def update_counters(
        self,
        interface_id: str,
        *,
        in_octets: int | None = None,
        out_octets: int | None = None,
        in_errors: int | None = None,
        out_errors: int | None = None,
        oper_status: str | None = None,
        utilization_in_pct: float | None = None,
        utilization_out_pct: float | None = None,
        flush: bool = True,
    ) -> Any:
        """Update SNMP traffic counters and operational state on an interface."""
        candidates = {
            "in_octets_last": in_octets,
            "in_octets": in_octets,
            "out_octets_last": out_octets,
            "out_octets": out_octets,
            "in_errors_last": in_errors,
            "in_errors": in_errors,
            "out_errors_last": out_errors,
            "out_errors": out_errors,
            "oper_status": oper_status,
            "utilization_in_pct": utilization_in_pct,
            "utilization_out_pct": utilization_out_pct,
        }
        cols = self._column_names()
        patch = {k: v for k, v in candidates.items() if v is not None and k in cols}
        return self.update(interface_id, patch, flush=flush)

    def status_summary(
        self,
        device_id: str | None = None,
        *,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Return interface counts grouped by operational status."""
        base = self._base_query(org_id=org_id)
        if device_id is not None:
            base = base.where(self._get_column("device_id") == device_id)
        sub = base.subquery()
        col = self._resolve_column("oper_status", "status")
        stmt = select(sub.c[col.key], func.count()).group_by(sub.c[col.key])
        return {str(st or "unknown"): int(cnt) for st, cnt in self.session.execute(stmt).all()}


class SubnetRepository(BaseRepository["Subnet"]):
    """Repository for IPAM :class:`Subnet` prefixes and child :class:`IpAllocation` leases."""

    _model_spec = ("app.models.inventory", "Subnet")
    default_order_by = ("cidr",)

    def _allocation_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        alloc_model = resolve_model("app.models.inventory", "IpAllocation")
        return BaseRepository(
            self.session,
            model=alloc_model,
            org_id=self._effective_org_id(org_id),
        )

    def get_by_cidr(self, cidr: str, *, org_id: str | None = None) -> Any | None:
        """Fetch a subnet by its normalized CIDR string (e.g. ``10.10.0.0/24``)."""
        normalized = str(ipaddress.ip_network(cidr.strip(), strict=False))
        return self.get_one_by(filters={"cidr": normalized}, org_id=org_id)

    def list_by_site(self, site_id: str, *, org_id: str | None = None) -> list[Any]:
        """List all subnets assigned to a site."""
        return self.list(filters={"site_id": site_id}, org_id=org_id)

    def list_allocations(
        self,
        subnet_id: str,
        *,
        status: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List IP address allocations within a subnet."""
        filters: dict[str, Any] = {"subnet_id": subnet_id}
        alloc_repo = self._allocation_repo(org_id=org_id)
        if status is not None and alloc_repo._has_column("status"):
            filters["status"] = status
        return alloc_repo.list(filters=filters, order_by="ip_address")

    def get_allocation_by_ip(self, ip_address: str, *, org_id: str | None = None) -> Any | None:
        """Find an IPAM allocation by exact IP address."""
        alloc_repo = self._allocation_repo(org_id=org_id)
        return alloc_repo.get_one_by(filters={"ip_address": ip_address.strip()})

    def allocate_ip(
        self,
        subnet_id: str,
        ip_address: str,
        *,
        hostname: str | None = None,
        device_id: str | None = None,
        mac_address: str | None = None,
        status: str = "allocated",
        description: str | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Validate IP containment inside the subnet and create an :class:`IpAllocation`."""
        subnet = self.get_by_id_or_raise(subnet_id, org_id=org_id)
        network = ipaddress.ip_network(str(getattr(subnet, "cidr")), strict=False)
        addr = ipaddress.ip_address(ip_address.strip())
        if addr not in network:
            raise ValidationError(
                f"IP address '{addr}' does not belong to subnet '{network}'",
                details={"ip_address": str(addr), "cidr": str(network)},
            )
        if self.get_allocation_by_ip(str(addr), org_id=org_id) is not None:
            raise ConflictError(
                f"IP address '{addr}' is already allocated",
                details={"ip_address": str(addr), "subnet_id": subnet_id},
            )

        alloc_repo = self._allocation_repo(org_id=org_id)
        cols = alloc_repo._column_names()
        candidates = {
            "subnet_id": subnet_id,
            "ip_address": str(addr),
            "hostname": hostname,
            "device_id": device_id,
            "mac_address": mac_address,
            "status": status,
            "description": description,
        }
        payload = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return alloc_repo.create(payload, flush=flush)

    def release_ip(self, ip_address: str, *, org_id: str | None = None, flush: bool = True) -> bool:
        """Release (delete) an IP allocation by IP address."""
        alloc = self.get_allocation_by_ip(ip_address, org_id=org_id)
        if alloc is None:
            return False
        alloc_repo = self._allocation_repo(org_id=org_id)
        return alloc_repo.delete(alloc, flush=flush)

    def get_utilization(self, subnet_id: str, *, org_id: str | None = None) -> dict[str, Any]:
        """Calculate usable IP capacity, allocated count, and utilization percentage."""
        subnet = self.get_by_id_or_raise(subnet_id, org_id=org_id)
        network = ipaddress.ip_network(str(getattr(subnet, "cidr")), strict=False)
        if network.version == 4 and network.prefixlen < 31:
            total_usable = max(0, network.num_addresses - 2)
        else:
            total_usable = int(network.num_addresses)

        alloc_repo = self._allocation_repo(org_id=org_id)
        allocated = alloc_repo.count(filters={"subnet_id": subnet_id})
        pct = round((allocated / total_usable) * 100.0, 2) if total_usable > 0 else 0.0
        return {
            "subnet_id": subnet.id,
            "cidr": str(network),
            "total_usable": total_usable,
            "allocated": allocated,
            "available": max(0, total_usable - allocated),
            "utilization_pct": pct,
        }


class VlanRepository(BaseRepository["Vlan"]):
    """Repository for Layer-2 :class:`Vlan` definitions across sites."""

    _model_spec = ("app.models.inventory", "Vlan")
    default_order_by = ("vlan_id_num",)

    def get_by_vlan_id(
        self,
        vlan_id: int,
        *,
        site_id: str | None = None,
        org_id: str | None = None,
    ) -> Any | None:
        """Fetch a VLAN by 802.1Q VLAN ID (1-4094), optionally scoped to a site."""
        if not 1 <= vlan_id <= 4094:
            raise ValidationError("vlan_id must be between 1 and 4094", details={"vlan_id": vlan_id})
        col = self._resolve_column("vlan_id_num", "vlan_id", "vid", "tag")
        filters: dict[str, Any] = {col.key: vlan_id}
        if site_id is not None and self._has_column("site_id"):
            filters["site_id"] = site_id
        return self.get_one_by(filters=filters, org_id=org_id)

    def list_by_site(self, site_id: str, *, org_id: str | None = None) -> list[Any]:
        """List all VLANs configured at a site."""
        return self.list(filters={"site_id": site_id}, org_id=org_id)

    def list_in_range(
        self,
        min_vlan: int,
        max_vlan: int,
        *,
        site_id: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List VLANs whose 802.1Q ID falls within ``[min_vlan, max_vlan]``."""
        col = self._resolve_column("vlan_id_num", "vlan_id", "vid", "tag")
        filters: dict[str, Any] = {f"{col.key}__gte": min_vlan, f"{col.key}__lte": max_vlan}
        if site_id is not None and self._has_column("site_id"):
            filters["site_id"] = site_id
        return self.list(filters=filters, org_id=org_id)


class DeviceGroupRepository(BaseRepository["DeviceGroup"]):
    """Repository for static and dynamic :class:`DeviceGroup` collections and membership."""

    _model_spec = ("app.models.inventory", "DeviceGroup")
    default_order_by = ("name",)

    def _member_model(self) -> type[Any]:
        return resolve_model("app.models.inventory", "DeviceGroupMember")

    def get_by_name(self, name: str, *, org_id: str | None = None) -> Any | None:
        """Fetch a device group by case-insensitive name."""
        stmt = self._base_query(org_id=org_id).where(
            func.lower(self._get_column("name")) == name.strip().lower()
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_member_device_ids(self, group_id: str, *, org_id: str | None = None) -> list[str]:
        """Return IDs of all devices belonging to ``group_id``."""
        self.get_by_id_or_raise(group_id, org_id=org_id)
        member_model = self._member_model()
        stmt = select(member_model.device_id).where(member_model.group_id == group_id)
        return [str(did) for did in self.session.execute(stmt).scalars().all()]

    def list_members(self, group_id: str, *, org_id: str | None = None) -> list[Any]:
        """Return full :class:`Device` ORM objects belonging to ``group_id``."""
        device_ids = self.list_member_device_ids(group_id, org_id=org_id)
        if not device_ids:
            return []
        device_repo = DeviceRepository(self.session, org_id=self._effective_org_id(org_id))
        return device_repo.get_many_by_ids(device_ids)

    def add_member(
        self,
        group_id: str,
        device_id: str,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Idempotently add a device to a group."""
        self.get_by_id_or_raise(group_id, org_id=org_id)
        member_model = self._member_model()
        existing = self.session.execute(
            select(member_model).where(
                and_(member_model.group_id == group_id, member_model.device_id == device_id)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        kwargs: dict[str, Any] = {"group_id": group_id, "device_id": device_id}
        effective_org = self._effective_org_id(org_id)
        if effective_org is not None and hasattr(member_model, "org_id"):
            kwargs["org_id"] = effective_org
        member = member_model(**kwargs)
        self.session.add(member)
        if flush:
            self.session.flush()
        return member

    def add_members(
        self,
        group_id: str,
        device_ids: Sequence[str],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> int:
        """Bulk-add devices to a group, skipping any already present; returns count added."""
        existing_ids = set(self.list_member_device_ids(group_id, org_id=org_id))
        to_add = [did for did in dict.fromkeys(device_ids) if did not in existing_ids]
        if not to_add:
            return 0
        member_model = self._member_model()
        effective_org = self._effective_org_id(org_id)
        records = []
        for did in to_add:
            kwargs: dict[str, Any] = {"group_id": group_id, "device_id": did}
            if effective_org is not None and hasattr(member_model, "org_id"):
                kwargs["org_id"] = effective_org
            records.append(member_model(**kwargs))
        self.session.add_all(records)
        if flush:
            self.session.flush()
        return len(records)

    def remove_member(
        self,
        group_id: str,
        device_id: str,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> bool:
        """Remove a device from a group; returns ``True`` if removed."""
        self.get_by_id_or_raise(group_id, org_id=org_id)
        member_model = self._member_model()
        stmt = sa_delete(member_model).where(
            and_(member_model.group_id == group_id, member_model.device_id == device_id)
        )
        result = self.session.execute(stmt)
        if flush:
            self.session.flush()
        return bool(result.rowcount)

    def list_groups_for_device(self, device_id: str, *, org_id: str | None = None) -> list[Any]:
        """Return all groups containing ``device_id``."""
        member_model = self._member_model()
        sub = select(member_model.group_id).where(member_model.device_id == device_id)
        stmt = self._base_query(org_id=org_id).where(self._get_column("id").in_(sub))
        return list(self.session.execute(stmt).scalars().all())

    def member_counts(self, *, org_id: str | None = None) -> dict[str, int]:
        """Return a mapping of ``group_id -> member_count`` for all groups in scope."""
        member_model = self._member_model()
        valid_groups = self._base_query(org_id=org_id).with_only_columns(self._get_column("id"))
        stmt = (
            select(member_model.group_id, func.count(member_model.device_id))
            .where(member_model.group_id.in_(valid_groups))
            .group_by(member_model.group_id)
        )
        return {str(gid): int(cnt) for gid, cnt in self.session.execute(stmt).all()}


__all__ = [
    "CredentialRepository",
    "DeviceGroupRepository",
    "DeviceRepository",
    "InterfaceRepository",
    "RackRepository",
    "SiteRepository",
    "SubnetRepository",
    "VlanRepository",
]
