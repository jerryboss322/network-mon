"""Network topology graph, auto-discovery, and service dependency ORM models.

Defines the spatial/logical graph and discovery pipeline models:
- ``TopologyNode``: Positioned node on the network map (device-backed or virtual/cloud/ISP).
- ``TopologyLink``: Directed/physical/logical link between two topology nodes with live telemetry.
- ``DiscoveryJob``: Scheduled or on-demand network sweep across CIDR ranges and protocols.
- ``DiscoveryFinding``: Individual host/device record unearthed by a discovery job.
- ``DependencyEdge``: Directed parent-to-child causal dependency for root-cause analysis & alert suppression.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin, utcnow

# ---------------------------------------------------------------------------
# Topology & Discovery Domain Constants
# ---------------------------------------------------------------------------

VALID_NODE_TYPES: frozenset[str] = frozenset(
    {
        "router",
        "switch",
        "firewall",
        "load_balancer",
        "server",
        "ap",
        "wireless_controller",
        "cloud",
        "isp",
        "subnet",
        "gateway",
        "storage",
        "unknown",
    }
)

VALID_TOPOLOGY_LAYERS: frozenset[str] = frozenset(
    {"core", "distribution", "access", "edge", "dmz", "cloud", "wan", "endpoint"}
)

VALID_LINK_TYPES: frozenset[str] = frozenset(
    {"ethernet", "fiber", "lag", "wireless", "vpn", "mpls", "bgp", "virtual", "serial", "unknown"}
)

VALID_DISCOVERY_PROTOCOLS: frozenset[str] = frozenset(
    {"lldp", "cdp", "arp", "snmp", "icmp", "bgp", "ospf", "netbios", "mdns", "tcp_scan", "manual"}
)

VALID_JOB_STATUSES: frozenset[str] = frozenset(
    {"queued", "running", "completed", "failed", "cancelled"}
)

TERMINAL_JOB_STATUSES: frozenset[str] = frozenset({"completed", "failed", "cancelled"})

VALID_FINDING_DISPOSITIONS: frozenset[str] = frozenset(
    {"new", "matched", "promoted", "ignored", "duplicate"}
)

VALID_DEPENDENCY_TYPES: frozenset[str] = frozenset(
    {"upstream_network", "power", "dns", "auth", "storage", "gateway", "routing", "application"}
)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_json_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("Expected JSON object.")
    raise ValueError(f"Unsupported type {type(value).__name__} for JSON object.")


def _coerce_json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        raise ValueError("Expected JSON array.")
    raise ValueError(f"Unsupported type {type(value).__name__} for JSON array.")


# ---------------------------------------------------------------------------
# Topology Nodes & Links
# ---------------------------------------------------------------------------


class TopologyNode(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Visual and logical node in an organization's network topology graph."""

    __tablename__ = "topology_nodes"
    __table_args__ = (
        Index("ix_topology_nodes_org_site", "org_id", "site_id"),
        Index("ix_topology_nodes_org_device", "org_id", "device_id"),
        Index("ix_topology_nodes_org_layer_status", "org_id", "layer", "status"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(150), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False, default="router", index=True)
    site_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("sites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    x_pos: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    y_pos: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    layer: Mapped[str] = mapped_column(String(50), nullable=False, default="access", index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown", index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    outgoing_links: Mapped[list[TopologyLink]] = relationship(
        "TopologyLink",
        foreign_keys="TopologyLink.source_node_id",
        back_populates="source_node",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    incoming_links: Mapped[list[TopologyLink]] = relationship(
        "TopologyLink",
        foreign_keys="TopologyLink.target_node_id",
        back_populates="target_node",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("metadata_json")
    def _validate_metadata(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    def set_position(self, x: float, y: float, *, pin: bool = True) -> None:
        """Update canvas coordinates and optionally lock the node against auto-layout."""
        self.x_pos = float(x)
        self.y_pos = float(y)
        self.pinned = pin

    def distance_to(self, other: TopologyNode) -> float:
        """Euclidean distance to another node on the topology canvas."""
        return math.hypot(
            (self.x_pos or 0.0) - (other.x_pos or 0.0),
            (self.y_pos or 0.0) - (other.y_pos or 0.0),
        )

    def to_graph_node(self) -> dict[str, Any]:
        """Serialize into a frontend graph renderer node payload."""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "label": self.label,
            "type": self.node_type,
            "site_id": self.site_id,
            "position": {"x": self.x_pos, "y": self.y_pos},
            "layer": self.layer,
            "status": self.status,
            "pinned": self.pinned,
            "metadata": self.metadata_json or {},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "label": self.label,
            "node_type": self.node_type,
            "site_id": self.site_id,
            "x_pos": self.x_pos,
            "y_pos": self.y_pos,
            "layer": self.layer,
            "status": self.status,
            "metadata_json": self.metadata_json or {},
            "pinned": self.pinned,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TopologyNode id={self.id!r} label={self.label!r} "
            f"type={self.node_type!r} status={self.status!r}>"
        )


class TopologyLink(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Physical or logical network link connecting two topology nodes."""

    __tablename__ = "topology_links"
    __table_args__ = (
        CheckConstraint("source_node_id != target_node_id", name="no_self_loop_link"),
        CheckConstraint(
            "utilization_pct >= 0.0 AND utilization_pct <= 100.0",
            name="link_utilization_range",
        ),
        CheckConstraint(
            "packet_loss_pct >= 0.0 AND packet_loss_pct <= 100.0",
            name="link_loss_range",
        ),
        Index("ix_topology_links_org_endpoints", "org_id", "source_node_id", "target_node_id"),
        Index("ix_topology_links_org_status", "org_id", "status"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_node_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("topology_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_node_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("topology_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_interface_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("device_interfaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_interface_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("device_interfaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    link_type: Mapped[str] = mapped_column(String(50), nullable=False, default="ethernet")
    discovery_protocol: Mapped[str] = mapped_column(String(50), nullable=False, default="lldp")
    bandwidth_mbps: Mapped[float | None] = mapped_column(Float, nullable=True, default=1000.0)
    utilization_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="up", index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    source_node: Mapped[TopologyNode] = relationship(
        "TopologyNode", foreign_keys=[source_node_id], back_populates="outgoing_links"
    )
    target_node: Mapped[TopologyNode] = relationship(
        "TopologyNode", foreign_keys=[target_node_id], back_populates="incoming_links"
    )

    @validates("metadata_json")
    def _validate_metadata(self, _key: str, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)

    @property
    def effective_throughput_mbps(self) -> float | None:
        """Estimated current link throughput derived from capacity and utilization."""
        if self.bandwidth_mbps is None:
            return None
        return round((self.bandwidth_mbps * (self.utilization_pct or 0.0)) / 100.0, 3)

    def is_congested(self, *, threshold_pct: float = 80.0) -> bool:
        return (self.utilization_pct or 0.0) >= threshold_pct

    def is_stale(self, *, max_age_seconds: int = 3600, now: datetime | None = None) -> bool:
        verified = _ensure_utc(self.last_verified_at)
        if verified is None:
            return True
        reference = _ensure_utc(now) or utcnow()
        return (reference - verified).total_seconds() > max_age_seconds

    def touch_verified(self, *, at: datetime | None = None) -> None:
        self.last_verified_at = at or utcnow()

    def to_graph_edge(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source_node_id,
            "target": self.target_node_id,
            "source_interface_id": self.source_interface_id,
            "target_interface_id": self.target_interface_id,
            "link_type": self.link_type,
            "discovery_protocol": self.discovery_protocol,
            "bandwidth_mbps": self.bandwidth_mbps,
            "utilization_pct": self.utilization_pct,
            "latency_ms": self.latency_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "status": self.status,
            "metadata": self.metadata_json or {},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "source_interface_id": self.source_interface_id,
            "target_interface_id": self.target_interface_id,
            "link_type": self.link_type,
            "discovery_protocol": self.discovery_protocol,
            "bandwidth_mbps": self.bandwidth_mbps,
            "utilization_pct": self.utilization_pct,
            "effective_throughput_mbps": self.effective_throughput_mbps,
            "latency_ms": self.latency_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "status": self.status,
            "metadata_json": self.metadata_json or {},
            "last_verified_at": (
                self.last_verified_at.isoformat() if self.last_verified_at else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TopologyLink id={self.id!r} {self.source_node_id!r}->{self.target_node_id!r} "
            f"util={self.utilization_pct}% status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# Auto-Discovery Jobs & Findings
# ---------------------------------------------------------------------------


class DiscoveryJob(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Network discovery sweep targeting CIDR blocks using SNMP/LLDP/CDP/ICMP/TCP."""

    __tablename__ = "discovery_jobs"
    __table_args__ = (
        CheckConstraint("progress_pct >= 0.0 AND progress_pct <= 100.0", name="discovery_progress_range"),
        CheckConstraint("hosts_scanned >= 0", name="hosts_scanned_non_negative"),
        CheckConstraint("devices_found >= 0", name="devices_found_non_negative"),
        CheckConstraint("links_found >= 0", name="links_found_non_negative"),
        Index("ix_discovery_jobs_org_status", "org_id", "status"),
        Index("ix_discovery_jobs_org_created", "org_id", "created_at"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    target_cidrs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    protocols_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    credential_profile_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued", index=True)
    progress_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    hosts_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    links_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list[DiscoveryFinding]] = relationship(
        "DiscoveryFinding",
        back_populates="job",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        normalized = (value or "queued").strip().lower()
        if normalized not in VALID_JOB_STATUSES:
            raise ValueError(
                f"Invalid DiscoveryJob status '{value}'. Expected one of {sorted(VALID_JOB_STATUSES)}."
            )
        return normalized

    @validates("target_cidrs_json")
    def _validate_cidrs(self, _key: str, value: Any) -> list[str]:
        return [str(c).strip() for c in _coerce_json_list(value) if str(c).strip()]

    @validates("protocols_json")
    def _validate_protocols(self, _key: str, value: Any) -> list[str]:
        return [str(p).strip().lower() for p in _coerce_json_list(value) if str(p).strip()]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_JOB_STATUSES

    @property
    def duration_seconds(self) -> float | None:
        started = _ensure_utc(self.started_at)
        if started is None:
            return None
        ended = _ensure_utc(self.completed_at) or utcnow()
        return round(max(0.0, (ended - started).total_seconds()), 2)

    def mark_running(self, *, at: datetime | None = None) -> None:
        self.status = "running"
        self.started_at = at or utcnow()
        self.completed_at = None
        self.error_summary = None

    def mark_completed(self, *, at: datetime | None = None) -> None:
        self.status = "completed"
        self.progress_pct = 100.0
        self.completed_at = at or utcnow()

    def mark_failed(self, error_summary: str, *, at: datetime | None = None) -> None:
        self.status = "failed"
        self.error_summary = error_summary
        self.completed_at = at or utcnow()

    def mark_cancelled(self, *, at: datetime | None = None) -> None:
        self.status = "cancelled"
        self.completed_at = at or utcnow()

    def update_progress(self, hosts_scanned: int, total_hosts: int) -> float:
        """Update scanned host count and clamped progress percentage."""
        self.hosts_scanned = max(0, hosts_scanned)
        if total_hosts > 0:
            self.progress_pct = round(min(100.0, (self.hosts_scanned / total_hosts) * 100.0), 2)
        return self.progress_pct

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "target_cidrs_json": self.target_cidrs_json or [],
            "protocols_json": self.protocols_json or [],
            "credential_profile_id": self.credential_profile_id,
            "status": self.status,
            "progress_pct": self.progress_pct,
            "hosts_scanned": self.hosts_scanned,
            "devices_found": self.devices_found,
            "links_found": self.links_found,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_summary": self.error_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<DiscoveryJob id={self.id!r} name={self.name!r} "
            f"status={self.status!r} progress={self.progress_pct}%>"
        )


class DiscoveryFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Single network host or device candidate identified during a DiscoveryJob."""

    __tablename__ = "discovery_findings"
    __table_args__ = (
        UniqueConstraint("job_id", "ip_address", name="uq_discovery_finding_job_ip"),
        Index("ix_discovery_findings_org_disposition", "org_id", "disposition"),
        Index("ix_discovery_findings_job_disposition", "job_id", "disposition"),
    )

    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    open_ports_json: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    snmp_sys_descr: Mapped[str | None] = mapped_column(Text, nullable=True)
    neighbors_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    matched_device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    disposition: Mapped[str] = mapped_column(String(50), nullable=False, default="new", index=True)

    job: Mapped[DiscoveryJob] = relationship("DiscoveryJob", back_populates="findings")

    @validates("disposition")
    def _validate_disposition(self, _key: str, value: str) -> str:
        normalized = (value or "new").strip().lower()
        if normalized not in VALID_FINDING_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition '{value}'. Expected one of {sorted(VALID_FINDING_DISPOSITIONS)}."
            )
        return normalized

    @validates("open_ports_json")
    def _validate_open_ports(self, _key: str, value: Any) -> list[int]:
        return [int(port) for port in _coerce_json_list(value)]

    @validates("neighbors_json")
    def _validate_neighbors(self, _key: str, value: Any) -> list[dict[str, Any]]:
        return [dict(item) if isinstance(item, dict) else {"value": item} for item in _coerce_json_list(value)]

    @property
    def is_matched(self) -> bool:
        return self.matched_device_id is not None

    def has_open_port(self, port: int) -> bool:
        return port in (self.open_ports_json or [])

    def promote_to_device(self, device_id: str) -> None:
        """Link this finding to a newly onboarded inventory device."""
        self.matched_device_id = device_id
        self.disposition = "promoted"

    def ignore(self) -> None:
        self.disposition = "ignored"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "org_id": self.org_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "open_ports_json": self.open_ports_json or [],
            "snmp_sys_descr": self.snmp_sys_descr,
            "neighbors_json": self.neighbors_json or [],
            "matched_device_id": self.matched_device_id,
            "disposition": self.disposition,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<DiscoveryFinding id={self.id!r} ip={self.ip_address!r} "
            f"vendor={self.vendor!r} disposition={self.disposition!r}>"
        )


# ---------------------------------------------------------------------------
# Causal Dependency Graph
# ---------------------------------------------------------------------------


class DependencyEdge(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """Directed dependency edge: ``child_device_id`` depends on ``parent_device_id``.

    Used by topology root-cause analysis (RCA) to suppress downstream symptom alerts
    when an upstream router, switch, power supply, or gateway fails.
    """

    __tablename__ = "dependency_edges"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "parent_device_id",
            "child_device_id",
            "dependency_type",
            name="uq_dependency_edge_pair_type",
        ),
        CheckConstraint("parent_device_id != child_device_id", name="no_self_dependency"),
        CheckConstraint("weight >= 0.0", name="dependency_weight_non_negative"),
        Index("ix_dependency_edges_org_parent", "org_id", "parent_device_id"),
        Index("ix_dependency_edges_org_child", "org_id", "child_device_id"),
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    child_device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    dependency_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="upstream_network", index=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    @validates("dependency_type")
    def _validate_dependency_type(self, _key: str, value: str) -> str:
        normalized = (value or "upstream_network").strip().lower()
        if normalized not in VALID_DEPENDENCY_TYPES:
            raise ValueError(
                f"Invalid dependency_type '{value}'. Expected one of {sorted(VALID_DEPENDENCY_TYPES)}."
            )
        return normalized

    def as_tuple(self) -> tuple[str, str]:
        """Return ``(parent_device_id, child_device_id)`` edge pair."""
        return (self.parent_device_id, self.child_device_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "parent_device_id": self.parent_device_id,
            "child_device_id": self.child_device_id,
            "weight": self.weight,
            "dependency_type": self.dependency_type,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<DependencyEdge id={self.id!r} {self.parent_device_id!r}->{self.child_device_id!r} "
            f"type={self.dependency_type!r} weight={self.weight}>"
        )


__all__ = [
    "TopologyNode",
    "TopologyLink",
    "DiscoveryJob",
    "DiscoveryFinding",
    "DependencyEdge",
    "VALID_NODE_TYPES",
    "VALID_TOPOLOGY_LAYERS",
    "VALID_LINK_TYPES",
    "VALID_DISCOVERY_PROTOCOLS",
    "VALID_JOB_STATUSES",
    "TERMINAL_JOB_STATUSES",
    "VALID_FINDING_DISPOSITIONS",
    "VALID_DEPENDENCY_TYPES",
]
