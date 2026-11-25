"""Network topology graph, auto-discovery, path analysis, blast radius, and dependencies.

Provides strongly typed Pydantic v2 contracts for:
- Topology graph vertices & edges: `TopologyNodeCreate/Update/Read`,
  `TopologyLinkCreate/Update/Read`, `TopologyGraphResponse` (nodes, links,
  graph stats, layout coordinates)
- Automated L2/L3 network discovery: `DiscoveryJobCreate/Read`,
  `DiscoveryFindingRead`
- Shortest/resilient path computation: `PathAnalysisRequest/Response`
- Failure impact & blast-radius propagation: `BlastRadiusRequest/Response`
- Directed service/infrastructure dependency graphs: `DependencyEdgeCreate/Read`
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Self

from pydantic import Field, computed_field, model_validator

from app.schemas.common import (
    BaseSchema,
    CIDRStr,
    IPAddressStr,
    MetadataDict,
    SeverityLevel,
    TagMap,
    TenantEntityReadSchema,
    UTCDatetime,
    utcnow,
)

# ---------------------------------------------------------------------------
# Topology & Discovery Enums
# ---------------------------------------------------------------------------


class NodeLayer(str, Enum):
    """Logical or physical layer placement of a topology node."""

    PHYSICAL = "physical"
    L2_SWITCHING = "l2_switching"
    L3_ROUTING = "l3_routing"
    OVERLAY = "overlay"
    SERVICE = "service"
    CLOUD = "cloud"


class NodeShape(str, Enum):
    """Visual glyph hint for interactive graph rendering."""

    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    CLOUD = "cloud"
    LOAD_BALANCER = "load_balancer"
    SITE = "site"
    SUBNET = "subnet"
    SERVICE = "service"
    GENERIC = "generic"


class LinkType(str, Enum):
    """Physical or logical link classification between two topology nodes."""

    PHYSICAL = "physical"
    LAG = "lag"
    TRUNK = "trunk"
    WAN = "wan"
    TUNNEL = "tunnel"
    BGP_PEERING = "bgp_peering"
    OSPF_ADJACENCY = "ospf_adjacency"
    WIRELESS = "wireless"
    LOGICAL = "logical"


class LinkProtocol(str, Enum):
    """Discovery or routing protocol that established a topology link."""

    LLDP = "lldp"
    CDP = "cdp"
    ARP = "arp"
    BGP = "bgp"
    OSPF = "ospf"
    ISIS = "isis"
    STP = "stp"
    TRACEROUTE = "traceroute"
    MANUAL = "manual"


class LinkStatus(str, Enum):
    """Operational state of a topology link."""

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    STANDBY = "standby"
    UNKNOWN = "unknown"


class LayoutAlgorithm(str, Enum):
    """Supported graph layout engines for client and server positioning."""

    FORCE_DIRECTED = "force_directed"
    HIERARCHICAL = "hierarchical"
    RADIAL = "radial"
    GEOGRAPHIC = "geographic"
    GRID = "grid"
    MANUAL = "manual"


class DiscoveryMethod(str, Enum):
    """Probing techniques available to an automated discovery job."""

    ICMP_SWEEP = "icmp_sweep"
    SNMP_WALK = "snmp_walk"
    LLDP_NEIGHBORS = "lldp_neighbors"
    CDP_NEIGHBORS = "cdp_neighbors"
    ARP_TABLE = "arp_table"
    BGP_PEERS = "bgp_peers"
    OSPF_NEIGHBORS = "ospf_neighbors"
    TCP_PORT_SCAN = "tcp_port_scan"
    DNS_REVERSE = "dns_reverse"


class DiscoveryJobStatus(str, Enum):
    """Execution lifecycle state of a network discovery job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoveryFindingType(str, Enum):
    """Category of artifact discovered during a scan."""

    NEW_DEVICE = "new_device"
    UPDATED_DEVICE = "updated_device"
    NEW_LINK = "new_link"
    NEW_SUBNET = "new_subnet"
    NEW_INTERFACE = "new_interface"
    IP_CONFLICT = "ip_conflict"
    UNREACHABLE_SEED = "unreachable_seed"
    AUTH_FAILURE = "auth_failure"


class DependencyType(str, Enum):
    """Semantic nature of a directed dependency edge between nodes."""

    NETWORK_UPLINK = "network_uplink"
    ROUTING = "routing"
    DNS_RESOLUTION = "dns_resolution"
    POWER = "power"
    VIRTUALIZATION_HOST = "virtualization_host"
    APPLICATION_CALL = "application_call"
    DATABASE = "database"
    STORAGE = "storage"
    AUTHENTICATION = "authentication"


class DependencyCriticality(str, Enum):
    """Severity of impact when an upstream dependency fails."""

    HARD = "hard"
    SOFT = "soft"
    REDUNDANT = "redundant"
    INFORMATIONAL = "informational"


# ---------------------------------------------------------------------------
# Topology Node & Link Schemas
# ---------------------------------------------------------------------------


class NodePosition(BaseSchema):
    """2D canvas or geographic coordinates for a topology node."""

    x: float = Field(default=0.0)
    y: float = Field(default=0.0)
    z: float | None = Field(default=None)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    pinned: bool = Field(
        default=False, description="When true, automatic layouts preserve x/y coordinates."
    )


class TopologyNodeCreate(BaseSchema):
    """Create a vertex in the network topology graph."""

    label: str = Field(..., min_length=1, max_length=128)
    device_id: str | None = Field(
        default=None, description="Optional backing inventory device UUID."
    )
    site_id: str | None = None
    layer: NodeLayer = Field(default=NodeLayer.L3_ROUTING)
    shape: NodeShape = Field(default=NodeShape.ROUTER)
    tier_rank: int = Field(
        default=2, ge=0, le=10, description="Hierarchical tier rank (0=core, higher=edge)."
    )
    management_ip: IPAddressStr | None = None
    status: str = Field(default="online", max_length=32)
    position: NodePosition = Field(default_factory=NodePosition)
    style: MetadataDict = Field(default_factory=dict)
    metadata: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)


class TopologyNodeUpdate(BaseSchema):
    """Partial update for a topology node."""

    label: str | None = Field(default=None, min_length=1, max_length=128)
    site_id: str | None = None
    layer: NodeLayer | None = None
    shape: NodeShape | None = None
    tier_rank: int | None = Field(default=None, ge=0, le=10)
    status: str | None = Field(default=None, max_length=32)
    position: NodePosition | None = None
    style: MetadataDict | None = None
    metadata: MetadataDict | None = None
    tags: TagMap | None = None


class TopologyNodeRead(TenantEntityReadSchema):
    """Full representation of a topology vertex with live telemetry overlay."""

    label: str
    device_id: str | None = None
    site_id: str | None = None
    layer: NodeLayer = NodeLayer.L3_ROUTING
    shape: NodeShape = NodeShape.ROUTER
    tier_rank: int = 2
    management_ip: str | None = None
    status: str = "online"
    position: NodePosition = Field(default_factory=NodePosition)
    cpu_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    latency_ms: float | None = Field(default=None, ge=0.0)
    active_alert_count: int = Field(default=0, ge=0)
    degree: int = Field(default=0, ge=0, description="Number of connected links.")
    style: MetadataDict = Field(default_factory=dict)
    metadata: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)


class TopologyLinkCreate(BaseSchema):
    """Create a physical or logical link between two topology nodes."""

    source_node_id: str = Field(..., description="Origin topology node UUID.")
    target_node_id: str = Field(..., description="Destination topology node UUID.")
    source_interface_id: str | None = None
    target_interface_id: str | None = None
    source_interface_name: str | None = Field(default=None, max_length=128)
    target_interface_name: str | None = Field(default=None, max_length=128)
    label: str | None = Field(default=None, max_length=160)
    link_type: LinkType = Field(default=LinkType.PHYSICAL)
    protocol: LinkProtocol = Field(default=LinkProtocol.MANUAL)
    status: LinkStatus = Field(default=LinkStatus.UP)
    bandwidth_mbps: int | None = Field(default=None, ge=1, le=10_000_000)
    latency_ms: float | None = Field(default=None, ge=0.0)
    utilization_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cost: float = Field(default=1.0, gt=0.0, description="Routing/graph traversal weight.")
    bidirectional: bool = Field(default=True)
    metadata: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)

    @model_validator(mode="after")
    def _reject_self_loop(self) -> Self:
        if self.source_node_id == self.target_node_id:
            raise ValueError("Topology link cannot connect a node to itself.")
        return self


class TopologyLinkUpdate(BaseSchema):
    """Partial update for a topology link."""

    source_interface_name: str | None = Field(default=None, max_length=128)
    target_interface_name: str | None = Field(default=None, max_length=128)
    label: str | None = Field(default=None, max_length=160)
    link_type: LinkType | None = None
    protocol: LinkProtocol | None = None
    status: LinkStatus | None = None
    bandwidth_mbps: int | None = Field(default=None, ge=1, le=10_000_000)
    latency_ms: float | None = Field(default=None, ge=0.0)
    utilization_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cost: float | None = Field(default=None, gt=0.0)
    bidirectional: bool | None = None
    metadata: MetadataDict | None = None
    tags: TagMap | None = None


class TopologyLinkRead(TenantEntityReadSchema):
    """Full representation of a topology link with live performance telemetry."""

    source_node_id: str
    target_node_id: str
    source_interface_id: str | None = None
    target_interface_id: str | None = None
    source_interface_name: str | None = None
    target_interface_name: str | None = None
    label: str | None = None
    link_type: LinkType = LinkType.PHYSICAL
    protocol: LinkProtocol = LinkProtocol.MANUAL
    status: LinkStatus = LinkStatus.UP
    bandwidth_mbps: int | None = None
    latency_ms: float | None = None
    utilization_pct: float | None = None
    packet_loss_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    cost: float = 1.0
    bidirectional: bool = True
    last_verified_at: UTCDatetime | None = None
    metadata: MetadataDict = Field(default_factory=dict)
    tags: TagMap = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Topology Graph Snapshot Schemas
# ---------------------------------------------------------------------------


class TopologyGraphStats(BaseSchema):
    """Structural graph metrics computed across the rendered topology."""

    node_count: int = Field(default=0, ge=0)
    link_count: int = Field(default=0, ge=0)
    connected_components: int = Field(default=0, ge=0)
    isolated_nodes: int = Field(default=0, ge=0)
    degraded_links: int = Field(default=0, ge=0)
    down_links: int = Field(default=0, ge=0)
    avg_degree: float = Field(default=0.0, ge=0.0)
    articulation_point_ids: list[str] = Field(
        default_factory=list,
        description="Single-point-of-failure nodes whose removal partitions the graph.",
    )


class TopologyLayoutConfig(BaseSchema):
    """Layout algorithm configuration and computed bounding box."""

    algorithm: LayoutAlgorithm = Field(default=LayoutAlgorithm.HIERARCHICAL)
    direction: Literal["TB", "BT", "LR", "RL"] = Field(default="TB")
    node_spacing: float = Field(default=120.0, gt=0.0)
    rank_spacing: float = Field(default=160.0, gt=0.0)
    bounds_width: float = Field(default=1200.0, ge=0.0)
    bounds_height: float = Field(default=800.0, ge=0.0)


class TopologyGraphResponse(BaseSchema):
    """Complete topology graph snapshot ready for visualization and analysis."""

    generated_at: UTCDatetime = Field(default_factory=utcnow)
    site_id: str | None = None
    layer: NodeLayer | None = None
    nodes: list[TopologyNodeRead] = Field(default_factory=list)
    links: list[TopologyLinkRead] = Field(default_factory=list)
    stats: TopologyGraphStats = Field(default_factory=TopologyGraphStats)
    layout: TopologyLayoutConfig = Field(default_factory=TopologyLayoutConfig)


# ---------------------------------------------------------------------------
# Network Auto-Discovery Schemas
# ---------------------------------------------------------------------------


class DiscoveryJobCreate(BaseSchema):
    """Launch an automated network discovery sweep over seed CIDRs or IPs."""

    name: str = Field(..., min_length=2, max_length=120)
    seed_cidrs: list[CIDRStr] = Field(default_factory=list, max_length=50)
    seed_ips: list[IPAddressStr] = Field(default_factory=list, max_length=200)
    exclude_cidrs: list[CIDRStr] = Field(default_factory=list, max_length=50)
    methods: list[DiscoveryMethod] = Field(
        default_factory=lambda: [
            DiscoveryMethod.ICMP_SWEEP,
            DiscoveryMethod.SNMP_WALK,
            DiscoveryMethod.LLDP_NEIGHBORS,
        ],
        min_length=1,
    )
    credential_profile_ids: list[str] = Field(default_factory=list)
    site_id: str | None = None
    edge_agent_id: str | None = None
    max_hops: int = Field(default=3, ge=0, le=16)
    max_hosts: int = Field(default=1024, ge=1, le=65536)
    concurrency: int = Field(default=32, ge=1, le=256)
    timeout_seconds: float = Field(default=3.0, ge=0.5, le=60.0)
    auto_onboard_devices: bool = Field(
        default=False, description="Automatically create inventory devices for new discoveries."
    )
    auto_create_links: bool = Field(
        default=True, description="Automatically materialize LLDP/CDP/BGP links in topology."
    )

    @model_validator(mode="after")
    def _require_seed_targets(self) -> Self:
        if not self.seed_cidrs and not self.seed_ips:
            raise ValueError("Discovery job requires at least one entry in 'seed_cidrs' or 'seed_ips'.")
        return self


class DiscoveryJobRead(TenantEntityReadSchema):
    """Status and progress metrics for a network discovery job."""

    name: str
    status: DiscoveryJobStatus = DiscoveryJobStatus.QUEUED
    seed_cidrs: list[str] = Field(default_factory=list)
    seed_ips: list[str] = Field(default_factory=list)
    methods: list[DiscoveryMethod] = Field(default_factory=list)
    site_id: str | None = None
    edge_agent_id: str | None = None
    max_hops: int = 3
    auto_onboard_devices: bool = False
    auto_create_links: bool = True
    started_at: UTCDatetime | None = None
    completed_at: UTCDatetime | None = None
    hosts_scanned: int = Field(default=0, ge=0)
    hosts_reachable: int = Field(default=0, ge=0)
    devices_discovered: int = Field(default=0, ge=0)
    links_discovered: int = Field(default=0, ge=0)
    findings_count: int = Field(default=0, ge=0)
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    error_message: str | None = None


class DiscoveryFindingRead(TenantEntityReadSchema):
    """Individual device, link, subnet, or conflict observed by a discovery job."""

    job_id: str
    finding_type: DiscoveryFindingType
    method: DiscoveryMethod
    target_ip: str | None = None
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    sys_description: str | None = None
    linked_device_id: str | None = None
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    is_applied: bool = Field(default=False)
    details: MetadataDict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Path Analysis, Blast Radius, and Dependency Graph Schemas
# ---------------------------------------------------------------------------


class PathAnalysisRequest(BaseSchema):
    """Compute shortest and redundant network paths between two topology nodes."""

    source_node_id: str
    target_node_id: str
    weight_metric: Literal["hops", "latency_ms", "cost", "utilization_pct"] = Field(
        default="latency_ms"
    )
    max_paths: int = Field(default=3, ge=1, le=10)
    max_hops: int = Field(default=16, ge=1, le=64)
    exclude_down_links: bool = Field(default=True)
    avoid_node_ids: list[str] = Field(default_factory=list)
    avoid_link_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _distinct_endpoints(self) -> Self:
        if self.source_node_id == self.target_node_id:
            raise ValueError("'source_node_id' and 'target_node_id' must be distinct.")
        return self


class PathHop(BaseSchema):
    """Single hop within a computed topology path."""

    hop_index: int = Field(..., ge=0)
    node_id: str
    node_label: str
    link_id: str | None = None
    egress_interface: str | None = None
    ingress_interface: str | None = None
    hop_latency_ms: float | None = Field(default=None, ge=0.0)
    link_bandwidth_mbps: int | None = None
    link_utilization_pct: float | None = None


class ComputedPath(BaseSchema):
    """A single end-to-end route candidate with aggregated cost metrics."""

    rank: int = Field(..., ge=1)
    hop_count: int = Field(..., ge=1)
    total_cost: float = Field(..., ge=0.0)
    total_latency_ms: float | None = Field(default=None, ge=0.0)
    bottleneck_bandwidth_mbps: int | None = None
    max_link_utilization_pct: float | None = None
    hops: list[PathHop] = Field(default_factory=list)


class PathAnalysisResponse(BaseSchema):
    """Result of shortest/k-shortest path computation across the topology."""

    source_node_id: str
    target_node_id: str
    weight_metric: str
    reachable: bool
    paths: list[ComputedPath] = Field(default_factory=list)
    single_points_of_failure: list[str] = Field(
        default_factory=list,
        description="Intermediate node IDs appearing in every available path.",
    )
    computed_at: UTCDatetime = Field(default_factory=utcnow)


class BlastRadiusRequest(BaseSchema):
    """Simulate failure propagation from one or more failed root nodes."""

    root_node_ids: list[str] = Field(..., min_length=1, max_length=25)
    max_depth: int = Field(default=6, ge=1, le=20)
    include_soft_dependencies: bool = Field(default=True)
    ignore_redundant_paths: bool = Field(
        default=False,
        description="When false, nodes with alternate healthy upstream paths have reduced impact.",
    )


class ImpactedNode(BaseSchema):
    """Downstream node affected by a simulated or real failure event."""

    node_id: str
    label: str
    device_id: str | None = None
    hop_distance: int = Field(..., ge=1)
    impact_severity: SeverityLevel
    impact_score: float = Field(..., ge=0.0, le=100.0)
    dependency_type: DependencyType | None = None
    has_failover: bool = False
    propagation_path: list[str] = Field(default_factory=list)


class BlastRadiusResponse(BaseSchema):
    """Failure blast-radius simulation report."""

    root_node_ids: list[str]
    total_impacted_nodes: int = Field(default=0, ge=0)
    critical_impact_count: int = Field(default=0, ge=0)
    degraded_impact_count: int = Field(default=0, ge=0)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    overall_severity: SeverityLevel = SeverityLevel.LOW
    impacted_nodes: list[ImpactedNode] = Field(default_factory=list)
    affected_site_ids: list[str] = Field(default_factory=list)
    affected_slo_ids: list[str] = Field(default_factory=list)
    computed_at: UTCDatetime = Field(default_factory=utcnow)

    @computed_field
    @property
    def is_wide_outage(self) -> bool:
        """True when 5 or more nodes suffer critical impact."""
        return self.critical_impact_count >= 5


class DependencyEdgeCreate(BaseSchema):
    """Define a directed dependency where downstream relies on upstream."""

    upstream_node_id: str = Field(..., description="Provider/parent topology node UUID.")
    downstream_node_id: str = Field(..., description="Dependent/child topology node UUID.")
    dependency_type: DependencyType = Field(default=DependencyType.NETWORK_UPLINK)
    criticality: DependencyCriticality = Field(default=DependencyCriticality.HARD)
    weight: float = Field(default=1.0, gt=0.0, le=100.0)
    failover_available: bool = Field(default=False)
    description: str | None = Field(default=None, max_length=500)
    metadata: MetadataDict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _reject_self_dependency(self) -> Self:
        if self.upstream_node_id == self.downstream_node_id:
            raise ValueError("A node cannot depend on itself.")
        return self


class DependencyEdgeRead(TenantEntityReadSchema):
    """Persisted directed dependency edge in the service/infrastructure DAG."""

    upstream_node_id: str
    downstream_node_id: str
    dependency_type: DependencyType = DependencyType.NETWORK_UPLINK
    criticality: DependencyCriticality = DependencyCriticality.HARD
    weight: float = 1.0
    failover_available: bool = False
    description: str | None = None
    metadata: MetadataDict = Field(default_factory=dict)
