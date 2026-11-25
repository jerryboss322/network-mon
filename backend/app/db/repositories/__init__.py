"""Unified exports for all NetPulse data-access repositories."""

from __future__ import annotations

from app.db.repositories.base import (
    BaseRepository,
    FilterOperator,
    FilterSpec,
    ModelT,
    PageResult,
    SortSpec,
    normalize_filters,
    normalize_ordering,
    resolve_model,
)
from app.db.repositories.identity import (
    ApiKeyRepository,
    AuditLogRepository,
    OrganizationRepository,
    UserRepository,
    UserSessionRepository,
    WebhookEndpointRepository,
)
from app.db.repositories.inventory import (
    CredentialRepository,
    DeviceGroupRepository,
    DeviceRepository,
    InterfaceRepository,
    RackRepository,
    SiteRepository,
    SubnetRepository,
    VlanRepository,
)
from app.db.repositories.operations import (
    AlertEventRepository,
    AlertRuleRepository,
    ComplianceRepository,
    ConfigSnapshotRepository,
    DiscoveryJobRepository,
    IncidentRepository,
    MaintenanceWindowRepository,
    PlaybookRepository,
    ReportRepository,
    SloRepository,
    TopologyRepository,
)
from app.db.repositories.telemetry import (
    BgpPeerRepository,
    EdgeAgentRepository,
    HostSampleRepository,
    IcmpSampleRepository,
    MetricRollupRepository,
    NetFlowRepository,
    SnmpSampleRepository,
    SyntheticProbeRepository,
    SyslogRepository,
)

__all__ = [
    # Base
    "BaseRepository",
    "FilterOperator",
    "FilterSpec",
    "ModelT",
    "PageResult",
    "SortSpec",
    "normalize_filters",
    "normalize_ordering",
    "resolve_model",
    # Identity
    "OrganizationRepository",
    "UserRepository",
    "UserSessionRepository",
    "ApiKeyRepository",
    "AuditLogRepository",
    "WebhookEndpointRepository",
    # Inventory
    "SiteRepository",
    "RackRepository",
    "CredentialRepository",
    "DeviceRepository",
    "InterfaceRepository",
    "SubnetRepository",
    "VlanRepository",
    "DeviceGroupRepository",
    # Telemetry
    "SnmpSampleRepository",
    "IcmpSampleRepository",
    "SyntheticProbeRepository",
    "HostSampleRepository",
    "MetricRollupRepository",
    "SyslogRepository",
    "NetFlowRepository",
    "BgpPeerRepository",
    "EdgeAgentRepository",
    # Operations & Automation
    "TopologyRepository",
    "DiscoveryJobRepository",
    "AlertRuleRepository",
    "AlertEventRepository",
    "IncidentRepository",
    "SloRepository",
    "MaintenanceWindowRepository",
    "ConfigSnapshotRepository",
    "ComplianceRepository",
    "PlaybookRepository",
    "ReportRepository",
]
