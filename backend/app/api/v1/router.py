"""Master API v1 router aggregating all NetPulse domain routers with OpenAPI metadata.

Combines all Phase 2 platform domains under a single versioned ``APIRouter``:
- **Health & System** (``app.api.v1.health``): liveness, readiness, system info,
  platform stats overview, and idempotent demo seeding.
- **Authentication & RBAC** (``app.api.v1.auth``): registration, login, token
  refresh/revocation, password management, demo tokens, and RBAC permission matrix.
- **Organization, Users, API Keys, Audit & Webhooks** (``app.api.v1.users``):
  tenant administration, user lifecycle, programmatic API keys, compliance audit
  trails, and outbound webhooks.
- **Sites & Racks** (``app.api.v1.sites``): physical data centers, geographic
  site health summaries, racks, and top-to-bottom U-slot elevation models.
- **Devices & Groups** (``app.api.v1.devices``): CMDB device inventory, search,
  bulk onboarding, JSON/CSV export, network interfaces, and static/dynamic groups.
- **IPAM & Credentials** (``app.api.v1.ipam``): IPv4/IPv6 subnets, CIDR/VLSM
  calculator, IP allocations, IEEE 802.1Q VLANs, Fernet credential vault, and
  MAC/OUI + port network utilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter

from app.api.v1 import auth, devices, health, ipam, sites, users

logger = logging.getLogger("netpulse.api.v1.router")


# ---------------------------------------------------------------------------
# OpenAPI Tag Catalog
# ---------------------------------------------------------------------------

OPENAPI_TAGS: list[dict[str, Any]] = [
    {
        "name": "Health & System",
        "description": (
            "Liveness, readiness, runtime diagnostics, platform-wide KPI summaries, "
            "and idempotent demo dataset seeding."
        ),
    },
    {
        "name": "Authentication & RBAC",
        "description": (
            "JWT access/refresh token lifecycle, session revocation, password "
            "management, demo authentication, and RBAC role/permission introspection."
        ),
    },
    {
        "name": "Organization, Users, API Keys, Audit & Webhooks",
        "description": (
            "Multi-tenant organization settings and quotas, operator account "
            "administration, scoped API key management, compliance audit logs, "
            "and outbound event webhook subscriptions."
        ),
    },
    {
        "name": "Sites & Racks",
        "description": (
            "Physical infrastructure hierarchy: data centers, POPs, branch offices, "
            "equipment racks, capacity summaries, and top-to-bottom U-slot elevation diagrams."
        ),
    },
    {
        "name": "Devices & Groups",
        "description": (
            "CMDB asset inventory for routers, switches, firewalls, load balancers, "
            "and servers; bulk import/export; physical/logical network interfaces; "
            "and static or dynamic rule-based device groups."
        ),
    },
    {
        "name": "IPAM & Credentials",
        "description": (
            "IPv4/IPv6 subnet management, CIDR/VLSM calculator and overlap checker, "
            "IP address allocations, IEEE 802.1Q VLANs, Fernet-encrypted polling "
            "credential vault (strictly redacted on reads), and MAC OUI / port utilities."
        ),
    },
]


# ---------------------------------------------------------------------------
# Router Registration Metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MountedRouterInfo:
    """Descriptor tracking each sub-router mounted into ``api_v1_router``."""

    module: str
    tag: str
    prefix: str
    route_count: int


_SUB_ROUTERS: tuple[tuple[str, str, APIRouter], ...] = (
    ("health", "Health & System", health.router),
    ("auth", "Authentication & RBAC", auth.router),
    ("users", "Organization, Users, API Keys, Audit & Webhooks", users.router),
    ("sites", "Sites & Racks", sites.router),
    ("devices", "Devices & Groups", devices.router),
    ("ipam", "IPAM & Credentials", ipam.router),
)


def build_v1_router() -> tuple[APIRouter, list[MountedRouterInfo]]:
    """Construct and return the master ``api_v1_router`` along with mounted diagnostics."""
    master = APIRouter()
    mounted: list[MountedRouterInfo] = []

    for module_name, tag_name, sub_router in _SUB_ROUTERS:
        master.include_router(sub_router)
        mounted.append(
            MountedRouterInfo(
                module=module_name,
                tag=tag_name,
                prefix=sub_router.prefix or "",
                route_count=len(sub_router.routes),
            )
        )
        logger.debug(
            "Mounted API v1 module '%s' (%d routes, prefix=%r)",
            module_name,
            len(sub_router.routes),
            sub_router.prefix,
        )

    @master.get(
        "/meta",
        tags=["Health & System"],
        summary="Describe registered API v1 modules and route counts",
    )
    def api_v1_meta() -> dict[str, Any]:
        """Return a catalog of mounted API v1 modules and total registered endpoints."""
        return {
            "api_version": "v1",
            "total_routes": sum(m.route_count for m in mounted),
            "modules": [
                {
                    "module": m.module,
                    "tag": m.tag,
                    "prefix": m.prefix,
                    "route_count": m.route_count,
                }
                for m in mounted
            ],
        }

    return master, mounted


api_v1_router, _MOUNTED_ROUTERS = build_v1_router()


def get_mounted_routers() -> list[dict[str, Any]]:
    """Return metadata for all sub-routers registered on :data:`api_v1_router`."""
    return [
        {
            "module": info.module,
            "tag": info.tag,
            "prefix": info.prefix,
            "route_count": info.route_count,
        }
        for info in _MOUNTED_ROUTERS
    ]


__all__ = [
    "OPENAPI_TAGS",
    "MountedRouterInfo",
    "api_v1_router",
    "build_v1_router",
    "get_mounted_routers",
]
