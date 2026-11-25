"""Health, readiness, system info, overview statistics, and demo seeding endpoints."""

from __future__ import annotations

import os
import platform
import sys
import time
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, inspect as sa_inspect, select, text
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    ensure_database_ready,
    get_current_auth,
    get_db_session,
    rate_limit_dependency,
)
from app.core.cache import get_cache_registry
from app.core.config import Settings, get_settings
from app.core.events import get_event_bus
from app.core.exceptions import AuthorizationError
from app.core.logging import get_logger, get_request_id
from app.core.security import Permission
from app.db.repositories.identity import AuditLogRepository
from app.db.seed import DEFAULT_ADMIN_EMAIL, DEFAULT_ORG_SLUG, seed_enterprise_demo
from app.models.alerting import AlertEvent, Incident
from app.models.automation import ComplianceEvaluation, PlaybookRun
from app.models.enums import AgentStatus, AlertStatus, DeviceStatus, IncidentStatus
from app.models.identity import Organization, User
from app.models.inventory import Device, DeviceInterface, Site, Subnet
from app.models.telemetry import (
    EdgeAgent,
    HostMetricSample,
    IcmpMetricSample,
    SnmpMetricSample,
    SyntheticProbeConfig,
    SyntheticProbeResult,
)
from app.schemas.common import (
    BaseSchema,
    ComponentHealth,
    HealthCheckResponse,
    HealthStatus,
    PlatformStatsSummary,
    utcnow,
)

logger = get_logger("netpulse.api.health")

router = APIRouter(tags=["Health & System"])

_PROCESS_START_MONOTONIC = time.monotonic()
_PROCESS_STARTED_AT = utcnow()

_REQUIRED_CORE_TABLES: tuple[str, ...] = (
    "organizations",
    "users",
    "devices",
    "sites",
    "alert_events",
    "incidents",
)


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class SystemInfoResponse(BaseSchema):
    """Sanitized runtime and configuration diagnostics for platform operators."""

    app_name: str
    version: str
    environment: str
    is_vercel: bool
    runtime_mode: str
    python_version: str
    platform: str
    uptime_seconds: float
    started_at: str
    database_dialect: str
    is_sqlite: bool
    api_v1_prefix: str
    collectors: dict[str, Any]
    retention: dict[str, int]
    security_policy: dict[str, Any]
    event_bus: dict[str, Any]
    caches: dict[str, Any]


class SeedTriggerRequest(BaseSchema):
    """Optional parameters for triggering the idempotent demo dataset seeder."""

    force: bool = False


class SeedTriggerResponse(BaseSchema):
    """Result payload returned after executing or verifying the demo seeder."""

    seeded: bool
    reason: str | None = None
    org_id: str | None = None
    org_slug: str
    admin_email: str
    summary: dict[str, Any]


# ---------------------------------------------------------------------------
# Internal Health Probe Helpers
# ---------------------------------------------------------------------------


def _uptime_seconds() -> float:
    return round(max(0.0, time.monotonic() - _PROCESS_START_MONOTONIC), 3)


def _probe_database(db: Session) -> ComponentHealth:
    started = time.perf_counter_ns()
    try:
        db.execute(text("SELECT 1")).scalar_one()
        latency_ms = round((time.perf_counter_ns() - started) / 1_000_000.0, 2)
        bind = db.get_bind()
        dialect = bind.dialect.name if bind is not None else "unknown"
        return ComponentHealth(
            name="database",
            status=HealthStatus.HEALTHY,
            latency_ms=latency_ms,
            message="Database connection responding normally",
            details={"dialect": dialect},
        )
    except Exception as exc:
        latency_ms = round((time.perf_counter_ns() - started) / 1_000_000.0, 2)
        logger.error("Database health probe failed: %s", exc)
        return ComponentHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            latency_ms=latency_ms,
            message="Database connectivity check failed",
            details={"error_type": type(exc).__name__},
        )


def _probe_schema_and_seed(db: Session) -> ComponentHealth:
    started = time.perf_counter_ns()
    try:
        bind = db.get_bind()
        inspector = sa_inspect(bind)
        existing_tables = set(inspector.get_table_names())
        missing = [tbl for tbl in _REQUIRED_CORE_TABLES if tbl not in existing_tables]
        if missing:
            return ComponentHealth(
                name="schema",
                status=HealthStatus.UNHEALTHY,
                latency_ms=round((time.perf_counter_ns() - started) / 1_000_000.0, 2),
                message=f"Missing required tables: {', '.join(missing)}",
                details={"missing_tables": missing, "table_count": len(existing_tables)},
            )
        org_count = int(db.execute(select(func.count()).select_from(Organization)).scalar_one())
        latency_ms = round((time.perf_counter_ns() - started) / 1_000_000.0, 2)
        if org_count == 0:
            return ComponentHealth(
                name="schema",
                status=HealthStatus.DEGRADED,
                latency_ms=latency_ms,
                message="Schema initialized but no organizations exist yet",
                details={"table_count": len(existing_tables), "organizations": 0},
            )
        return ComponentHealth(
            name="schema",
            status=HealthStatus.HEALTHY,
            latency_ms=latency_ms,
            message="Schema ready with active tenant data",
            details={"table_count": len(existing_tables), "organizations": org_count},
        )
    except Exception as exc:
        return ComponentHealth(
            name="schema",
            status=HealthStatus.UNHEALTHY,
            latency_ms=round((time.perf_counter_ns() - started) / 1_000_000.0, 2),
            message="Failed to inspect database schema",
            details={"error_type": type(exc).__name__},
        )


def _probe_event_bus() -> ComponentHealth:
    bus = get_event_bus()
    stats = bus.stats()
    dlq_count = int(stats.get("dead_letter_count", 0))
    bus_status = HealthStatus.DEGRADED if dlq_count > 50 else HealthStatus.HEALTHY
    return ComponentHealth(
        name="event_bus",
        status=bus_status,
        latency_ms=0.0,
        message="In-process event bus operational",
        details=stats,
    )


def _probe_cache_registry() -> ComponentHealth:
    registry = get_cache_registry()
    all_stats = registry.all_stats()
    return ComponentHealth(
        name="cache",
        status=HealthStatus.HEALTHY,
        latency_ms=0.0,
        message=f"{len(all_stats)} named caches registered",
        details={"cache_count": len(all_stats)},
    )


def _aggregate_status(components: list[ComponentHealth]) -> HealthStatus:
    statuses = {comp.status for comp in components}
    if HealthStatus.UNHEALTHY in statuses:
        return HealthStatus.UNHEALTHY
    if HealthStatus.DEGRADED in statuses:
        return HealthStatus.DEGRADED
    if not statuses:
        return HealthStatus.UNKNOWN
    return HealthStatus.HEALTHY


def _can_seed_system(auth: AuthContext | None, settings: Settings, *, force: bool) -> bool:
    if auth is not None and auth.has_permission(Permission.ADMIN_SYSTEM_CONFIG):
        return True
    if force and settings.environment == "production" and not settings.is_vercel:
        return False
    return bool(
        settings.is_vercel
        or settings.collectors.simulate_demo_telemetry
        or settings.environment in {"development", "test"}
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    summary="Liveness and lightweight subsystem health check",
)
def health_check(
    db: Session = Depends(get_db_session),
) -> HealthCheckResponse:
    """Return service liveness, uptime, and lightweight subsystem status."""
    settings = get_settings()
    components = [
        _probe_database(db),
        _probe_event_bus(),
        _probe_cache_registry(),
    ]
    overall = _aggregate_status(components)
    return HealthCheckResponse(
        status=overall,
        service=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        uptime_seconds=_uptime_seconds(),
        timestamp=utcnow(),
        components=components,
    )


@router.get(
    "/ready",
    response_model=HealthCheckResponse,
    summary="Deep readiness probe verifying database, schema, and seed readiness",
)
def readiness_check(
    db: Session = Depends(get_db_session),
) -> JSONResponse | HealthCheckResponse:
    """Verify the service is ready to accept production traffic.

    Returns HTTP 200 when healthy or degraded-but-serving, and HTTP 503 when
    any critical subsystem is unhealthy.
    """
    settings = get_settings()
    components = [
        _probe_database(db),
        _probe_schema_and_seed(db),
        _probe_event_bus(),
        _probe_cache_registry(),
    ]
    overall = _aggregate_status(components)
    payload = HealthCheckResponse(
        status=overall,
        service=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        uptime_seconds=_uptime_seconds(),
        timestamp=utcnow(),
        components=components,
    )
    if overall == HealthStatus.UNHEALTHY:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload.model_dump(mode="json"),
        )
    return payload


@router.get(
    "/system/info",
    response_model=SystemInfoResponse,
    summary="Inspect sanitized runtime, collector, retention, and cache diagnostics",
)
def system_info(
    _auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db_session),
) -> SystemInfoResponse:
    """Return runtime environment, dialect, collector, retention, and cache metadata."""
    settings = get_settings()
    bind = db.get_bind()
    dialect = bind.dialect.name if bind is not None else ("sqlite" if settings.is_sqlite else "unknown")
    runtime_mode = "vercel_serverless" if settings.is_vercel else "self_hosted"

    return SystemInfoResponse(
        app_name=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        is_vercel=settings.is_vercel,
        runtime_mode=runtime_mode,
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        uptime_seconds=_uptime_seconds(),
        started_at=_PROCESS_STARTED_AT.isoformat(),
        database_dialect=dialect,
        is_sqlite=settings.is_sqlite,
        api_v1_prefix=settings.api_v1_prefix,
        collectors={
            "enabled": settings.collectors.enabled,
            "simulate_demo_telemetry": settings.collectors.simulate_demo_telemetry,
            "icmp_interval_seconds": settings.collectors.icmp_interval_seconds,
            "snmp_interval_seconds": settings.collectors.snmp_interval_seconds,
            "synthetic_interval_seconds": settings.collectors.synthetic_interval_seconds,
            "host_interval_seconds": settings.collectors.host_interval_seconds,
            "max_concurrent_probes": settings.collectors.max_concurrent_probes,
            "syslog_udp_port": settings.collectors.syslog_udp_port,
            "netflow_udp_port": settings.collectors.netflow_udp_port,
        },
        retention={
            "raw_metrics_days": settings.retention.raw_metrics_days,
            "rollup_1m_days": settings.retention.rollup_1m_days,
            "rollup_5m_days": settings.retention.rollup_5m_days,
            "rollup_1h_days": settings.retention.rollup_1h_days,
            "syslog_days": settings.retention.syslog_days,
            "netflow_days": settings.retention.netflow_days,
            "audit_log_days": settings.retention.audit_log_days,
        },
        security_policy={
            "jwt_algorithm": settings.security.jwt_algorithm,
            "access_token_expire_minutes": settings.security.access_token_expire_minutes,
            "refresh_token_expire_days": settings.security.refresh_token_expire_days,
            "password_min_length": settings.security.password_min_length,
            "api_key_prefix": settings.security.api_key_prefix,
            "max_login_attempts": settings.security.max_login_attempts,
            "lockout_minutes": settings.security.lockout_minutes,
            "demo_fallback_mode": bool(
                os.getenv("NETMON_DEMO_FALLBACK", "").lower() in {"1", "true"}
                or settings.is_vercel
                or settings.environment in {"development", "test"}
            ),
        },
        event_bus=get_event_bus().stats(),
        caches=get_cache_registry().all_stats(),
    )


@router.get(
    "/stats/overview",
    response_model=PlatformStatsSummary,
    summary="Executive KPI snapshot across inventory, alerts, telemetry, compliance, and automation",
)
def stats_overview(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db_session),
) -> PlatformStatsSummary:
    """Compute real-time tenant KPI metrics for executive and NOC overview dashboards."""
    org_id = auth.org_id
    now = utcnow()
    one_hour_ago = now - timedelta(hours=1)
    one_day_ago = now - timedelta(hours=24)

    # Organizations & active users
    organizations_total = int(
        db.execute(
            select(func.count())
            .select_from(Organization)
            .where(Organization.is_deleted.is_(False))
        ).scalar_one()
    )
    users_active = int(
        db.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.org_id == org_id,
                User.is_deleted.is_(False),
                User.is_active.is_(True),
            )
        ).scalar_one()
    )

    # Sites & device availability breakdown
    sites_total = int(
        db.execute(
            select(func.count())
            .select_from(Site)
            .where(Site.org_id == org_id, Site.is_deleted.is_(False))
        ).scalar_one()
    )

    device_status_rows = db.execute(
        select(Device.status, func.count())
        .where(Device.org_id == org_id, Device.is_deleted.is_(False))
        .group_by(Device.status)
    ).all()
    status_counts: dict[str, int] = {str(st): int(cnt) for st, cnt in device_status_rows}
    devices_total = sum(status_counts.values())
    devices_online = status_counts.get(DeviceStatus.UP.value, 0)
    devices_degraded = (
        status_counts.get(DeviceStatus.DEGRADED.value, 0)
        + status_counts.get(DeviceStatus.WARNING.value, 0)
    )
    devices_offline = (
        status_counts.get(DeviceStatus.DOWN.value, 0)
        + status_counts.get(DeviceStatus.CRITICAL.value, 0)
        + status_counts.get(DeviceStatus.UNREACHABLE.value, 0)
    )
    devices_maintenance = status_counts.get(DeviceStatus.MAINTENANCE.value, 0)

    # Interfaces & IPAM
    interfaces_monitored = int(
        db.execute(
            select(func.count())
            .select_from(DeviceInterface)
            .where(
                DeviceInterface.org_id == org_id,
                DeviceInterface.is_monitored.is_(True),
            )
        ).scalar_one()
    )
    subnet_row = db.execute(
        select(func.count(), func.avg(Subnet.utilization_pct)).where(
            Subnet.org_id == org_id, Subnet.is_deleted.is_(False)
        )
    ).one()
    subnets_managed = int(subnet_row[0] or 0)
    ip_utilization_pct = round(min(100.0, max(0.0, float(subnet_row[1] or 0.0))), 2)

    # Active alerts & open incidents
    open_alert_statuses = [
        AlertStatus.FIRING.value,
        AlertStatus.ACTIVE.value,
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.SILENCED.value,
        AlertStatus.SUPPRESSED.value,
    ]
    alert_sev_rows = db.execute(
        select(AlertEvent.severity, func.count())
        .where(
            AlertEvent.org_id == org_id,
            AlertEvent.status.in_(open_alert_statuses),
        )
        .group_by(AlertEvent.severity)
    ).all()
    active_alerts_by_severity = {str(sev): int(cnt) for sev, cnt in alert_sev_rows}
    active_alerts_total = sum(active_alerts_by_severity.values())

    terminal_incident_statuses = [IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value]
    open_incidents = int(
        db.execute(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.org_id == org_id,
                Incident.status.not_in(terminal_incident_statuses),
            )
        ).scalar_one()
    )

    # Synthetic probes & edge agents
    synthetic_probes_total = int(
        db.execute(
            select(func.count())
            .select_from(SyntheticProbeConfig)
            .where(
                SyntheticProbeConfig.org_id == org_id,
                SyntheticProbeConfig.is_deleted.is_(False),
                SyntheticProbeConfig.enabled.is_(True),
            )
        ).scalar_one()
    )
    # Count probes whose most recent result succeeded
    latest_probe_subq = (
        select(
            SyntheticProbeResult.probe_id,
            func.max(SyntheticProbeResult.timestamp).label("max_ts"),
        )
        .where(SyntheticProbeResult.org_id == org_id)
        .group_by(SyntheticProbeResult.probe_id)
        .subquery()
    )
    synthetic_probes_passing = int(
        db.execute(
            select(func.count(func.distinct(SyntheticProbeResult.probe_id)))
            .join(
                latest_probe_subq,
                (SyntheticProbeResult.probe_id == latest_probe_subq.c.probe_id)
                & (SyntheticProbeResult.timestamp == latest_probe_subq.c.max_ts),
            )
            .where(
                SyntheticProbeResult.org_id == org_id,
                SyntheticProbeResult.success.is_(True),
            )
        ).scalar_one()
    )

    edge_agents_online = int(
        db.execute(
            select(func.count())
            .select_from(EdgeAgent)
            .where(
                EdgeAgent.org_id == org_id,
                EdgeAgent.is_deleted.is_(False),
                EdgeAgent.status == AgentStatus.ONLINE.value,
            )
        ).scalar_one()
    )

    # Telemetry ingestion volume & average latency over the last hour
    icmp_1h = int(
        db.execute(
            select(func.count())
            .select_from(IcmpMetricSample)
            .where(
                IcmpMetricSample.org_id == org_id,
                IcmpMetricSample.timestamp >= one_hour_ago,
            )
        ).scalar_one()
    )
    snmp_1h = int(
        db.execute(
            select(func.count())
            .select_from(SnmpMetricSample)
            .where(
                SnmpMetricSample.org_id == org_id,
                SnmpMetricSample.timestamp >= one_hour_ago,
            )
        ).scalar_one()
    )
    host_1h = int(
        db.execute(
            select(func.count())
            .select_from(HostMetricSample)
            .where(
                HostMetricSample.org_id == org_id,
                HostMetricSample.timestamp >= one_hour_ago,
            )
        ).scalar_one()
    )
    samples_ingested_last_hour = icmp_1h + snmp_1h + host_1h

    avg_rtt_raw = db.execute(
        select(func.avg(IcmpMetricSample.avg_rtt_ms)).where(
            IcmpMetricSample.org_id == org_id,
            IcmpMetricSample.timestamp >= one_hour_ago,
            IcmpMetricSample.avg_rtt_ms.is_not(None),
        )
    ).scalar_one()
    if avg_rtt_raw is None:
        # Fall back to last 24h if no sample was ingested in the last 60m
        avg_rtt_raw = db.execute(
            select(func.avg(IcmpMetricSample.avg_rtt_ms)).where(
                IcmpMetricSample.org_id == org_id,
                IcmpMetricSample.avg_rtt_ms.is_not(None),
            )
        ).scalar_one()
    avg_fleet_latency_ms = round(float(avg_rtt_raw), 2) if avg_rtt_raw is not None else None

    # Compliance score & playbook executions
    avg_comp_raw = db.execute(
        select(func.avg(ComplianceEvaluation.score_pct)).where(
            ComplianceEvaluation.org_id == org_id,
        )
    ).scalar_one()
    avg_compliance_score_pct = (
        round(min(100.0, max(0.0, float(avg_comp_raw))), 2)
        if avg_comp_raw is not None
        else None
    )

    playbooks_executed_24h = int(
        db.execute(
            select(func.count())
            .select_from(PlaybookRun)
            .where(
                PlaybookRun.org_id == org_id,
                PlaybookRun.created_at >= one_day_ago,
            )
        ).scalar_one()
    )

    return PlatformStatsSummary(
        generated_at=now,
        organizations_total=organizations_total,
        users_active=users_active,
        sites_total=sites_total,
        devices_total=devices_total,
        devices_online=devices_online,
        devices_degraded=devices_degraded,
        devices_offline=devices_offline,
        devices_maintenance=devices_maintenance,
        interfaces_monitored=interfaces_monitored,
        subnets_managed=subnets_managed,
        ip_utilization_pct=ip_utilization_pct,
        active_alerts_total=active_alerts_total,
        active_alerts_by_severity=active_alerts_by_severity,
        open_incidents=open_incidents,
        synthetic_probes_total=synthetic_probes_total,
        synthetic_probes_passing=synthetic_probes_passing,
        edge_agents_online=edge_agents_online,
        samples_ingested_last_hour=samples_ingested_last_hour,
        avg_fleet_latency_ms=avg_fleet_latency_ms,
        avg_compliance_score_pct=avg_compliance_score_pct,
        playbooks_executed_24h=playbooks_executed_24h,
    )


@router.post(
    "/system/seed",
    response_model=SeedTriggerResponse,
    dependencies=[Depends(rate_limit_dependency(10, scope="system:seed"))],
    summary="Idempotently seed the NetPulse enterprise demo dataset",
)
def trigger_system_seed(
    request: Request,
    payload: SeedTriggerRequest | None = None,
    force: bool = Query(default=False, description="Force seeding even if org already exists"),
    db: Session = Depends(get_db_session),
) -> SeedTriggerResponse:
    """Ensure the database schema exists and populate the enterprise demo dataset."""
    settings = get_settings()
    effective_force = bool(force or (payload.force if payload is not None else False))

    # Try to resolve auth if provided, without failing when demo seeding on cold start
    auth: AuthContext | None = None
    if request.headers.get("authorization") or request.headers.get("x-api-key"):
        auth = get_current_auth(request, db)

    if not _can_seed_system(auth, settings, force=effective_force):
        raise AuthorizationError(
            "System seeding requires admin:system_config permission in production",
            error_code="SEED_FORBIDDEN",
        )

    ensure_database_ready(db, auto_seed=False)
    result = seed_enterprise_demo(db, commit=True, force=effective_force)

    org_id = result.get("org_id")
    if org_id:
        try:
            AuditLogRepository(db).record(
                action="settings_update",
                resource_type="system",
                resource_id="enterprise_demo_seed",
                org_id=str(org_id),
                actor_user_id=auth.user_id if auth else None,
                actor_email=auth.email if auth else "system@netpulse.io",
                summary="Triggered enterprise demo dataset seed",
                ip_address=auth.client_ip if auth else (request.client.host if request.client else None),
                user_agent=request.headers.get("user-agent"),
                request_id=get_request_id(),
                after_state={"seeded": bool(result.get("seeded")), "force": effective_force},
            )
            db.commit()
        except Exception:
            db.rollback()

    return SeedTriggerResponse(
        seeded=bool(result.get("seeded", False)),
        reason=result.get("reason"),
        org_id=str(org_id) if org_id else None,
        org_slug=str(result.get("org_slug") or DEFAULT_ORG_SLUG),
        admin_email=str(result.get("admin_email") or DEFAULT_ADMIN_EMAIL),
        summary={k: v for k, v in result.items() if k not in {"seeded", "reason", "org_id"}},
    )
