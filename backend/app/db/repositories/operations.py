"""Data-access repositories for topology, discovery, alerting, incidents, SLOs, NCM, compliance, playbooks, and reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, desc, func, or_, select

from app.core.exceptions import ValidationError
from app.db.base import utcnow
from app.db.repositories.base import BaseRepository, PageResult, resolve_model

if TYPE_CHECKING:
    from app.models.alerting import (
        AlertEvent,
        AlertRule,
        EscalationPolicy,
        Incident,
        IncidentTimelineEntry,
        MaintenanceWindow,
        NotificationChannel,
        NotificationDelivery,
        OnCallSchedule,
        SloDefinition,
    )
    from app.models.automation import (
        ComplianceEvaluation,
        CompliancePolicy,
        ConfigDiff,
        ConfigSnapshot,
        GeneratedReport,
        PlaybookDefinition,
        PlaybookRun,
        PluginRegistration,
        ScheduledReport,
    )
    from app.models.topology import (
        DependencyEdge,
        DiscoveryFinding,
        DiscoveryJob,
        TopologyLink,
        TopologyNode,
    )


class TopologyRepository(BaseRepository["TopologyNode"]):
    """Repository for L2/L3 network :class:`TopologyNode`, :class:`TopologyLink`, and :class:`DependencyEdge` graphs."""

    _model_spec = ("app.models.topology", "TopologyNode")
    default_order_by = ("label",)

    def _link_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.topology", "TopologyLink"),
            org_id=self._effective_org_id(org_id),
        )

    def _dependency_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.topology", "DependencyEdge"),
            org_id=self._effective_org_id(org_id),
        )

    def get_node_by_device(self, device_id: str, *, org_id: str | None = None) -> Any | None:
        """Fetch the topology node representing a given inventory device."""
        return self.get_one_by(filters={"device_id": device_id}, org_id=org_id)

    def list_links(
        self,
        *,
        protocol: str | None = None,
        status: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List topology links optionally filtered by discovery protocol or link status."""
        link_repo = self._link_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if protocol is not None:
            proto_col = link_repo._optional_column("discovery_protocol", "protocol")
            if proto_col is not None:
                filters[proto_col.key] = protocol
        if status is not None and link_repo._has_column("status"):
            filters["status"] = status
        return link_repo.list(filters=filters)

    def list_neighbors(self, node_id: str, *, org_id: str | None = None) -> list[Any]:
        """Return all links connected to ``node_id`` (either source or target)."""
        link_repo = self._link_repo(org_id=org_id)
        src_col = link_repo._resolve_column("source_node_id", "src_node_id")
        dst_col = link_repo._resolve_column("target_node_id", "dst_node_id")
        stmt = link_repo._base_query().where(or_(src_col == node_id, dst_col == node_id))
        return list(self.session.execute(stmt).scalars().all())

    def upsert_link(
        self,
        source_node_id: str,
        target_node_id: str,
        *,
        protocol: str = "lldp",
        defaults: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> tuple[Any, bool]:
        """Idempotently create or update a topology link between two nodes."""
        if source_node_id == target_node_id:
            raise ValidationError("Topology link cannot connect a node to itself")
        link_repo = self._link_repo(org_id=org_id)
        src_key = link_repo._resolve_column("source_node_id", "src_node_id").key
        dst_key = link_repo._resolve_column("target_node_id", "dst_node_id").key
        lookup: dict[str, Any] = {src_key: source_node_id, dst_key: target_node_id}
        proto_col = link_repo._optional_column("discovery_protocol", "protocol")
        if proto_col is not None:
            lookup[proto_col.key] = protocol
        return link_repo.upsert_by(lookup, defaults or {}, flush=flush)

    def list_dependency_edges(
        self,
        *,
        parent_id: str | None = None,
        child_id: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return service/device root-cause dependency edges."""
        dep_repo = self._dependency_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if parent_id is not None:
            pcol = dep_repo._resolve_column("parent_device_id", "upstream_id", "source_id")
            filters[pcol.key] = parent_id
        if child_id is not None:
            ccol = dep_repo._resolve_column("child_device_id", "downstream_id", "target_id")
            filters[ccol.key] = child_id
        return dep_repo.list(filters=filters)

    def get_graph(
        self,
        *,
        site_id: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, list[Any]]:
        """Fetch nodes, links, and dependency edges forming the topology graph."""
        node_filters = {"site_id": site_id} if site_id is not None and self._has_column("site_id") else None
        nodes = self.list(filters=node_filters, org_id=org_id)
        node_ids = {getattr(n, "id") for n in nodes}
        links = self.list_links(org_id=org_id)
        if site_id is not None and node_ids:
            links = [
                lnk
                for lnk in links
                if getattr(lnk, "source_node_id", getattr(lnk, "src_node_id", None)) in node_ids
                or getattr(lnk, "target_node_id", getattr(lnk, "dst_node_id", None)) in node_ids
            ]
        dependencies = self.list_dependency_edges(org_id=org_id)
        return {"nodes": nodes, "links": links, "dependencies": dependencies}


class DiscoveryJobRepository(BaseRepository["DiscoveryJob"]):
    """Repository for automated network :class:`DiscoveryJob` scans and :class:`DiscoveryFinding` records."""

    _model_spec = ("app.models.topology", "DiscoveryJob")
    default_order_by = ("-created_at",)

    def _finding_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.topology", "DiscoveryFinding"),
            org_id=self._effective_org_id(org_id),
        )

    def list_by_status(self, status: str, *, org_id: str | None = None) -> list[Any]:
        """List discovery jobs in a specific lifecycle state."""
        return self.list(filters={"status": status}, org_id=org_id)

    def mark_running(self, job_id: str, *, org_id: str | None = None, flush: bool = True) -> Any:
        """Transition a discovery job into the ``running`` state."""
        patch: dict[str, Any] = {"status": "running"}
        if self._has_column("started_at"):
            patch["started_at"] = utcnow()
        return self.update(job_id, patch, org_id=org_id, flush=flush)

    def mark_completed(
        self,
        job_id: str,
        *,
        hosts_found: int | None = None,
        summary: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Mark a discovery job as completed with result counts."""
        patch: dict[str, Any] = {"status": "completed"}
        if self._has_column("completed_at"):
            patch["completed_at"] = utcnow()
        if hosts_found is not None:
            for col in ("hosts_discovered", "devices_found", "found_count"):
                if self._has_column(col):
                    patch[col] = hosts_found
                    break
        if summary is not None and self._has_column("summary"):
            patch["summary"] = dict(summary)
        return self.update(job_id, patch, org_id=org_id, flush=flush)

    def mark_failed(
        self,
        job_id: str,
        error_message: str,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Mark a discovery job as failed and persist the error reason."""
        patch: dict[str, Any] = {"status": "failed"}
        if self._has_column("completed_at"):
            patch["completed_at"] = utcnow()
        for col in ("error_summary", "error_message", "error"):
            if self._has_column(col):
                patch[col] = error_message[:2000]
                break
        return self.update(job_id, patch, org_id=org_id, flush=flush)

    def add_finding(
        self,
        job_id: str,
        data: Mapping[str, Any],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Record an individual host/link :class:`DiscoveryFinding` for a job."""
        finding_repo = self._finding_repo(org_id=org_id)
        fk_col = finding_repo._resolve_column("job_id", "discovery_job_id")
        payload = {**data, fk_col.key: job_id}
        return finding_repo.create(payload, flush=flush)

    def list_findings(
        self,
        job_id: str,
        *,
        status: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List findings discovered during ``job_id``."""
        finding_repo = self._finding_repo(org_id=org_id)
        fk_col = finding_repo._resolve_column("job_id", "discovery_job_id")
        filters: dict[str, Any] = {fk_col.key: job_id}
        if status is not None and finding_repo._has_column("status"):
            filters["status"] = status
        return finding_repo.list(filters=filters)


class AlertRuleRepository(BaseRepository["AlertRule"]):
    """Repository for threshold, anomaly, and expression :class:`AlertRule` definitions."""

    _model_spec = ("app.models.alerting", "AlertRule")
    default_order_by = ("name",)

    def list_enabled(
        self,
        *,
        severity: str | None = None,
        metric_name: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return all enabled alert rules, optionally filtered by severity or metric."""
        filters: dict[str, Any] = {}
        for flag in ("is_enabled", "enabled"):
            if self._has_column(flag):
                filters[flag] = True
                break
        if severity is not None and self._has_column("severity"):
            filters["severity"] = severity
        if metric_name is not None and self._has_column("metric_name"):
            filters["metric_name"] = metric_name
        return self.list(filters=filters, org_id=org_id)

    def set_enabled(
        self,
        rule_id: str,
        enabled: bool,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Enable or mute an alert rule."""
        flag = self._resolve_column("is_enabled", "enabled")
        return self.update(rule_id, {flag.key: enabled}, org_id=org_id, flush=flush)

    def record_evaluation(
        self,
        rule_id: str,
        *,
        triggered: bool = False,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Update evaluation and optional trigger timestamps on an alert rule."""
        now = utcnow()
        patch: dict[str, Any] = {}
        if self._has_column("last_evaluated_at"):
            patch["last_evaluated_at"] = now
        if triggered and self._has_column("last_triggered_at"):
            patch["last_triggered_at"] = now
        return self.update(rule_id, patch, org_id=org_id, flush=flush)


class AlertEventRepository(BaseRepository["AlertEvent"]):
    """Repository for firing, acknowledged, suppressed, and resolved :class:`AlertEvent` instances."""

    _model_spec = ("app.models.alerting", "AlertEvent")
    default_order_by = ("-created_at",)

    def list_active(
        self,
        *,
        severity: str | Sequence[str] | None = None,
        device_id: str | None = None,
        rule_id: str | None = None,
        limit: int = 200,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return all currently open/firing or acknowledged alert events."""
        status_col = self._resolve_column("status", "state")
        stmt = self._base_query(org_id=org_id).where(status_col.in_(["firing", "open", "acknowledged", "active"]))
        if severity is not None and self._has_column("severity"):
            sev_col = self._get_column("severity")
            stmt = stmt.where(sev_col == severity if isinstance(severity, str) else sev_col.in_(list(severity)))
        if device_id is not None and self._has_column("device_id"):
            stmt = stmt.where(self._get_column("device_id") == device_id)
        if rule_id is not None and self._has_column("rule_id"):
            stmt = stmt.where(self._get_column("rule_id") == rule_id)
        stmt = self._apply_ordering(stmt, None).limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def get_active_by_fingerprint(
        self,
        fingerprint: str,
        *,
        org_id: str | None = None,
    ) -> Any | None:
        """Find an active alert matching a deduplication fingerprint."""
        if not self._has_column("fingerprint"):
            return None
        status_col = self._resolve_column("status", "state")
        stmt = self._base_query(org_id=org_id).where(
            and_(
                self._get_column("fingerprint") == fingerprint,
                status_col.in_(["firing", "open", "acknowledged", "active"]),
            )
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def acknowledge(
        self,
        alert_id: str,
        *,
        actor_user_id: str | None = None,
        note: str | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Mark a firing alert as acknowledged."""
        status_col = self._resolve_column("status", "state")
        patch: dict[str, Any] = {status_col.key: "acknowledged"}
        if self._has_column("acknowledged_at"):
            patch["acknowledged_at"] = utcnow()
        if actor_user_id is not None and self._has_column("acknowledged_by"):
            patch["acknowledged_by"] = actor_user_id
        if note is not None and self._has_column("acknowledgement_note"):
            patch["acknowledgement_note"] = note
        return self.update(alert_id, patch, org_id=org_id, flush=flush)

    def resolve(
        self,
        alert_id: str,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Mark an alert event as resolved."""
        status_col = self._resolve_column("status", "state")
        patch: dict[str, Any] = {status_col.key: "resolved"}
        if self._has_column("resolved_at"):
            patch["resolved_at"] = utcnow()
        return self.update(alert_id, patch, org_id=org_id, flush=flush)

    def severity_counts(
        self,
        *,
        active_only: bool = True,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Return alert event counts grouped by severity."""
        base = self._base_query(org_id=org_id)
        if active_only:
            status_col = self._resolve_column("status", "state")
            base = base.where(status_col.in_(["firing", "open", "acknowledged", "active"]))
        sub = base.subquery()
        agg = select(sub.c.severity, func.count()).group_by(sub.c.severity)
        return {str(sev): int(cnt) for sev, cnt in self.session.execute(agg).all()}


class IncidentRepository(BaseRepository["Incident"]):
    """Repository for correlated :class:`Incident` workflows, timelines, escalation, and notifications."""

    _model_spec = ("app.models.alerting", "Incident")
    default_order_by = ("-created_at",)

    def _timeline_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.alerting", "IncidentTimelineEntry"),
            org_id=self._effective_org_id(org_id),
        )

    def list_open(
        self,
        *,
        severity: str | None = None,
        assigned_to: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List all unresolved incidents."""
        status_col = self._resolve_column("status", "state")
        stmt = self._base_query(org_id=org_id).where(status_col.not_in(["resolved", "closed"]))
        if severity is not None and self._has_column("severity"):
            stmt = stmt.where(self._get_column("severity") == severity)
        if assigned_to is not None:
            owner_col = self._optional_column("assigned_to_user_id", "assigned_to_id", "assigned_to", "owner_id")
            if owner_col is not None:
                stmt = stmt.where(owner_col == assigned_to)
        return list(self.session.execute(self._apply_ordering(stmt, None)).scalars().all())

    def transition_status(
        self,
        incident_id: str,
        new_status: str,
        *,
        actor_user_id: str | None = None,
        summary: str | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Transition an incident's lifecycle state and record a timeline audit entry."""
        now = utcnow()
        status_col = self._resolve_column("status", "state")
        patch: dict[str, Any] = {status_col.key: new_status}
        if new_status == "acknowledged" and self._has_column("acknowledged_at"):
            patch["acknowledged_at"] = now
        if new_status in {"resolved", "closed"} and self._has_column("resolved_at"):
            patch["resolved_at"] = now

        incident = self.update(incident_id, patch, org_id=org_id, flush=flush)
        self.add_timeline_entry(
            incident_id,
            entry_type="status_change",
            message=summary or f"Incident status changed to '{new_status}'",
            actor_user_id=actor_user_id,
            org_id=org_id,
            flush=flush,
        )
        return incident

    def assign(
        self,
        incident_id: str,
        assignee_id: str,
        *,
        actor_user_id: str | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Assign an incident to an engineer and log the change on the timeline."""
        owner_col = self._resolve_column("assigned_to_user_id", "assigned_to_id", "assigned_to", "owner_id")
        incident = self.update(incident_id, {owner_col.key: assignee_id}, org_id=org_id, flush=flush)
        self.add_timeline_entry(
            incident_id,
            entry_type="assignment",
            message=f"Incident assigned to {assignee_id}",
            actor_user_id=actor_user_id,
            org_id=org_id,
            flush=flush,
        )
        return incident

    def add_timeline_entry(
        self,
        incident_id: str,
        *,
        entry_type: str,
        message: str,
        actor_user_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Append a chronological :class:`IncidentTimelineEntry` to an incident."""
        repo = self._timeline_repo(org_id=org_id)
        cols = repo._column_names()
        candidates = {
            "incident_id": incident_id,
            "entry_type": entry_type,
            "event_type": entry_type,
            "content": message,
            "message": message,
            "body": message,
            "author_user_id": actor_user_id,
            "actor_user_id": actor_user_id,
            "author_id": actor_user_id,
            "user_id": actor_user_id,
            "metadata_json": dict(metadata) if metadata else {},
            "details": dict(metadata) if metadata else {},
        }
        payload = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return repo.create(payload, flush=flush)

    def list_timeline(self, incident_id: str, *, org_id: str | None = None) -> list[Any]:
        """Return ordered timeline entries for an incident."""
        repo = self._timeline_repo(org_id=org_id)
        return repo.list(filters={"incident_id": incident_id}, order_by="created_at")

    def mttr_summary(
        self,
        *,
        since: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Calculate Mean Time To Acknowledge (MTTA) and Mean Time To Resolve (MTTR) in minutes."""
        window_start = since or (utcnow() - timedelta(days=30))
        incidents = self.list(filters={"created_at__gte": window_start}, org_id=org_id)
        ack_mins: list[float] = []
        res_mins: list[float] = []
        for inc in incidents:
            created = getattr(inc, "created_at", None)
            acked = getattr(inc, "acknowledged_at", None)
            resolved = getattr(inc, "resolved_at", None)
            if created and acked:
                ack_mins.append(max(0.0, (acked - created).total_seconds() / 60.0))
            if created and resolved:
                res_mins.append(max(0.0, (resolved - created).total_seconds() / 60.0))
        return {
            "incident_count": len(incidents),
            "resolved_count": len(res_mins),
            "mtta_minutes": round(sum(ack_mins) / len(ack_mins), 2) if ack_mins else None,
            "mttr_minutes": round(sum(res_mins) / len(res_mins), 2) if res_mins else None,
        }

    def list_escalation_policies(self, *, org_id: str | None = None) -> list[Any]:
        """List configured :class:`EscalationPolicy` definitions."""
        repo = BaseRepository(
            self.session,
            model=resolve_model("app.models.alerting", "EscalationPolicy"),
            org_id=self._effective_org_id(org_id),
        )
        return repo.list(order_by="name")

    def list_oncall_schedules(self, *, org_id: str | None = None) -> list[Any]:
        """List active :class:`OnCallSchedule` rotations."""
        repo = BaseRepository(
            self.session,
            model=resolve_model("app.models.alerting", "OnCallSchedule"),
            org_id=self._effective_org_id(org_id),
        )
        return repo.list(order_by="name")

    def list_notification_channels(self, *, enabled_only: bool = True, org_id: str | None = None) -> list[Any]:
        """List configured :class:`NotificationChannel` destinations (Slack, PagerDuty, Email, Webhook)."""
        repo = BaseRepository(
            self.session,
            model=resolve_model("app.models.alerting", "NotificationChannel"),
            org_id=self._effective_org_id(org_id),
        )
        filters: dict[str, Any] = {}
        if enabled_only:
            for flag in ("is_enabled", "enabled", "is_active"):
                if repo._has_column(flag):
                    filters[flag] = True
                    break
        return repo.list(filters=filters, order_by="name")

    def record_notification_delivery(
        self,
        data: Mapping[str, Any],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Record an outbound :class:`NotificationDelivery` attempt."""
        repo = BaseRepository(
            self.session,
            model=resolve_model("app.models.alerting", "NotificationDelivery"),
            org_id=self._effective_org_id(org_id),
        )
        return repo.create(data, flush=flush)


class SloRepository(BaseRepository["SloDefinition"]):
    """Repository for Service Level Objective (:class:`SloDefinition`) tracking and error budgets."""

    _model_spec = ("app.models.alerting", "SloDefinition")
    default_order_by = ("name",)

    def list_active(self, *, org_id: str | None = None) -> list[Any]:
        """List all enabled SLO definitions."""
        filters: dict[str, Any] = {}
        for flag in ("is_active", "is_enabled", "enabled"):
            if self._has_column(flag):
                filters[flag] = True
                break
        return self.list(filters=filters, org_id=org_id)

    def list_breaching(self, *, org_id: str | None = None) -> list[Any]:
        """Return SLOs whose current SLI has dropped below target or whose error budget is exhausted."""
        slos = self.list_active(org_id=org_id)
        breaching: list[Any] = []
        for slo in slos:
            target = getattr(slo, "target_pct", getattr(slo, "target_percentage", None))
            current = getattr(slo, "current_sli_pct", getattr(slo, "current_value", None))
            budget_rem = getattr(slo, "error_budget_remaining_pct", None)
            if (target is not None and current is not None and float(current) < float(target)) or (
                budget_rem is not None and float(budget_rem) <= 0.0
            ):
                breaching.append(slo)
        return breaching

    def update_sli(
        self,
        slo_id: str,
        *,
        current_sli_pct: float,
        error_budget_remaining_pct: float | None = None,
        burn_rate: float | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Update live computed SLI value and error budget burn metrics."""
        cols = self._column_names()
        candidates = {
            "current_sli_pct": current_sli_pct,
            "current_value": current_sli_pct,
            "error_budget_remaining_pct": error_budget_remaining_pct,
            "burn_rate": burn_rate,
            "last_evaluated_at": utcnow(),
        }
        patch = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return self.update(slo_id, patch, org_id=org_id, flush=flush)


class MaintenanceWindowRepository(BaseRepository["MaintenanceWindow"]):
    """Repository for scheduled :class:`MaintenanceWindow` alert suppression periods."""

    _model_spec = ("app.models.alerting", "MaintenanceWindow")
    default_order_by = ("starts_at",)

    def list_active(
        self,
        *,
        at: datetime | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return maintenance windows active at timestamp ``at`` (defaults to now)."""
        now = at or utcnow()
        start_col = self._resolve_column("starts_at", "start_time")
        end_col = self._resolve_column("ends_at", "end_time")
        stmt = self._base_query(org_id=org_id).where(and_(start_col <= now, end_col >= now))
        if self._has_column("is_active"):
            stmt = stmt.where(self._get_column("is_active").is_(True))
        if self._has_column("status"):
            stmt = stmt.where(self._get_column("status").not_in(["cancelled", "canceled", "completed"]))
        return list(self.session.execute(stmt).scalars().all())

    def list_upcoming(
        self,
        *,
        within_days: int = 14,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return scheduled maintenance windows starting within the next ``within_days`` days."""
        now = utcnow()
        horizon = now + timedelta(days=within_days)
        start_col = self._resolve_column("starts_at", "start_time")
        stmt = (
            self._base_query(org_id=org_id)
            .where(and_(start_col > now, start_col <= horizon))
            .order_by(start_col.asc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def is_device_in_maintenance(
        self,
        device_id: str,
        *,
        site_id: str | None = None,
        at: datetime | None = None,
        org_id: str | None = None,
    ) -> bool:
        """Return ``True`` if ``device_id`` (or its ``site_id``) is covered by an active maintenance window."""
        active_windows = self.list_active(at=at, org_id=org_id)
        for win in active_windows:
            if getattr(win, "device_id", None) == device_id:
                return True
            device_ids = getattr(win, "scope_device_ids_json", None) or getattr(win, "device_ids", None) or []
            if device_id in device_ids:
                return True
            site_ids = getattr(win, "scope_site_ids_json", None) or []
            if site_id is not None and (getattr(win, "site_id", None) == site_id or site_id in site_ids):
                return True
            if getattr(win, "scope", None) == "global" or (not device_ids and not site_ids):
                return True
        return False


class ConfigSnapshotRepository(BaseRepository["ConfigSnapshot"]):
    """Repository for Network Configuration Management :class:`ConfigSnapshot` backups and :class:`ConfigDiff` records."""

    _model_spec = ("app.models.automation", "ConfigSnapshot")
    default_order_by = ("-created_at",)

    def _diff_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.automation", "ConfigDiff"),
            org_id=self._effective_org_id(org_id),
        )

    def list_for_device(
        self,
        device_id: str,
        *,
        config_type: str | None = None,
        limit: int = 50,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return configuration snapshots for ``device_id``, newest first."""
        filters: dict[str, Any] = {"device_id": device_id}
        if config_type is not None and self._has_column("config_type"):
            filters["config_type"] = config_type
        return self.list(filters=filters, limit=limit, org_id=org_id)

    def latest_for_device(
        self,
        device_id: str,
        *,
        config_type: str | None = None,
        org_id: str | None = None,
    ) -> Any | None:
        """Return the latest configuration backup for a device."""
        snaps = self.list_for_device(device_id, config_type=config_type, limit=1, org_id=org_id)
        return snaps[0] if snaps else None

    def has_config_changed(
        self,
        device_id: str,
        content_hash: str,
        *,
        config_type: str | None = None,
        org_id: str | None = None,
    ) -> bool:
        """Return ``True`` if ``content_hash`` differs from the latest stored snapshot."""
        latest = self.latest_for_device(device_id, config_type=config_type, org_id=org_id)
        if latest is None:
            return True
        prev_hash = getattr(latest, "content_hash", None) or getattr(latest, "sha256_hash", None) or getattr(latest, "checksum", None)
        return prev_hash != content_hash

    def record_diff(
        self,
        data: Mapping[str, Any],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Persist a computed :class:`ConfigDiff` between two configuration snapshots."""
        return self._diff_repo(org_id=org_id).create(data, flush=flush)

    def list_recent_diffs(
        self,
        *,
        device_id: str | None = None,
        limit: int = 50,
        org_id: str | None = None,
    ) -> list[Any]:
        """List recent configuration drift diffs across the fleet or for one device."""
        diff_repo = self._diff_repo(org_id=org_id)
        filters = {"device_id": device_id} if device_id is not None and diff_repo._has_column("device_id") else None
        return diff_repo.list(filters=filters, limit=limit)


class ComplianceRepository(BaseRepository["CompliancePolicy"]):
    """Repository for CIS/NIST/custom :class:`CompliancePolicy` rules and :class:`ComplianceEvaluation` results."""

    _model_spec = ("app.models.automation", "CompliancePolicy")
    default_order_by = ("name",)

    def _eval_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.automation", "ComplianceEvaluation"),
            org_id=self._effective_org_id(org_id),
        )

    def list_enabled_policies(
        self,
        *,
        framework: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return enabled compliance policies, optionally filtered by framework (e.g. ``CIS``)."""
        filters: dict[str, Any] = {}
        for flag in ("is_enabled", "enabled", "is_active"):
            if self._has_column(flag):
                filters[flag] = True
                break
        if framework is not None and self._has_column("framework"):
            filters["framework"] = framework
        return self.list(filters=filters, org_id=org_id)

    def record_evaluation(
        self,
        data: Mapping[str, Any],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Store a :class:`ComplianceEvaluation` outcome for a policy/device pair."""
        return self._eval_repo(org_id=org_id).create(data, flush=flush)

    def list_evaluations(
        self,
        *,
        policy_id: str | None = None,
        device_id: str | None = None,
        status: str | None = None,
        limit: int = 200,
        org_id: str | None = None,
    ) -> list[Any]:
        """List compliance evaluation results with optional filters."""
        eval_repo = self._eval_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if policy_id is not None and eval_repo._has_column("policy_id"):
            filters["policy_id"] = policy_id
        if device_id is not None and eval_repo._has_column("device_id"):
            filters["device_id"] = device_id
        if status is not None and eval_repo._has_column("status"):
            filters["status"] = status
        return eval_repo.list(filters=filters, limit=limit)

    def posture_summary(self, *, org_id: str | None = None) -> dict[str, Any]:
        """Aggregate fleet compliance pass/fail counts and overall compliance percentage."""
        evals = self.list_evaluations(limit=5000, org_id=org_id)
        latest_by_pair: dict[tuple[str, str], Any] = {}
        for ev in evals:
            key = (str(getattr(ev, "policy_id", "")), str(getattr(ev, "device_id", "")))
            if key not in latest_by_pair:
                latest_by_pair[key] = ev

        passed = 0
        failed = 0
        other = 0
        for ev in latest_by_pair.values():
            st = str(getattr(ev, "status", "")).lower()
            is_pass = getattr(ev, "passed", None)
            if is_pass is True or st in {"pass", "passed", "compliant"}:
                passed += 1
            elif is_pass is False or st in {"fail", "failed", "non_compliant", "violation"}:
                failed += 1
            else:
                other += 1
        total = passed + failed + other
        return {
            "evaluated_pairs": total,
            "passed": passed,
            "failed": failed,
            "other": other,
            "compliance_pct": round((passed / total) * 100.0, 2) if total > 0 else 100.0,
        }


class PlaybookRepository(BaseRepository["PlaybookDefinition"]):
    """Repository for automated remediation :class:`PlaybookDefinition` workflows and :class:`PlaybookRun` history."""

    _model_spec = ("app.models.automation", "PlaybookDefinition")
    default_order_by = ("name",)

    def _run_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.automation", "PlaybookRun"),
            org_id=self._effective_org_id(org_id),
        )

    def list_enabled(
        self,
        *,
        trigger_type: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List enabled playbooks, optionally filtered by trigger type."""
        filters: dict[str, Any] = {}
        for flag in ("is_enabled", "enabled", "is_active"):
            if self._has_column(flag):
                filters[flag] = True
                break
        if trigger_type is not None and self._has_column("trigger_type"):
            filters["trigger_type"] = trigger_type
        return self.list(filters=filters, org_id=org_id)

    def start_run(
        self,
        playbook_id: str,
        *,
        device_id: str | None = None,
        alert_event_id: str | None = None,
        triggered_by: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Create a new :class:`PlaybookRun` record in ``running`` state."""
        run_repo = self._run_repo(org_id=org_id)
        cols = run_repo._column_names()
        trigger_ctx = dict(parameters) if parameters else {}
        if device_id is not None:
            trigger_ctx.setdefault("device_id", device_id)
        if alert_event_id is not None:
            trigger_ctx.setdefault("alert_event_id", alert_event_id)
        candidates = {
            "playbook_id": playbook_id,
            "device_id": device_id,
            "alert_event_id": alert_event_id,
            "triggered_by": triggered_by,
            "status": "running",
            "started_at": utcnow(),
            "trigger_context_json": trigger_ctx,
            "parameters": trigger_ctx,
            "input_params": trigger_ctx,
        }
        payload = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return run_repo.create(payload, flush=flush)

    def finish_run(
        self,
        run_id: str,
        *,
        status: str = "succeeded",
        output: Any = None,
        error_message: str | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Finalize a :class:`PlaybookRun` with completion timestamp and execution logs."""
        run_repo = self._run_repo(org_id=org_id)
        cols = run_repo._column_names()
        candidates = {
            "status": status,
            "completed_at": utcnow(),
            "finished_at": utcnow(),
            "step_results_json": output,
            "output": output,
            "step_results": output,
            "error_message": error_message,
        }
        patch = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return run_repo.update(run_id, patch, flush=flush)

    def list_runs(
        self,
        *,
        playbook_id: str | None = None,
        device_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        org_id: str | None = None,
    ) -> list[Any]:
        """List historical playbook execution runs."""
        run_repo = self._run_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if playbook_id is not None and run_repo._has_column("playbook_id"):
            filters["playbook_id"] = playbook_id
        if device_id is not None and run_repo._has_column("device_id"):
            filters["device_id"] = device_id
        if status is not None and run_repo._has_column("status"):
            filters["status"] = status
        return run_repo.list(filters=filters, limit=limit)


class ReportRepository(BaseRepository["ScheduledReport"]):
    """Repository for :class:`ScheduledReport` schedules, :class:`GeneratedReport` artifacts, and plugins."""

    _model_spec = ("app.models.automation", "ScheduledReport")
    default_order_by = ("name",)

    def _generated_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.automation", "GeneratedReport"),
            org_id=self._effective_org_id(org_id),
        )

    def _plugin_repo(self, org_id: str | None = None) -> BaseRepository[Any]:
        return BaseRepository(
            self.session,
            model=resolve_model("app.models.automation", "PluginRegistration"),
            org_id=self._effective_org_id(org_id),
        )

    def list_due_schedules(
        self,
        *,
        as_of: datetime | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return enabled scheduled reports whose ``next_run_at`` is due."""
        now = as_of or utcnow()
        stmt = self._base_query(org_id=org_id)
        for flag in ("is_enabled", "enabled", "is_active"):
            if self._has_column(flag):
                stmt = stmt.where(self._get_column(flag).is_(True))
                break
        if self._has_column("next_run_at"):
            col = self._get_column("next_run_at")
            stmt = stmt.where(or_(col.is_(None), col <= now))
        return list(self.session.execute(stmt).scalars().all())

    def record_generated_report(
        self,
        data: Mapping[str, Any],
        *,
        schedule_id: str | None = None,
        next_run_at: datetime | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Store a newly generated report artifact and optionally advance the parent schedule."""
        gen_repo = self._generated_repo(org_id=org_id)
        payload = dict(data)
        if schedule_id is not None:
            fk = gen_repo._optional_column("scheduled_report_id", "schedule_id")
            if fk is not None:
                payload.setdefault(fk.key, schedule_id)
        report = gen_repo.create(payload, flush=flush)

        if schedule_id is not None:
            patch: dict[str, Any] = {}
            if self._has_column("last_run_at"):
                patch["last_run_at"] = utcnow()
            if next_run_at is not None and self._has_column("next_run_at"):
                patch["next_run_at"] = next_run_at
            if patch:
                self.update(schedule_id, patch, org_id=org_id, flush=flush)
        return report

    def list_generated_reports(
        self,
        *,
        schedule_id: str | None = None,
        report_type: str | None = None,
        limit: int = 100,
        org_id: str | None = None,
    ) -> list[Any]:
        """List generated report artifacts, newest first."""
        gen_repo = self._generated_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if schedule_id is not None:
            fk = gen_repo._optional_column("scheduled_report_id", "schedule_id")
            if fk is not None:
                filters[fk.key] = schedule_id
        if report_type is not None and gen_repo._has_column("report_type"):
            filters["report_type"] = report_type
        return gen_repo.list(filters=filters, limit=limit)

    def list_plugins(
        self,
        *,
        enabled_only: bool = False,
        org_id: str | None = None,
    ) -> list[Any]:
        """List registered platform extensions (:class:`PluginRegistration`)."""
        plugin_repo = self._plugin_repo(org_id=org_id)
        filters: dict[str, Any] = {}
        if enabled_only:
            for flag in ("is_enabled", "enabled", "is_active"):
                if plugin_repo._has_column(flag):
                    filters[flag] = True
                    break
        return plugin_repo.list(filters=filters, order_by="name")


__all__ = [
    "AlertEventRepository",
    "AlertRuleRepository",
    "ComplianceRepository",
    "ConfigSnapshotRepository",
    "DiscoveryJobRepository",
    "IncidentRepository",
    "MaintenanceWindowRepository",
    "PlaybookRepository",
    "ReportRepository",
    "SloRepository",
    "TopologyRepository",
]
