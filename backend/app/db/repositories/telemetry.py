"""Data-access repositories for time-series telemetry, syslog, NetFlow, BGP, and edge agents."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import Select, and_, case, desc, func, or_, select
from sqlalchemy.orm import InstrumentedAttribute

from app.db.base import utcnow
from app.db.repositories.base import BaseRepository, ModelT, PageResult, resolve_model

if TYPE_CHECKING:
    from app.models.telemetry import (
        BgpPeerSession,
        EdgeAgent,
        HostMetricSample,
        IcmpMetricSample,
        MetricDefinition,
        MetricRollup,
        NetFlowRecord,
        SnmpMetricSample,
        SyntheticProbeConfig,
        SyntheticProbeResult,
        SyslogEvent,
    )


class _TimeSeriesRepository(BaseRepository[ModelT]):
    """Shared time-window and retention helpers for telemetry sample repositories."""

    _timestamp_candidates: tuple[str, ...] = (
        "timestamp",
        "collected_at",
        "sampled_at",
        "observed_at",
        "received_at",
        "bucket_start",
        "created_at",
    )

    def _ts_col(self) -> InstrumentedAttribute[Any]:
        return self._resolve_column(*self._timestamp_candidates)

    def _apply_time_window(
        self,
        stmt: Select[Any],
        *,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> Select[Any]:
        ts_col = self._ts_col()
        if start is not None:
            stmt = stmt.where(ts_col >= start)
        if end is not None:
            stmt = stmt.where(ts_col <= end)
        return stmt

    def list_range(
        self,
        *,
        device_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 1000,
        descending: bool = False,
        extra_filters: Mapping[str, Any] | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """Query samples within an optional ``[start, end]`` time range."""
        stmt = self._base_query(org_id=org_id)
        if device_id is not None and self._has_column("device_id"):
            stmt = stmt.where(self._get_column("device_id") == device_id)
        stmt = self._apply_time_window(stmt, start=start, end=end)
        if extra_filters:
            stmt = self._apply_filters(stmt, extra_filters)
        ts_col = self._ts_col()
        stmt = stmt.order_by(ts_col.desc() if descending else ts_col.asc())
        if limit > 0:
            stmt = stmt.limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def latest_for_device(self, device_id: str, *, org_id: str | None = None) -> Any | None:
        """Return the single most recent sample recorded for ``device_id``."""
        ts_col = self._ts_col()
        stmt = (
            self._base_query(org_id=org_id)
            .where(self._get_column("device_id") == device_id)
            .order_by(ts_col.desc())
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def purge_older_than(
        self,
        cutoff: datetime,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> int:
        """Delete samples older than ``cutoff`` for retention enforcement."""
        ts_col = self._ts_col()
        return self.delete_where(filters={f"{ts_col.key}__lt": cutoff}, org_id=org_id, flush=flush)


class SnmpSampleRepository(_TimeSeriesRepository["SnmpMetricSample"]):
    """Repository for SNMP telemetry samples and :class:`MetricDefinition` catalog entries."""

    _model_spec = ("app.models.telemetry", "SnmpMetricSample")
    default_order_by = ("-timestamp",)

    def list_for_device(
        self,
        device_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        metric_name: str | None = None,
        oid: str | None = None,
        interface_id: str | None = None,
        limit: int = 1000,
        descending: bool = False,
        org_id: str | None = None,
    ) -> list[Any]:
        """List SNMP metric samples for a device with optional metric/OID/interface filters."""
        extra: dict[str, Any] = {}
        if metric_name is not None and self._has_column("metric_name"):
            extra["metric_name"] = metric_name
        if oid is not None and self._has_column("oid"):
            extra["oid"] = oid
        if interface_id is not None and self._has_column("interface_id"):
            extra["interface_id"] = interface_id
        return self.list_range(
            device_id=device_id,
            start=start,
            end=end,
            limit=limit,
            descending=descending,
            extra_filters=extra,
            org_id=org_id,
        )

    def latest_metrics_map(
        self,
        device_id: str,
        *,
        lookback_hours: int = 24,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Return a mapping of ``metric_name -> latest sample`` (or latest wide-row dict)."""
        if self._has_column("metric_name"):
            since = utcnow() - timedelta(hours=lookback_hours)
            samples = self.list_for_device(
                device_id,
                start=since,
                limit=500,
                descending=True,
                org_id=org_id,
            )
            latest: dict[str, Any] = {}
            for sample in samples:
                mname = str(getattr(sample, "metric_name", "unknown"))
                if mname not in latest:
                    latest[mname] = sample
            return latest

        latest_row = self.latest_for_device(device_id, org_id=org_id)
        if latest_row is None:
            return {}
        return {col: getattr(latest_row, col) for col in self._column_names()}

    def aggregate_stats(
        self,
        device_id: str,
        *,
        metric_name: str | None = None,
        value_field: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute min, max, avg, and sample count over an SNMP time window."""
        val_col = (
            self._get_column(value_field)
            if value_field is not None
            else self._resolve_column("value", "cpu_pct", "metric_value", "in_octets")
        )
        stmt = self._base_query(org_id=org_id).where(self._get_column("device_id") == device_id)
        if metric_name is not None and self._has_column("metric_name"):
            stmt = stmt.where(self._get_column("metric_name") == metric_name)
        stmt = self._apply_time_window(stmt, start=start, end=end)
        sub = stmt.subquery()
        agg_stmt = select(
            func.count().label("count"),
            func.min(sub.c[val_col.key]).label("min"),
            func.max(sub.c[val_col.key]).label("max"),
            func.avg(sub.c[val_col.key]).label("avg"),
        )
        row = self.session.execute(agg_stmt).one()
        return {
            "device_id": device_id,
            "metric": metric_name or val_col.key,
            "count": int(row.count or 0),
            "min": float(row.min) if row.min is not None else None,
            "max": float(row.max) if row.max is not None else None,
            "avg": round(float(row.avg), 3) if row.avg is not None else None,
        }

    def list_definitions(
        self,
        *,
        category: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List registered :class:`MetricDefinition` entries from the telemetry catalog."""
        def_model = resolve_model("app.models.telemetry", "MetricDefinition")
        repo = BaseRepository(self.session, model=def_model, org_id=self._effective_org_id(org_id))
        filters: dict[str, Any] = {}
        if category is not None and repo._has_column("category"):
            filters["category"] = category
        return repo.list(filters=filters, order_by="name")


class IcmpSampleRepository(_TimeSeriesRepository["IcmpMetricSample"]):
    """Repository for ICMP ping reachability, RTT latency, jitter, and packet loss samples."""

    _model_spec = ("app.models.telemetry", "IcmpMetricSample")
    default_order_by = ("-timestamp",)

    def list_for_device(
        self,
        device_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 1000,
        descending: bool = False,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return ICMP probe samples for ``device_id`` within a time range."""
        return self.list_range(
            device_id=device_id,
            start=start,
            end=end,
            limit=limit,
            descending=descending,
            org_id=org_id,
        )

    def latest_per_device(
        self,
        device_ids: Sequence[str] | None = None,
        *,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Return the latest ICMP sample for each device in a single correlated query."""
        ts_col = self._ts_col()
        dev_col = self._get_column("device_id")

        base = self._base_query(org_id=org_id)
        if device_ids is not None:
            if not device_ids:
                return {}
            base = base.where(dev_col.in_(list(device_ids)))

        sub = base.subquery()
        latest_ts = (
            select(
                sub.c.device_id.label("device_id"),
                func.max(sub.c[ts_col.key]).label("max_ts"),
            )
            .group_by(sub.c.device_id)
            .subquery()
        )
        stmt = (
            self._base_query(org_id=org_id)
            .join(
                latest_ts,
                and_(dev_col == latest_ts.c.device_id, ts_col == latest_ts.c.max_ts),
            )
        )
        result: dict[str, Any] = {}
        for sample in self.session.execute(stmt).scalars().all():
            result[str(getattr(sample, "device_id"))] = sample
        return result

    def availability_summary(
        self,
        device_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Calculate uptime percentage, RTT min/avg/max/p95, and average packet loss."""
        samples = self.list_for_device(device_id, start=start, end=end, limit=10000, org_id=org_id)
        total = len(samples)
        if total == 0:
            return {
                "device_id": device_id,
                "samples": 0,
                "availability_pct": None,
                "avg_rtt_ms": None,
                "min_rtt_ms": None,
                "max_rtt_ms": None,
                "p95_rtt_ms": None,
                "avg_packet_loss_pct": None,
            }

        rtts: list[float] = []
        losses: list[float] = []
        reachable_count = 0
        for sample in samples:
            is_up = getattr(sample, "is_reachable", None)
            if is_up is None:
                is_up = getattr(sample, "reachable", None)
            if is_up is None:
                loss_val = getattr(sample, "packet_loss_pct", 0.0)
                is_up = float(loss_val or 0.0) < 100.0
            if is_up:
                reachable_count += 1

            rtt = (
                getattr(sample, "rtt_avg_ms", None)
                or getattr(sample, "rtt_ms", None)
                or getattr(sample, "avg_rtt_ms", None)
            )
            if rtt is not None:
                rtts.append(float(rtt))

            loss = getattr(sample, "packet_loss_pct", None)
            if loss is not None:
                losses.append(float(loss))

        rtts_sorted = sorted(rtts)
        p95 = rtts_sorted[min(len(rtts_sorted) - 1, int(len(rtts_sorted) * 0.95))] if rtts_sorted else None
        return {
            "device_id": device_id,
            "samples": total,
            "availability_pct": round((reachable_count / total) * 100.0, 3),
            "avg_rtt_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "min_rtt_ms": round(rtts_sorted[0], 2) if rtts_sorted else None,
            "max_rtt_ms": round(rtts_sorted[-1], 2) if rtts_sorted else None,
            "p95_rtt_ms": round(p95, 2) if p95 is not None else None,
            "avg_packet_loss_pct": round(sum(losses) / len(losses), 2) if losses else 0.0,
        }

    def list_degraded_devices(
        self,
        *,
        rtt_threshold_ms: float = 100.0,
        loss_threshold_pct: float = 5.0,
        since: datetime | None = None,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Identify devices whose average RTT or packet loss exceeds SLA thresholds."""
        window_start = since or (utcnow() - timedelta(minutes=30))
        rtt_col = self._resolve_column("rtt_avg_ms", "rtt_ms", "avg_rtt_ms")
        loss_col = self._resolve_column("packet_loss_pct", "loss_pct")
        stmt = self._apply_time_window(self._base_query(org_id=org_id), start=window_start)
        sub = stmt.subquery()
        agg = (
            select(
                sub.c.device_id,
                func.avg(sub.c[rtt_col.key]).label("avg_rtt_ms"),
                func.avg(sub.c[loss_col.key]).label("avg_loss_pct"),
                func.count().label("sample_count"),
            )
            .group_by(sub.c.device_id)
            .having(
                or_(
                    func.avg(sub.c[rtt_col.key]) >= rtt_threshold_ms,
                    func.avg(sub.c[loss_col.key]) >= loss_threshold_pct,
                )
            )
            .order_by(desc("avg_loss_pct"), desc("avg_rtt_ms"))
        )
        return [
            {
                "device_id": str(row.device_id),
                "avg_rtt_ms": round(float(row.avg_rtt_ms or 0.0), 2),
                "avg_loss_pct": round(float(row.avg_loss_pct or 0.0), 2),
                "sample_count": int(row.sample_count),
            }
            for row in self.session.execute(agg).all()
        ]


class SyntheticProbeRepository(BaseRepository["SyntheticProbeConfig"]):
    """Repository for synthetic HTTP/TLS/DNS/TCP probe configs and execution results."""

    _model_spec = ("app.models.telemetry", "SyntheticProbeConfig")
    default_order_by = ("name",)

    def _result_repo(self, org_id: str | None = None) -> _TimeSeriesRepository[Any]:
        res_model = resolve_model("app.models.telemetry", "SyntheticProbeResult")
        return _TimeSeriesRepository(
            self.session,
            model=res_model,
            org_id=self._effective_org_id(org_id),
        )

    def list_enabled_configs(
        self,
        *,
        probe_type: str | None = None,
        site_id: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List active synthetic probe configurations."""
        filters: dict[str, Any] = {}
        if self._has_column("is_enabled"):
            filters["is_enabled"] = True
        elif self._has_column("enabled"):
            filters["enabled"] = True
        if probe_type is not None and self._has_column("probe_type"):
            filters["probe_type"] = probe_type
        if site_id is not None and self._has_column("site_id"):
            filters["site_id"] = site_id
        return self.list(filters=filters, org_id=org_id)

    def record_result(
        self,
        probe_id: str,
        data: Mapping[str, Any],
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Persist a new :class:`SyntheticProbeResult` linked to ``probe_id``."""
        repo = self._result_repo(org_id=org_id)
        fk_col = repo._resolve_column("probe_id", "probe_config_id", "config_id")
        payload = dict(data)
        payload.setdefault(fk_col.key, probe_id)
        return repo.create(payload, flush=flush)

    def list_results(
        self,
        probe_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        success: bool | None = None,
        limit: int = 500,
        descending: bool = False,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return historical execution results for a synthetic probe."""
        repo = self._result_repo(org_id=org_id)
        fk_col = repo._resolve_column("probe_id", "probe_config_id", "config_id")
        extra: dict[str, Any] = {fk_col.key: probe_id}
        if success is not None:
            ok_col = repo._optional_column("is_success", "success")
            if ok_col is not None:
                extra[ok_col.key] = success
        return repo.list_range(
            start=start,
            end=end,
            limit=limit,
            descending=descending,
            extra_filters=extra,
            org_id=org_id,
        )

    def latest_result(self, probe_id: str, *, org_id: str | None = None) -> Any | None:
        """Fetch the most recent execution result for ``probe_id``."""
        results = self.list_results(probe_id, limit=1, descending=True, org_id=org_id)
        return results[0] if results else None

    def probe_sla_summary(
        self,
        probe_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute synthetic probe success rate and latency percentiles over a window."""
        results = self.list_results(probe_id, start=start, end=end, limit=5000, org_id=org_id)
        total = len(results)
        if total == 0:
            return {
                "probe_id": probe_id,
                "runs": 0,
                "success_rate_pct": None,
                "avg_latency_ms": None,
                "p95_latency_ms": None,
            }
        ok = 0
        latencies: list[float] = []
        for res in results:
            succeeded = getattr(res, "is_success", None)
            if succeeded is None:
                succeeded = getattr(res, "success", None)
            if succeeded is None:
                succeeded = str(getattr(res, "status", "")).lower() in {"ok", "up", "passed", "success"}
            if succeeded:
                ok += 1
            lat = getattr(res, "response_time_ms", None) or getattr(res, "latency_ms", None) or getattr(res, "total_ms", None)
            if lat is not None:
                latencies.append(float(lat))
        latencies.sort()
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else None
        return {
            "probe_id": probe_id,
            "runs": total,
            "success_rate_pct": round((ok / total) * 100.0, 3),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "p95_latency_ms": round(p95, 2) if p95 is not None else None,
        }


class HostSampleRepository(_TimeSeriesRepository["HostMetricSample"]):
    """Repository for host OS telemetry samples (CPU, RAM, disk, load average, network I/O)."""

    _model_spec = ("app.models.telemetry", "HostMetricSample")
    default_order_by = ("-timestamp",)

    def list_for_device(
        self,
        device_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 1000,
        descending: bool = False,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return host OS metric samples for ``device_id``."""
        return self.list_range(
            device_id=device_id,
            start=start,
            end=end,
            limit=limit,
            descending=descending,
            org_id=org_id,
        )

    def resource_summary(
        self,
        device_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute average and peak CPU, memory, and disk utilization for a host."""
        stmt = self._base_query(org_id=org_id).where(self._get_column("device_id") == device_id)
        stmt = self._apply_time_window(stmt, start=start, end=end)
        sub = stmt.subquery()

        cpu_user = self._optional_column("cpu_user_pct")
        cpu_sys = self._optional_column("cpu_system_pct")
        cpu_col = self._optional_column("cpu_pct", "cpu_percent", "cpu_usage_pct")
        mem_col = self._optional_column("mem_used_pct", "mem_pct", "memory_pct", "memory_percent")
        disk_col = self._optional_column("disk_used_pct", "disk_pct", "disk_percent", "disk_usage_pct")

        selections: list[Any] = [func.count().label("samples")]
        if cpu_col is not None:
            selections.extend(
                [
                    func.avg(sub.c[cpu_col.key]).label("avg_cpu"),
                    func.max(sub.c[cpu_col.key]).label("max_cpu"),
                ]
            )
        elif cpu_user is not None:
            cpu_expr = (
                func.coalesce(sub.c[cpu_user.key], 0.0) + func.coalesce(sub.c[cpu_sys.key], 0.0)
                if cpu_sys is not None
                else sub.c[cpu_user.key]
            )
            selections.extend(
                [
                    func.avg(cpu_expr).label("avg_cpu"),
                    func.max(cpu_expr).label("max_cpu"),
                ]
            )
        if mem_col is not None:
            selections.extend(
                [
                    func.avg(sub.c[mem_col.key]).label("avg_mem"),
                    func.max(sub.c[mem_col.key]).label("max_mem"),
                ]
            )
        if disk_col is not None:
            selections.extend(
                [
                    func.avg(sub.c[disk_col.key]).label("avg_disk"),
                    func.max(sub.c[disk_col.key]).label("max_disk"),
                ]
            )

        row = self.session.execute(select(*selections)).mappings().one()
        return {
            "device_id": device_id,
            "samples": int(row["samples"] or 0),
            "avg_cpu_pct": round(float(row["avg_cpu"]), 2) if row.get("avg_cpu") is not None else None,
            "max_cpu_pct": round(float(row["max_cpu"]), 2) if row.get("max_cpu") is not None else None,
            "avg_mem_pct": round(float(row["avg_mem"]), 2) if row.get("avg_mem") is not None else None,
            "max_mem_pct": round(float(row["max_mem"]), 2) if row.get("max_mem") is not None else None,
            "avg_disk_pct": round(float(row["avg_disk"]), 2) if row.get("avg_disk") is not None else None,
            "max_disk_pct": round(float(row["max_disk"]), 2) if row.get("max_disk") is not None else None,
        }

    def top_cpu_hosts(
        self,
        *,
        since: datetime | None = None,
        limit: int = 10,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Rank hosts by highest average CPU utilization since ``since``."""
        window_start = since or (utcnow() - timedelta(hours=1))
        stmt = self._apply_time_window(self._base_query(org_id=org_id), start=window_start)
        sub = stmt.subquery()
        cpu_col = self._optional_column("cpu_pct", "cpu_percent", "cpu_usage_pct")
        if cpu_col is not None:
            cpu_expr: Any = sub.c[cpu_col.key]
        else:
            u_col = self._resolve_column("cpu_user_pct")
            s_col = self._optional_column("cpu_system_pct")
            cpu_expr = (
                func.coalesce(sub.c[u_col.key], 0.0) + func.coalesce(sub.c[s_col.key], 0.0)
                if s_col is not None
                else sub.c[u_col.key]
            )
        agg = (
            select(
                sub.c.device_id,
                func.avg(cpu_expr).label("avg_cpu_pct"),
                func.max(cpu_expr).label("max_cpu_pct"),
            )
            .group_by(sub.c.device_id)
            .order_by(desc("avg_cpu_pct"))
            .limit(limit)
        )
        return [
            {
                "device_id": str(r.device_id),
                "avg_cpu_pct": round(float(r.avg_cpu_pct or 0.0), 2),
                "max_cpu_pct": round(float(r.max_cpu_pct or 0.0), 2),
            }
            for r in self.session.execute(agg).all()
        ]


class MetricRollupRepository(_TimeSeriesRepository["MetricRollup"]):
    """Repository for downsampled 1m/5m/1h/1d :class:`MetricRollup` time-series buckets."""

    _model_spec = ("app.models.telemetry", "MetricRollup")
    default_order_by = ("bucket_start",)

    def list_rollups(
        self,
        *,
        device_id: str | None = None,
        metric_name: str | None = None,
        granularity: str = "5m",
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 2000,
        org_id: str | None = None,
    ) -> list[Any]:
        """Fetch rolled-up metric buckets for charting and anomaly detection."""
        extra: dict[str, Any] = {}
        if metric_name is not None and self._has_column("metric_name"):
            extra["metric_name"] = metric_name
        gran_col = self._optional_column("bucket_size", "granularity", "interval", "resolution")
        if gran_col is not None:
            extra[gran_col.key] = granularity
        return self.list_range(
            device_id=device_id,
            start=start,
            end=end,
            limit=limit,
            descending=False,
            extra_filters=extra,
            org_id=org_id,
        )

    def upsert_bucket(
        self,
        *,
        device_id: str,
        metric_name: str,
        granularity: str,
        bucket_start: datetime,
        min_value: float,
        max_value: float,
        avg_value: float,
        p95_value: float | None = None,
        sample_count: int = 1,
        org_id: str | None = None,
        flush: bool = True,
    ) -> tuple[Any, bool]:
        """Idempotently insert or update a single rollup bucket."""
        gran_col = self._resolve_column("bucket_size", "granularity", "interval", "resolution")
        ts_col = self._ts_col()
        lookup: dict[str, Any] = {
            "device_id": device_id,
            "metric_name": metric_name,
            gran_col.key: granularity,
            ts_col.key: bucket_start,
        }
        cols = self._column_names()
        candidates = {
            "min_value": min_value,
            "min_val": min_value,
            "max_value": max_value,
            "max_val": max_value,
            "avg_value": avg_value,
            "avg_val": avg_value,
            "p95_value": p95_value,
            "p95_val": p95_value,
            "sample_count": sample_count,
        }
        defaults = {k: v for k, v in candidates.items() if k in cols and v is not None}
        return self.upsert_by(lookup, defaults, org_id=org_id, flush=flush)

    def purge_by_granularity(
        self,
        granularity: str,
        cutoff: datetime,
        *,
        org_id: str | None = None,
        flush: bool = True,
    ) -> int:
        """Delete rollup rows of a specific granularity older than ``cutoff``."""
        gran_col = self._resolve_column("bucket_size", "granularity", "interval", "resolution")
        ts_col = self._ts_col()
        return self.delete_where(
            filters={gran_col.key: granularity, f"{ts_col.key}__lt": cutoff},
            org_id=org_id,
            flush=flush,
        )


class SyslogRepository(_TimeSeriesRepository["SyslogEvent"]):
    """Repository for ingested RFC 5424/3164 :class:`SyslogEvent` log messages."""

    _model_spec = ("app.models.telemetry", "SyslogEvent")
    default_order_by = ("-timestamp",)

    def search(
        self,
        *,
        device_id: str | None = None,
        severity: str | int | Sequence[str | int] | None = None,
        facility: str | int | None = None,
        source_ip: str | None = None,
        query: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int = 1,
        page_size: int = 100,
        org_id: str | None = None,
    ) -> PageResult[Any]:
        """Full-text and structured search across syslog events."""
        stmt = self._base_query(org_id=org_id)
        if device_id is not None and self._has_column("device_id"):
            stmt = stmt.where(self._get_column("device_id") == device_id)
        if severity is not None and self._has_column("severity"):
            sev_col = self._get_column("severity")
            if isinstance(severity, (str, int)):
                stmt = stmt.where(sev_col == severity)
            else:
                stmt = stmt.where(sev_col.in_(list(severity)))
        if facility is not None and self._has_column("facility"):
            stmt = stmt.where(self._get_column("facility") == facility)
        if source_ip is not None:
            ip_col = self._optional_column("source_ip", "host_ip", "hostname")
            if ip_col is not None:
                stmt = stmt.where(ip_col == source_ip)
        stmt = self._apply_time_window(stmt, start=start, end=end)
        if query:
            pattern = f"%{query.strip()}%"
            clauses = []
            for candidate in ("message", "raw_message", "app_name", "program", "hostname", "mnemonic"):
                if self._has_column(candidate):
                    clauses.append(self._get_column(candidate).ilike(pattern))
            if clauses:
                stmt = stmt.where(or_(*clauses))

        total = int(self.session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        ts_col = self._ts_col()
        ordered = stmt.order_by(ts_col.desc()).offset((page - 1) * page_size).limit(page_size)
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

    def severity_histogram(
        self,
        *,
        device_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Count syslog events grouped by severity level."""
        stmt = self._base_query(org_id=org_id)
        if device_id is not None and self._has_column("device_id"):
            stmt = stmt.where(self._get_column("device_id") == device_id)
        stmt = self._apply_time_window(stmt, start=start, end=end)
        sub = stmt.subquery()
        sev_col = self._resolve_column("severity", "severity_label")
        agg = select(sub.c[sev_col.key], func.count()).group_by(sub.c[sev_col.key])
        return {str(sev): int(cnt) for sev, cnt in self.session.execute(agg).all()}

    def recent_errors(
        self,
        *,
        device_id: str | None = None,
        limit: int = 50,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return recent high-severity (emergency/alert/critical/error) syslog messages."""
        stmt = self._base_query(org_id=org_id)
        if device_id is not None and self._has_column("device_id"):
            stmt = stmt.where(self._get_column("device_id") == device_id)
        sev_col = self._optional_column("severity")
        if sev_col is not None:
            col_type = str(sev_col.type).upper()
            if "INT" in col_type:
                stmt = stmt.where(sev_col <= 3)
            else:
                stmt = stmt.where(
                    sev_col.in_(["emergency", "alert", "critical", "error", "err", "crit", "emerg"])
                )
        ts_col = self._ts_col()
        return list(self.session.execute(stmt.order_by(ts_col.desc()).limit(limit)).scalars().all())


class NetFlowRepository(_TimeSeriesRepository["NetFlowRecord"]):
    """Repository for NetFlow/IPFIX/sFlow traffic records, top talkers, and protocol analytics."""

    _model_spec = ("app.models.telemetry", "NetFlowRecord")
    default_order_by = ("-timestamp",)

    def _exporter_col(self) -> InstrumentedAttribute[Any] | None:
        return self._optional_column("exporter_device_id", "device_id")

    def list_flows(
        self,
        *,
        device_id: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | int | None = None,
        dst_port: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 500,
        org_id: str | None = None,
    ) -> list[Any]:
        """Query raw NetFlow records filtered by endpoints, protocol, port, and time range."""
        extra: dict[str, Any] = {}
        if device_id is not None:
            exp_col = self._exporter_col()
            if exp_col is not None:
                extra[exp_col.key] = device_id
        if src_ip is not None:
            extra[self._resolve_column("src_ip", "source_ip").key] = src_ip
        if dst_ip is not None:
            extra[self._resolve_column("dst_ip", "destination_ip").key] = dst_ip
        if protocol is not None and self._has_column("protocol"):
            extra["protocol"] = protocol
        if dst_port is not None:
            extra[self._resolve_column("dst_port", "destination_port").key] = dst_port
        return self.list_range(
            start=start,
            end=end,
            limit=limit,
            descending=True,
            extra_filters=extra,
            org_id=org_id,
        )

    def _filtered_flow_query(
        self,
        *,
        device_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        org_id: str | None = None,
    ) -> Select[Any]:
        stmt = self._base_query(org_id=org_id)
        if device_id is not None:
            exp_col = self._exporter_col()
            if exp_col is not None:
                stmt = stmt.where(exp_col == device_id)
        return self._apply_time_window(stmt, start=start, end=end)

    def top_talkers(
        self,
        *,
        direction: Literal["src", "dst", "pair"] = "src",
        start: datetime | None = None,
        end: datetime | None = None,
        device_id: str | None = None,
        limit: int = 10,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate top bandwidth consumers by source IP, destination IP, or conversation pair."""
        stmt = self._filtered_flow_query(device_id=device_id, start=start, end=end, org_id=org_id)
        sub = stmt.subquery()

        src_key = self._resolve_column("src_ip", "source_ip").key
        dst_key = self._resolve_column("dst_ip", "destination_ip").key
        bytes_key = self._resolve_column("bytes_count", "bytes", "octets").key
        pkts_key = self._resolve_column("packets_count", "packets").key

        total_bytes = func.sum(sub.c[bytes_key]).label("total_bytes")
        total_pkts = func.sum(sub.c[pkts_key]).label("total_packets")
        flow_cnt = func.count().label("flow_count")

        if direction == "pair":
            agg = (
                select(sub.c[src_key], sub.c[dst_key], total_bytes, total_pkts, flow_cnt)
                .group_by(sub.c[src_key], sub.c[dst_key])
                .order_by(desc("total_bytes"))
                .limit(limit)
            )
            return [
                {
                    "src_ip": str(r[0]),
                    "dst_ip": str(r[1]),
                    "total_bytes": int(r[2] or 0),
                    "total_packets": int(r[3] or 0),
                    "flow_count": int(r[4] or 0),
                }
                for r in self.session.execute(agg).all()
            ]

        key_col = sub.c[src_key] if direction == "src" else sub.c[dst_key]
        agg = (
            select(key_col, total_bytes, total_pkts, flow_cnt)
            .group_by(key_col)
            .order_by(desc("total_bytes"))
            .limit(limit)
        )
        return [
            {
                "ip": str(r[0]),
                "direction": direction,
                "total_bytes": int(r[1] or 0),
                "total_packets": int(r[2] or 0),
                "flow_count": int(r[3] or 0),
            }
            for r in self.session.execute(agg).all()
        ]

    def protocol_breakdown(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        device_id: str | None = None,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate traffic volume and share percentage grouped by transport protocol."""
        stmt = self._filtered_flow_query(device_id=device_id, start=start, end=end, org_id=org_id)
        sub = stmt.subquery()

        proto_key = self._resolve_column("protocol", "application").key
        bytes_key = self._resolve_column("bytes_count", "bytes", "octets").key
        pkts_key = self._resolve_column("packets_count", "packets").key

        agg = (
            select(
                sub.c[proto_key],
                func.sum(sub.c[bytes_key]).label("total_bytes"),
                func.sum(sub.c[pkts_key]).label("total_packets"),
                func.count().label("flow_count"),
            )
            .group_by(sub.c[proto_key])
            .order_by(desc("total_bytes"))
        )
        rows = self.session.execute(agg).all()
        grand_total = sum(int(r[1] or 0) for r in rows)
        return [
            {
                "protocol": str(r[0]),
                "total_bytes": int(r[1] or 0),
                "total_packets": int(r[2] or 0),
                "flow_count": int(r[3] or 0),
                "share_pct": round((int(r[1] or 0) / grand_total) * 100.0, 2) if grand_total > 0 else 0.0,
            }
            for r in rows
        ]

    def top_ports(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        device_id: str | None = None,
        limit: int = 10,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Rank top destination ports by total byte volume."""
        stmt = self._filtered_flow_query(device_id=device_id, start=start, end=end, org_id=org_id)
        sub = stmt.subquery()

        port_key = self._resolve_column("dst_port", "destination_port").key
        bytes_key = self._resolve_column("bytes_count", "bytes", "octets").key
        agg = (
            select(
                sub.c[port_key],
                func.sum(sub.c[bytes_key]).label("total_bytes"),
                func.count().label("flow_count"),
            )
            .group_by(sub.c[port_key])
            .order_by(desc("total_bytes"))
            .limit(limit)
        )
        return [
            {
                "dst_port": int(r[0]) if r[0] is not None else 0,
                "total_bytes": int(r[1] or 0),
                "flow_count": int(r[2] or 0),
            }
            for r in self.session.execute(agg).all()
        ]

    def traffic_totals(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        device_id: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, int]:
        """Return total flows, bytes, and packets across a time window."""
        stmt = self._filtered_flow_query(device_id=device_id, start=start, end=end, org_id=org_id)
        sub = stmt.subquery()

        bytes_key = self._resolve_column("bytes_count", "bytes", "octets").key
        pkts_key = self._resolve_column("packets_count", "packets").key
        row = self.session.execute(
            select(
                func.count().label("flows"),
                func.coalesce(func.sum(sub.c[bytes_key]), 0).label("bytes"),
                func.coalesce(func.sum(sub.c[pkts_key]), 0).label("packets"),
            )
        ).one()
        return {
            "total_flows": int(row.flows or 0),
            "total_bytes": int(row.bytes or 0),
            "total_packets": int(row.packets or 0),
        }


class BgpPeerRepository(BaseRepository["BgpPeerSession"]):
    """Repository for eBGP/iBGP :class:`BgpPeerSession` states, prefixes, and flap counts."""

    _model_spec = ("app.models.telemetry", "BgpPeerSession")
    default_order_by = ("peer_ip",)

    def list_by_device(
        self,
        device_id: str,
        *,
        state: str | None = None,
        org_id: str | None = None,
    ) -> list[Any]:
        """List all BGP sessions configured on a router."""
        filters: dict[str, Any] = {"device_id": device_id}
        if state is not None:
            st_col = self._resolve_column("state", "session_state")
            filters[st_col.key] = state
        return self.list(filters=filters, org_id=org_id)

    def get_by_device_and_peer(
        self,
        device_id: str,
        peer_ip: str,
        *,
        org_id: str | None = None,
    ) -> Any | None:
        """Fetch a BGP session by local router ID and peer IP address."""
        return self.get_one_by(filters={"device_id": device_id, "peer_ip": peer_ip}, org_id=org_id)

    def list_non_established(self, *, org_id: str | None = None) -> list[Any]:
        """Return all BGP peer sessions that are not in the ``established`` state."""
        st_col = self._resolve_column("state", "session_state")
        stmt = self._base_query(org_id=org_id).where(func.lower(st_col) != "established")
        return list(self.session.execute(stmt).scalars().all())

    def state_summary(self, *, org_id: str | None = None) -> dict[str, Any]:
        """Summarize BGP peering health: counts per FSM state and total received prefixes."""
        st_col = self._resolve_column("state", "session_state")
        sub = self._base_query(org_id=org_id).subquery()
        agg = select(sub.c[st_col.key], func.count()).group_by(sub.c[st_col.key])
        by_state = {str(st): int(cnt) for st, cnt in self.session.execute(agg).all()}

        prefix_col = self._optional_column("prefixes_received", "received_prefixes")
        total_prefixes = 0
        if prefix_col is not None:
            total_prefixes = int(
                self.session.execute(
                    select(func.coalesce(func.sum(sub.c[prefix_col.key]), 0))
                ).scalar_one()
            )
        return {
            "total_sessions": sum(by_state.values()),
            "by_state": by_state,
            "total_prefixes_received": total_prefixes,
        }

    def record_flap(
        self,
        session_id: str,
        *,
        new_state: str,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Record a BGP FSM state transition and increment flap count."""
        peer = self.get_by_id_or_raise(session_id, org_id=org_id)
        st_col = self._resolve_column("state", "session_state")
        patch: dict[str, Any] = {st_col.key: new_state}
        flap_col = self._optional_column("flap_count", "flaps_24h")
        if flap_col is not None:
            patch[flap_col.key] = int(getattr(peer, flap_col.key, 0) or 0) + 1
        if self._has_column("last_flap_at"):
            patch["last_flap_at"] = utcnow()
        return self.update(peer, patch, flush=flush)


class EdgeAgentRepository(BaseRepository["EdgeAgent"]):
    """Repository for remote distributed polling :class:`EdgeAgent` nodes."""

    _model_spec = ("app.models.telemetry", "EdgeAgent")
    default_order_by = ("name",)

    def get_by_name(self, name: str, *, org_id: str | None = None) -> Any | None:
        """Lookup an edge agent by unique name."""
        stmt = self._base_query(org_id=org_id).where(
            func.lower(self._get_column("name")) == name.strip().lower()
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_by_site(self, site_id: str, *, org_id: str | None = None) -> list[Any]:
        """List all remote collector agents deployed at a site."""
        return self.list(filters={"site_id": site_id}, org_id=org_id)

    def list_online(
        self,
        *,
        stale_after_seconds: int = 120,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return edge agents that sent a heartbeat within ``stale_after_seconds``."""
        hb_col = self._optional_column("last_heartbeat_at", "last_seen_at")
        stmt = self._base_query(org_id=org_id)
        if hb_col is not None:
            cutoff = utcnow() - timedelta(seconds=stale_after_seconds)
            stmt = stmt.where(hb_col >= cutoff)
        elif self._has_column("status"):
            stmt = stmt.where(self._get_column("status") == "online")
        return list(self.session.execute(stmt).scalars().all())

    def list_offline(
        self,
        *,
        stale_after_seconds: int = 120,
        org_id: str | None = None,
    ) -> list[Any]:
        """Return edge agents whose heartbeat is missing or older than ``stale_after_seconds``."""
        hb_col = self._optional_column("last_heartbeat_at", "last_seen_at")
        stmt = self._base_query(org_id=org_id)
        if hb_col is not None:
            cutoff = utcnow() - timedelta(seconds=stale_after_seconds)
            stmt = stmt.where(or_(hb_col.is_(None), hb_col < cutoff))
        elif self._has_column("status"):
            stmt = stmt.where(self._get_column("status") != "online")
        return list(self.session.execute(stmt).scalars().all())

    def record_heartbeat(
        self,
        agent_id: str,
        *,
        status: str = "online",
        version: str | None = None,
        ip_address: str | None = None,
        metrics: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        flush: bool = True,
    ) -> Any:
        """Update heartbeat timestamp, version, and runtime telemetry for an edge agent."""
        now = utcnow()
        patch: dict[str, Any] = {}
        if self._has_column("status"):
            patch["status"] = status
        if self._has_column("last_heartbeat_at"):
            patch["last_heartbeat_at"] = now
        if self._has_column("last_seen_at"):
            patch["last_seen_at"] = now
        if version is not None:
            ver_col = self._optional_column("agent_version", "version")
            if ver_col is not None:
                patch[ver_col.key] = version
        if ip_address is not None and self._has_column("ip_address"):
            patch["ip_address"] = ip_address
        if metrics is not None:
            meta_col = self._optional_column("capabilities_json", "metrics", "capabilities", "metadata_json")
            if meta_col is not None:
                patch[meta_col.key] = dict(metrics)
        return self.update(agent_id, patch, org_id=org_id, flush=flush)


__all__ = [
    "BgpPeerRepository",
    "EdgeAgentRepository",
    "HostSampleRepository",
    "IcmpSampleRepository",
    "MetricRollupRepository",
    "NetFlowRepository",
    "SnmpSampleRepository",
    "SyntheticProbeRepository",
    "SyslogRepository",
]
