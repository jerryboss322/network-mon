"""In-process typed event bus with wildcard routing, middleware, DLQ, and SSE replay.

Designed to decouple NetPulse subsystems (collectors, alert engine, topology
discovery, compliance auditor, playbooks, and real-time WebSocket/SSE streams):
- Strongly-typed immutable :class:`Event` envelope with correlation ID & tenant scope.
- AMQP/MQTT-style wildcard topic matching (``device.*``, ``alert.#``, ``*``).
- Support for both synchronous and asynchronous subscribers with priority ordering
  and per-subscription predicate filters.
- Composable middleware pipeline for enrichment, metrics, auditing, or filtering.
- Bounded dead-letter queue (DLQ) capturing failed deliveries with replay support.
- Bounded ring-buffer event history supporting replay and live SSE streaming.
- Concrete factory helpers for device, telemetry, alert, incident, topology,
  compliance, and playbook domain events.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import threading
import traceback
import uuid
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.core.logging import get_org_id, get_request_id

logger = logging.getLogger(__name__)


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


@dataclass(frozen=True)
class Event:
    """Typed domain event envelope propagated through :class:`EventBus`."""

    topic: str
    payload: dict[str, Any] = field(default_factory=dict)
    source: str = "netpulse.core"
    org_id: str | None = field(default_factory=get_org_id)
    id: str = field(default_factory=_new_event_id)
    timestamp: datetime = field(default_factory=_utcnow)
    correlation_id: str | None = field(default_factory=get_request_id)
    severity: EventSeverity = EventSeverity.INFO
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "topic": self.topic,
            "source": self.source,
            "org_id": self.org_id,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "severity": self.severity.value if isinstance(self.severity, EventSeverity) else str(self.severity),
            "version": self.version,
            "metadata": self.metadata,
        }

    def to_sse(self) -> str:
        """Render the event as a Server-Sent Events (SSE) frame."""
        data = json.dumps(self.to_dict(), default=str, separators=(",", ":"))
        return f"id: {self.id}\nevent: {self.topic}\ndata: {data}\n\n"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        """Reconstruct an :class:`Event` from a serialized dictionary."""
        ts_raw = raw.get("timestamp")
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw)
        elif isinstance(ts_raw, datetime):
            ts = ts_raw
        else:
            ts = _utcnow()

        sev_raw = raw.get("severity", EventSeverity.INFO.value)
        try:
            severity = EventSeverity(sev_raw)
        except ValueError:
            severity = EventSeverity.INFO

        return cls(
            id=str(raw.get("id") or _new_event_id()),
            topic=str(raw["topic"]),
            payload=dict(raw.get("payload") or {}),
            source=str(raw.get("source") or "netpulse.core"),
            org_id=raw.get("org_id"),
            timestamp=ts,
            correlation_id=raw.get("correlation_id"),
            severity=severity,
            version=int(raw.get("version", 1)),
            metadata=dict(raw.get("metadata") or {}),
        )


# ---------------------------------------------------------------------------
# Wildcard topic matcher
# ---------------------------------------------------------------------------


def match_topic(pattern: str, topic: str) -> bool:
    """Match a dot-delimited topic against a wildcard subscription pattern.

    Matching rules:
    - ``*`` as the entire pattern matches **any** topic (catch-all convenience).
    - ``#`` matches zero or more dot-separated segments (e.g. ``alert.#`` matches
      ``alert``, ``alert.triggered``, and ``alert.bgp.session_down``).
    - ``*`` inside a dotted pattern matches **exactly one** segment (e.g.
      ``device.*`` matches ``device.discovered`` but not ``device.link.down``).
    - Literal segments match case-sensitively.
    """
    pat = pattern.strip()
    top = topic.strip()
    if not pat or not top:
        return False
    if pat in {"*", "#"}:
        return True
    if pat == top:
        return True

    p_parts = pat.split(".")
    t_parts = top.split(".")
    p_len = len(p_parts)
    t_len = len(t_parts)

    # Dynamic programming table over (pattern index, topic index)
    memo: dict[tuple[int, int], bool] = {}

    def _match(pi: int, ti: int) -> bool:
        key = (pi, ti)
        if key in memo:
            return memo[key]

        if pi == p_len and ti == t_len:
            result = True
        elif pi == p_len:
            result = False
        elif p_parts[pi] == "#":
            # '#' can consume zero segments or one segment and stay on '#'
            result = _match(pi + 1, ti) or (ti < t_len and _match(pi, ti + 1))
        elif ti == t_len:
            result = False
        elif p_parts[pi] == "*" or p_parts[pi] == t_parts[ti]:
            result = _match(pi + 1, ti + 1)
        else:
            result = False

        memo[key] = result
        return result

    return _match(0, 0)


# ---------------------------------------------------------------------------
# Subscription, Middleware, and Dead-Letter Queue types
# ---------------------------------------------------------------------------

EventHandler = Callable[[Event], Any]
EventFilter = Callable[[Event], bool]
NextMiddleware = Callable[[Event], Awaitable[Event | None]]
EventMiddleware = Callable[[Event, NextMiddleware], Awaitable[Event | None] | Event | None]


@dataclass
class Subscription:
    """Represents a registered handler bound to a topic pattern."""

    id: str
    pattern: str
    handler: EventHandler
    name: str
    priority: int = 0
    is_async: bool = False
    filter_fn: EventFilter | None = None
    once: bool = False
    org_id: str | None = None
    delivered_count: int = 0
    error_count: int = 0
    created_at: datetime = field(default_factory=_utcnow)

    def matches(self, event: Event) -> bool:
        if self.org_id is not None and event.org_id != self.org_id:
            return False
        if not match_topic(self.pattern, event.topic):
            return False
        if self.filter_fn is not None:
            return bool(self.filter_fn(event))
        return True


@dataclass
class DeadLetterEntry:
    """Captures a failed event delivery for inspection and replay."""

    id: str
    event: Event
    subscription_id: str
    handler_name: str
    pattern: str
    error_type: str
    error_message: str
    traceback_text: str
    failed_at: datetime = field(default_factory=_utcnow)
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event": self.event.to_dict(),
            "subscription_id": self.subscription_id,
            "handler_name": self.handler_name,
            "pattern": self.pattern,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "failed_at": self.failed_at.isoformat(),
            "attempts": self.attempts,
        }


@dataclass
class PublishResult:
    """Summary returned after publishing an event."""

    event_id: str
    topic: str
    matched_subscribers: int
    delivered: int
    failed: int
    suppressed_by_middleware: bool = False


# ---------------------------------------------------------------------------
# EventBus implementation
# ---------------------------------------------------------------------------


class EventBus:
    """Asynchronous & synchronous pub/sub event bus with middleware, DLQ, and history."""

    def __init__(
        self,
        *,
        history_size: int = 2000,
        dlq_size: int = 500,
    ) -> None:
        self._lock = threading.RLock()
        self._subscriptions: dict[str, Subscription] = {}
        self._middlewares: list[EventMiddleware] = []
        self._history: deque[Event] = deque(maxlen=max(1, history_size))
        self._dlq: deque[DeadLetterEntry] = deque(maxlen=max(1, dlq_size))
        self._stream_queues: dict[str, tuple[str, str | None, asyncio.Queue[Event]]] = {}

        # Metrics counters
        self._published_total: int = 0
        self._delivered_total: int = 0
        self._failed_total: int = 0
        self._suppressed_total: int = 0

    # --- Middleware registration ---

    def use(self, middleware: EventMiddleware) -> None:
        """Append a middleware callable to the publish pipeline.

        Middleware signature: ``async def mw(event, next_fn) -> Event | None``
        (sync callables returning ``Event | None`` are also supported).
        Returning ``None`` suppresses event delivery.
        """
        with self._lock:
            self._middlewares.append(middleware)

    # --- Subscription management ---

    def subscribe(
        self,
        pattern: str,
        handler: EventHandler,
        *,
        name: str | None = None,
        priority: int = 0,
        filter_fn: EventFilter | None = None,
        once: bool = False,
        org_id: str | None = None,
    ) -> Subscription:
        """Register a sync or async subscriber for ``pattern``."""
        if not pattern or not pattern.strip():
            raise ValueError("Subscription topic pattern must not be empty")
        sub_id = f"sub_{uuid.uuid4().hex[:12]}"
        handler_name = name or getattr(handler, "__qualname__", repr(handler))
        sub = Subscription(
            id=sub_id,
            pattern=pattern.strip(),
            handler=handler,
            name=handler_name,
            priority=priority,
            is_async=inspect.iscoroutinefunction(handler),
            filter_fn=filter_fn,
            once=once,
            org_id=org_id,
        )
        with self._lock:
            self._subscriptions[sub_id] = sub
        return sub

    def on(
        self,
        pattern: str,
        *,
        priority: int = 0,
        filter_fn: EventFilter | None = None,
        once: bool = False,
        org_id: str | None = None,
    ) -> Callable[[EventHandler], EventHandler]:
        """Decorator registering a function as a subscriber for ``pattern``."""

        def decorator(func: EventHandler) -> EventHandler:
            self.subscribe(
                pattern,
                func,
                priority=priority,
                filter_fn=filter_fn,
                once=once,
                org_id=org_id,
            )
            return func

        return decorator

    def unsubscribe(self, subscription_id: str) -> bool:
        """Remove a subscriber by its subscription ID."""
        with self._lock:
            return self._subscriptions.pop(subscription_id, None) is not None

    def list_subscriptions(self) -> list[Subscription]:
        """Return all active subscriptions ordered by priority descending."""
        with self._lock:
            return sorted(
                self._subscriptions.values(),
                key=lambda s: (-s.priority, s.created_at),
            )

    # --- Publishing ---

    def _record_history_and_streams(self, event: Event) -> None:
        with self._lock:
            self._history.append(event)
            self._published_total += 1
            streams = list(self._stream_queues.values())

        for pattern, org_filter, queue in streams:
            if org_filter is not None and event.org_id != org_filter:
                continue
            if not match_topic(pattern, event.topic):
                continue
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest event on slow SSE consumer to protect bus memory
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass

    def _record_dead_letter(self, event: Event, sub: Subscription, exc: BaseException) -> None:
        entry = DeadLetterEntry(
            id=f"dlq_{uuid.uuid4().hex[:12]}",
            event=event,
            subscription_id=sub.id,
            handler_name=sub.name,
            pattern=sub.pattern,
            error_type=type(exc).__name__,
            error_message=str(exc),
            traceback_text=traceback.format_exc(),
        )
        with self._lock:
            sub.error_count += 1
            self._failed_total += 1
            self._dlq.append(entry)
        logger.warning(
            "Event handler %s failed for topic %s (%s): %s",
            sub.name,
            event.topic,
            entry.error_type,
            entry.error_message,
        )

    def _matching_subscriptions(self, event: Event) -> list[Subscription]:
        with self._lock:
            candidates = sorted(
                self._subscriptions.values(),
                key=lambda s: (-s.priority, s.created_at),
            )
        matched: list[Subscription] = []
        for sub in candidates:
            try:
                if sub.matches(event):
                    matched.append(sub)
            except Exception as exc:
                self._record_dead_letter(event, sub, exc)
        return matched

    async def _run_middleware_async(self, event: Event) -> Event | None:
        with self._lock:
            chain = list(self._middlewares)

        async def invoke(idx: int, current: Event) -> Event | None:
            if idx >= len(chain):
                return current
            mw = chain[idx]

            async def next_fn(ev: Event) -> Event | None:
                return await invoke(idx + 1, ev)

            res = mw(current, next_fn)
            if inspect.isawaitable(res):
                return await res
            return res

        return await invoke(0, event)

    async def publish(self, event: Event) -> PublishResult:
        """Publish an event asynchronously through middleware and all matched subscribers."""
        processed = await self._run_middleware_async(event)
        if processed is None:
            with self._lock:
                self._suppressed_total += 1
            return PublishResult(
                event_id=event.id,
                topic=event.topic,
                matched_subscribers=0,
                delivered=0,
                failed=0,
                suppressed_by_middleware=True,
            )

        self._record_history_and_streams(processed)
        subscribers = self._matching_subscriptions(processed)

        delivered = 0
        failed = 0
        once_to_remove: list[str] = []

        for sub in subscribers:
            if sub.once:
                once_to_remove.append(sub.id)
            try:
                result = sub.handler(processed)
                if inspect.isawaitable(result):
                    await result
                with self._lock:
                    sub.delivered_count += 1
                    self._delivered_total += 1
                delivered += 1
            except Exception as exc:
                self._record_dead_letter(processed, sub, exc)
                failed += 1

        if once_to_remove:
            with self._lock:
                for sid in once_to_remove:
                    self._subscriptions.pop(sid, None)

        return PublishResult(
            event_id=processed.id,
            topic=processed.topic,
            matched_subscribers=len(subscribers),
            delivered=delivered,
            failed=failed,
        )

    def publish_sync(self, event: Event) -> PublishResult:
        """Synchronously publish an event.

        Executes synchronous middleware and handlers inline. If async subscribers
        match and an event loop is already running in this thread, schedules them
        as background tasks; otherwise executes them via ``asyncio.run``.
        """
        with self._lock:
            has_async_mw = any(inspect.iscoroutinefunction(m) for m in self._middlewares)

        if has_async_mw:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(self.publish(event))

        # Execute sync middleware chain
        processed: Event | None = event
        with self._lock:
            chain = list(self._middlewares)

        for mw in chain:
            if processed is None:
                break
            if inspect.iscoroutinefunction(mw):
                continue

            captured: list[Event | None] = [processed]

            async def _noop_next(ev: Event) -> Event | None:
                captured[0] = ev
                return ev

            res = mw(processed, _noop_next)
            if inspect.isawaitable(res):
                # Avoid unawaited coroutine warning
                if asyncio.iscoroutine(res):
                    res.close()
                continue
            processed = res

        if processed is None:
            with self._lock:
                self._suppressed_total += 1
            return PublishResult(
                event_id=event.id,
                topic=event.topic,
                matched_subscribers=0,
                delivered=0,
                failed=0,
                suppressed_by_middleware=True,
            )

        self._record_history_and_streams(processed)
        subscribers = self._matching_subscriptions(processed)

        delivered = 0
        failed = 0
        once_to_remove: list[str] = []

        for sub in subscribers:
            if sub.once:
                once_to_remove.append(sub.id)
            try:
                if sub.is_async:
                    coro = sub.handler(processed)
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self._run_scheduled_handler(coro, processed, sub))
                    except RuntimeError:
                        asyncio.run(coro)
                else:
                    res = sub.handler(processed)
                    if inspect.isawaitable(res):
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(self._run_scheduled_handler(res, processed, sub))
                        except RuntimeError:
                            asyncio.run(res)  # type: ignore[arg-type]
                with self._lock:
                    sub.delivered_count += 1
                    self._delivered_total += 1
                delivered += 1
            except Exception as exc:
                self._record_dead_letter(processed, sub, exc)
                failed += 1

        if once_to_remove:
            with self._lock:
                for sid in once_to_remove:
                    self._subscriptions.pop(sid, None)

        return PublishResult(
            event_id=processed.id,
            topic=processed.topic,
            matched_subscribers=len(subscribers),
            delivered=delivered,
            failed=failed,
        )

    async def _run_scheduled_handler(
        self,
        awaitable: Awaitable[Any],
        event: Event,
        sub: Subscription,
    ) -> None:
        try:
            await awaitable
        except Exception as exc:
            self._record_dead_letter(event, sub, exc)

    # --- History & SSE streaming ---

    def get_history(
        self,
        *,
        pattern: str = "*",
        org_id: str | None = None,
        since: datetime | None = None,
        after_event_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Query the bounded ring-buffer history for replay or audit inspection."""
        with self._lock:
            snapshot = list(self._history)

        if after_event_id is not None:
            for idx, ev in enumerate(snapshot):
                if ev.id == after_event_id:
                    snapshot = snapshot[idx + 1 :]
                    break

        results: list[Event] = []
        for ev in snapshot:
            if org_id is not None and ev.org_id != org_id:
                continue
            if since is not None and ev.timestamp < since:
                continue
            if not match_topic(pattern, ev.topic):
                continue
            results.append(ev)

        if limit > 0 and len(results) > limit:
            return results[-limit:]
        return results

    async def stream(
        self,
        *,
        pattern: str = "*",
        org_id: str | None = None,
        replay_last: int = 0,
        after_event_id: str | None = None,
        queue_size: int = 256,
    ) -> AsyncIterator[Event]:
        """Async generator yielding replayed and live events for SSE/WebSocket feeds."""
        stream_id = f"stream_{uuid.uuid4().hex[:12]}"
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)

        with self._lock:
            self._stream_queues[stream_id] = (pattern, org_id, queue)

        try:
            if after_event_id is not None:
                for ev in self.get_history(
                    pattern=pattern, org_id=org_id, after_event_id=after_event_id, limit=queue_size
                ):
                    yield ev
            elif replay_last > 0:
                for ev in self.get_history(pattern=pattern, org_id=org_id, limit=replay_last):
                    yield ev

            while True:
                ev = await queue.get()
                yield ev
        finally:
            with self._lock:
                self._stream_queues.pop(stream_id, None)

    # --- Dead-Letter Queue operations ---

    def get_dead_letters(self, *, limit: int = 100) -> list[DeadLetterEntry]:
        """Return recent dead-letter entries (newest last)."""
        with self._lock:
            entries = list(self._dlq)
        return entries[-limit:] if limit > 0 else entries

    async def replay_dead_letter(self, dlq_id: str) -> bool:
        """Retry delivery of a specific dead-letter entry against its original subscriber."""
        with self._lock:
            target_idx: int | None = None
            target_entry: DeadLetterEntry | None = None
            for idx, entry in enumerate(self._dlq):
                if entry.id == dlq_id:
                    target_idx = idx
                    target_entry = entry
                    break
            if target_entry is None or target_idx is None:
                return False
            sub = self._subscriptions.get(target_entry.subscription_id)
            if sub is None:
                return False

        try:
            res = sub.handler(target_entry.event)
            if inspect.isawaitable(res):
                await res
            with self._lock:
                try:
                    self._dlq.remove(target_entry)
                except ValueError:
                    pass
                sub.delivered_count += 1
                self._delivered_total += 1
            return True
        except Exception as exc:
            with self._lock:
                target_entry.attempts += 1
                target_entry.error_type = type(exc).__name__
                target_entry.error_message = str(exc)
                target_entry.traceback_text = traceback.format_exc()
                target_entry.failed_at = _utcnow()
            return False

    def clear_dead_letters(self) -> int:
        """Purge all dead-letter entries and return how many were cleared."""
        with self._lock:
            count = len(self._dlq)
            self._dlq.clear()
            return count

    def clear_history(self) -> None:
        """Clear the event replay ring buffer."""
        with self._lock:
            self._history.clear()

    def stats(self) -> dict[str, Any]:
        """Return operational telemetry counters for the event bus."""
        with self._lock:
            return {
                "published_total": self._published_total,
                "delivered_total": self._delivered_total,
                "failed_total": self._failed_total,
                "suppressed_total": self._suppressed_total,
                "active_subscribers": len(self._subscriptions),
                "active_streams": len(self._stream_queues),
                "history_size": len(self._history),
                "history_capacity": self._history.maxlen,
                "dead_letter_count": len(self._dlq),
                "dead_letter_capacity": self._dlq.maxlen,
            }


# ---------------------------------------------------------------------------
# Singleton bus management
# ---------------------------------------------------------------------------

_event_bus: EventBus | None = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Return the process-wide singleton :class:`EventBus`."""
    global _event_bus
    if _event_bus is None:
        with _bus_lock:
            if _event_bus is None:
                _event_bus = EventBus()
    return _event_bus


def reset_event_bus(*, history_size: int = 2000, dlq_size: int = 500) -> EventBus:
    """Replace the singleton :class:`EventBus` (useful in tests)."""
    global _event_bus
    with _bus_lock:
        _event_bus = EventBus(history_size=history_size, dlq_size=dlq_size)
        return _event_bus


# ---------------------------------------------------------------------------
# Concrete domain event factory helpers
# ---------------------------------------------------------------------------


def device_discovered_event(
    *,
    device_id: str,
    hostname: str,
    ip_address: str,
    vendor: str | None = None,
    device_type: str | None = None,
    org_id: str | None = None,
    discovery_method: str = "snmp",
) -> Event:
    return Event(
        topic="device.discovered",
        source="netpulse.discovery",
        org_id=org_id,
        severity=EventSeverity.INFO,
        payload={
            "device_id": device_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "vendor": vendor,
            "device_type": device_type,
            "discovery_method": discovery_method,
        },
    )


def device_status_changed_event(
    *,
    device_id: str,
    hostname: str,
    previous_status: str,
    new_status: str,
    reason: str | None = None,
    org_id: str | None = None,
) -> Event:
    severity = EventSeverity.CRITICAL if new_status.lower() in {"down", "unreachable"} else EventSeverity.INFO
    return Event(
        topic="device.status.changed",
        source="netpulse.collector",
        org_id=org_id,
        severity=severity,
        payload={
            "device_id": device_id,
            "hostname": hostname,
            "previous_status": previous_status,
            "new_status": new_status,
            "reason": reason,
        },
    )


def device_updated_event(
    *,
    device_id: str,
    changed_fields: list[str],
    updated_by: str | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="device.updated",
        source="netpulse.inventory",
        org_id=org_id,
        payload={
            "device_id": device_id,
            "changed_fields": changed_fields,
            "updated_by": updated_by,
        },
    )


def telemetry_ingested_event(
    *,
    device_id: str,
    collector: str,
    metric_count: int,
    metrics_summary: dict[str, Any] | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic=f"telemetry.ingested.{collector}",
        source=f"netpulse.collector.{collector}",
        org_id=org_id,
        severity=EventSeverity.DEBUG,
        payload={
            "device_id": device_id,
            "collector": collector,
            "metric_count": metric_count,
            "summary": metrics_summary or {},
        },
    )


def interface_threshold_event(
    *,
    device_id: str,
    interface_name: str,
    metric: str,
    value: float,
    threshold: float,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="telemetry.interface.threshold_breached",
        source="netpulse.telemetry",
        org_id=org_id,
        severity=EventSeverity.WARNING,
        payload={
            "device_id": device_id,
            "interface_name": interface_name,
            "metric": metric,
            "value": value,
            "threshold": threshold,
        },
    )


def alert_triggered_event(
    *,
    alert_id: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    device_id: str | None = None,
    metric_value: float | None = None,
    message: str = "",
    org_id: str | None = None,
) -> Event:
    sev_map = {
        "critical": EventSeverity.CRITICAL,
        "high": EventSeverity.ERROR,
        "warning": EventSeverity.WARNING,
        "info": EventSeverity.INFO,
    }
    return Event(
        topic=f"alert.triggered.{severity.lower()}",
        source="netpulse.alerting",
        org_id=org_id,
        severity=sev_map.get(severity.lower(), EventSeverity.WARNING),
        payload={
            "alert_id": alert_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "device_id": device_id,
            "metric_value": metric_value,
            "message": message,
        },
    )


def alert_acknowledged_event(
    *,
    alert_id: str,
    acknowledged_by: str,
    comment: str | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="alert.acknowledged",
        source="netpulse.alerting",
        org_id=org_id,
        payload={
            "alert_id": alert_id,
            "acknowledged_by": acknowledged_by,
            "comment": comment,
        },
    )


def alert_resolved_event(
    *,
    alert_id: str,
    resolved_by: str | None = None,
    auto_resolved: bool = False,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="alert.resolved",
        source="netpulse.alerting",
        org_id=org_id,
        payload={
            "alert_id": alert_id,
            "resolved_by": resolved_by,
            "auto_resolved": auto_resolved,
        },
    )


def incident_created_event(
    *,
    incident_id: str,
    title: str,
    severity: str,
    alert_ids: list[str] | None = None,
    root_cause_device_id: str | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="incident.created",
        source="netpulse.incidents",
        org_id=org_id,
        severity=EventSeverity.CRITICAL if severity.lower() == "critical" else EventSeverity.ERROR,
        payload={
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "alert_ids": alert_ids or [],
            "root_cause_device_id": root_cause_device_id,
        },
    )


def incident_resolved_event(
    *,
    incident_id: str,
    resolved_by: str | None = None,
    resolution_summary: str = "",
    duration_seconds: float | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="incident.resolved",
        source="netpulse.incidents",
        org_id=org_id,
        payload={
            "incident_id": incident_id,
            "resolved_by": resolved_by,
            "resolution_summary": resolution_summary,
            "duration_seconds": duration_seconds,
        },
    )


def topology_link_discovered_event(
    *,
    link_id: str,
    source_device_id: str,
    target_device_id: str,
    source_interface: str | None = None,
    target_interface: str | None = None,
    protocol: str = "lldp",
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="topology.link.discovered",
        source="netpulse.topology",
        org_id=org_id,
        payload={
            "link_id": link_id,
            "source_device_id": source_device_id,
            "target_device_id": target_device_id,
            "source_interface": source_interface,
            "target_interface": target_interface,
            "protocol": protocol,
        },
    )


def topology_link_down_event(
    *,
    link_id: str,
    source_device_id: str,
    target_device_id: str,
    reason: str | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="topology.link.down",
        source="netpulse.topology",
        org_id=org_id,
        severity=EventSeverity.ERROR,
        payload={
            "link_id": link_id,
            "source_device_id": source_device_id,
            "target_device_id": target_device_id,
            "reason": reason,
        },
    )


def compliance_violation_event(
    *,
    policy_id: str,
    policy_name: str,
    device_id: str,
    severity: str,
    violated_rules: list[str],
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="compliance.violation.detected",
        source="netpulse.compliance",
        org_id=org_id,
        severity=EventSeverity.WARNING if severity.lower() != "critical" else EventSeverity.CRITICAL,
        payload={
            "policy_id": policy_id,
            "policy_name": policy_name,
            "device_id": device_id,
            "severity": severity,
            "violated_rules": violated_rules,
        },
    )


def compliance_audit_completed_event(
    *,
    audit_id: str,
    devices_checked: int,
    passed: int,
    failed: int,
    score_pct: float,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic="compliance.audit.completed",
        source="netpulse.compliance",
        org_id=org_id,
        payload={
            "audit_id": audit_id,
            "devices_checked": devices_checked,
            "passed": passed,
            "failed": failed,
            "score_pct": score_pct,
        },
    )


def playbook_execution_event(
    *,
    execution_id: str,
    playbook_id: str,
    status: str,
    triggered_by: str | None = None,
    target_device_ids: list[str] | None = None,
    org_id: str | None = None,
) -> Event:
    return Event(
        topic=f"playbook.execution.{status.lower()}",
        source="netpulse.playbooks",
        org_id=org_id,
        severity=EventSeverity.ERROR if status.lower() == "failed" else EventSeverity.INFO,
        payload={
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "status": status,
            "triggered_by": triggered_by,
            "target_device_ids": target_device_ids or [],
        },
    )
