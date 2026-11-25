"""Thread-safe TTL/LRU caching and API/collector rate limiters.

Provides high-performance in-process caching and throttling primitives:
- Generic thread-safe :class:`TTLCache` with LRU eviction, per-key TTL,
  tag-based invalidation, prefix invalidation, hit/miss/eviction metrics,
  and stampede-protected async :meth:`TTLCache.get_or_compute`.
- :class:`TokenBucketRateLimiter` for smooth burst-tolerant API and collector
  probe throttling.
- :class:`SlidingWindowRateLimiter` for strict per-window request quotas.
- :class:`CacheRegistry` for centrally inspecting and invalidating named caches.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from app.core.exceptions import RateLimitError

T = TypeVar("T")

_MISSING: Any = object()


@dataclass
class _CacheEntry(Generic[T]):
    value: T
    expires_at: float | None  # monotonic timestamp, or None for no expiry
    tags: frozenset[str]
    created_at: float


@dataclass(frozen=True)
class CacheStats:
    """Point-in-time metrics snapshot for a :class:`TTLCache`."""

    name: str
    size: int
    max_size: int
    hits: int
    misses: int
    sets: int
    deletes: int
    evictions: int
    expirations: int
    tag_invalidations: int

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return round(self.hits / total, 4) if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hit_rate,
            "sets": self.sets,
            "deletes": self.deletes,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "tag_invalidations": self.tag_invalidations,
        }


class TTLCache(Generic[T]):
    """Thread-safe generic LRU cache with per-key TTL, tags, metrics, and async coalescing."""

    def __init__(
        self,
        *,
        max_size: int = 1024,
        default_ttl: float | None = 300.0,
        name: str = "default",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if default_ttl is not None and default_ttl <= 0:
            raise ValueError("default_ttl must be > 0 or None")

        self.name = name
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: OrderedDict[str, _CacheEntry[T]] = OrderedDict()
        self._tag_index: dict[str, set[str]] = {}

        # Async singleflight / stampede protection state (per running event loop)
        self._inflight_lock = threading.Lock()
        self._inflight: dict[tuple[int, str], asyncio.Future[Any]] = {}

        # Metrics
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._deletes = 0
        self._evictions = 0
        self._expirations = 0
        self._tag_invalidations = 0

    def _is_expired(self, entry: _CacheEntry[T], now: float) -> bool:
        return entry.expires_at is not None and now >= entry.expires_at

    def _unlink_tags(self, key: str, tags: frozenset[str]) -> None:
        for tag in tags:
            bucket = self._tag_index.get(tag)
            if bucket is not None:
                bucket.discard(key)
                if not bucket:
                    del self._tag_index[tag]

    def _remove_entry_locked(self, key: str, *, reason: str) -> bool:
        entry = self._entries.pop(key, None)
        if entry is None:
            return False
        self._unlink_tags(key, entry.tags)
        if reason == "expired":
            self._expirations += 1
        elif reason == "evicted":
            self._evictions += 1
        elif reason == "deleted":
            self._deletes += 1
        return True

    def _enforce_capacity_locked(self, now: float) -> None:
        if len(self._entries) < self.max_size:
            return
        expired_keys = [k for k, v in self._entries.items() if self._is_expired(v, now)]
        for k in expired_keys:
            self._remove_entry_locked(k, reason="expired")
        while len(self._entries) >= self.max_size:
            oldest_key, oldest_entry = self._entries.popitem(last=False)
            self._unlink_tags(oldest_key, oldest_entry.tags)
            self._evictions += 1

    def get(self, key: str, default: Any = None) -> T | Any:
        """Retrieve a cached value, updating LRU recency. Returns ``default`` on miss."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return default
            if self._is_expired(entry, now):
                self._remove_entry_locked(key, reason="expired")
                self._misses += 1
                return default
            self._entries.move_to_end(key, last=True)
            self._hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: T,
        *,
        ttl: float | None = _MISSING,
        tags: Iterable[str] = (),
    ) -> None:
        """Store ``value`` under ``key`` with optional per-key TTL and invalidation tags."""
        effective_ttl = self.default_ttl if ttl is _MISSING else ttl
        if effective_ttl is not None and effective_ttl <= 0:
            self.delete(key)
            return

        now = self._clock()
        expires_at = (now + effective_ttl) if effective_ttl is not None else None
        tag_set = frozenset(t for t in tags if t)

        with self._lock:
            if key in self._entries:
                existing = self._entries.pop(key)
                self._unlink_tags(key, existing.tags)
            else:
                self._enforce_capacity_locked(now)

            self._entries[key] = _CacheEntry(
                value=value,
                expires_at=expires_at,
                tags=tag_set,
                created_at=now,
            )
            for tag in tag_set:
                self._tag_index.setdefault(tag, set()).add(key)
            self._sets += 1

    def delete(self, key: str) -> bool:
        """Remove a single key from the cache."""
        with self._lock:
            return self._remove_entry_locked(key, reason="deleted")

    def touch(self, key: str, ttl: float | None = _MISSING) -> bool:
        """Extend the TTL and refresh LRU position of an existing key."""
        now = self._clock()
        effective_ttl = self.default_ttl if ttl is _MISSING else ttl
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return False
            if self._is_expired(entry, now):
                self._remove_entry_locked(key, reason="expired")
                return False
            entry.expires_at = (now + effective_ttl) if effective_ttl is not None else None
            self._entries.move_to_end(key, last=True)
            return True

    def ttl_remaining(self, key: str) -> float | None:
        """Return remaining seconds until ``key`` expires, or ``None`` if absent/no-TTL."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if self._is_expired(entry, now):
                self._remove_entry_locked(key, reason="expired")
                return None
            if entry.expires_at is None:
                return None
            return max(0.0, entry.expires_at - now)

    def invalidate_tag(self, tag: str) -> int:
        """Invalidate all cached entries associated with ``tag``."""
        with self._lock:
            keys = list(self._tag_index.pop(tag, ()))
            removed = 0
            for key in keys:
                if self._remove_entry_locked(key, reason="deleted"):
                    removed += 1
            self._tag_invalidations += removed
            return removed

    def invalidate_tags(self, tags: Iterable[str]) -> int:
        """Invalidate all cached entries associated with any tag in ``tags``."""
        total = 0
        for tag in tags:
            total += self.invalidate_tag(tag)
        return total

    def invalidate_prefix(self, prefix: str) -> int:
        """Invalidate all cached keys starting with ``prefix``."""
        with self._lock:
            matched = [k for k in self._entries if k.startswith(prefix)]
            removed = 0
            for key in matched:
                if self._remove_entry_locked(key, reason="deleted"):
                    removed += 1
            return removed

    def get_many(self, keys: Iterable[str]) -> dict[str, T]:
        """Fetch multiple keys at once, omitting misses."""
        result: dict[str, T] = {}
        for key in keys:
            val = self.get(key, _MISSING)
            if val is not _MISSING:
                result[key] = val
        return result

    def set_many(
        self,
        items: dict[str, T],
        *,
        ttl: float | None = _MISSING,
        tags: Iterable[str] = (),
    ) -> None:
        """Insert multiple key-value pairs with shared TTL and tags."""
        tag_tuple = tuple(tags)
        for key, value in items.items():
            self.set(key, value, ttl=ttl, tags=tag_tuple)

    def prune_expired(self) -> int:
        """Actively scan and evict all expired entries."""
        now = self._clock()
        with self._lock:
            expired = [k for k, v in self._entries.items() if self._is_expired(v, now)]
            for key in expired:
                self._remove_entry_locked(key, reason="expired")
            return len(expired)

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], T],
        *,
        ttl: float | None = _MISSING,
        tags: Iterable[str] = (),
    ) -> T:
        """Synchronous cache-aside lookup that invokes ``factory`` on cache miss."""
        cached_val = self.get(key, _MISSING)
        if cached_val is not _MISSING:
            return cached_val
        computed = factory()
        self.set(key, computed, ttl=ttl, tags=tags)
        return computed

    async def get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Awaitable[T] | T],
        *,
        ttl: float | None = _MISSING,
        tags: Iterable[str] = (),
    ) -> T:
        """Stampede-protected async cache-aside computation (singleflight).

        Concurrent async callers requesting the same missing ``key`` coalesce onto
        a single in-flight computation instead of triggering a thundering herd.
        """
        cached_val = self.get(key, _MISSING)
        if cached_val is not _MISSING:
            return cached_val

        loop = asyncio.get_running_loop()
        inflight_key = (id(loop), key)

        with self._inflight_lock:
            existing_future = self._inflight.get(inflight_key)
            if existing_future is None:
                future: asyncio.Future[T] = loop.create_future()
                self._inflight[inflight_key] = future
                is_leader = True
            else:
                future = existing_future
                is_leader = False

        if not is_leader:
            return await asyncio.shield(future)

        try:
            # Re-check cache after acquiring leadership in case it was just populated
            recheck = self.get(key, _MISSING)
            if recheck is not _MISSING:
                result: T = recheck
            else:
                raw_res = compute_fn()
                result = await raw_res if inspect.isawaitable(raw_res) else raw_res
                self.set(key, result, ttl=ttl, tags=tags)
            if not future.done():
                future.set_result(result)
            return result
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            with self._inflight_lock:
                self._inflight.pop(inflight_key, None)

    def clear(self) -> None:
        """Remove all entries and tag mappings from the cache."""
        with self._lock:
            self._entries.clear()
            self._tag_index.clear()

    def keys(self) -> list[str]:
        """Return all currently live (non-expired) keys."""
        self.prune_expired()
        with self._lock:
            return list(self._entries.keys())

    def stats(self) -> CacheStats:
        """Return a thread-safe snapshot of cache utilization and hit metrics."""
        with self._lock:
            return CacheStats(
                name=self.name,
                size=len(self._entries),
                max_size=self.max_size,
                hits=self._hits,
                misses=self._misses,
                sets=self._sets,
                deletes=self._deletes,
                evictions=self._evictions,
                expirations=self._expirations,
                tag_invalidations=self._tag_invalidations,
            )

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return False
            if self._is_expired(entry, now):
                self._remove_entry_locked(key, reason="expired")
                return False
            return True

    def __len__(self) -> int:
        self.prune_expired()
        with self._lock:
            return len(self._entries)


def cached(
    cache: TTLCache[Any],
    *,
    ttl: float | None = _MISSING,
    key_builder: Callable[..., str] | None = None,
    tags: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator caching sync or async function results in a :class:`TTLCache`."""

    def _default_key(func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        kw_part = ",".join(f"{k}={v!r}" for k, v in sorted(kwargs.items()))
        arg_part = ",".join(repr(a) for a in args)
        return f"{func.__module__}.{func.__qualname__}({arg_part};{kw_part})"

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                key = key_builder(*args, **kwargs) if key_builder else _default_key(func, args, kwargs)
                return await cache.get_or_compute(
                    key,
                    lambda: func(*args, **kwargs),
                    ttl=ttl,
                    tags=tags,
                )

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            key = key_builder(*args, **kwargs) if key_builder else _default_key(func, args, kwargs)
            return cache.get_or_set(
                key,
                lambda: func(*args, **kwargs),
                ttl=ttl,
                tags=tags,
            )

        return sync_wrapper

    return decorator


# ---------------------------------------------------------------------------
# Rate limiters (Token Bucket & Sliding Window)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of evaluating a rate-limit check."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: float
    reset_at: float

    def to_headers(self) -> dict[str, str]:
        """Format standard HTTP rate-limit response headers."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(math.ceil(self.reset_at))),
        }
        if not self.allowed and self.retry_after_seconds > 0:
            headers["Retry-After"] = str(max(1, int(math.ceil(self.retry_after_seconds))))
        return headers


@dataclass
class _BucketState:
    tokens: float
    last_refill: float


class TokenBucketRateLimiter:
    """Thread-safe per-key token bucket rate limiter supporting smooth bursts.

    Ideal for collector polling quotas, SNMP/SSH concurrency pacing, and bursty
    API endpoints.
    """

    def __init__(
        self,
        *,
        capacity: float,
        refill_rate: float,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")

        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.RLock()
        self._buckets: dict[str, _BucketState] = {}
        self._allowed_total = 0
        self._rejected_total = 0

    def allow(self, key: str, *, tokens: float = 1.0) -> RateLimitDecision:
        """Attempt to consume ``tokens`` from ``key``'s bucket."""
        if tokens <= 0:
            raise ValueError("tokens must be > 0")
        now = self._clock()
        wall_now = self._wall_clock()

        with self._lock:
            state = self._buckets.get(key)
            if state is None:
                state = _BucketState(tokens=self.capacity, last_refill=now)
                self._buckets[key] = state
            else:
                elapsed = max(0.0, now - state.last_refill)
                state.tokens = min(self.capacity, state.tokens + elapsed * self.refill_rate)
                state.last_refill = now

            if state.tokens >= tokens:
                state.tokens -= tokens
                self._allowed_total += 1
                seconds_to_full = (self.capacity - state.tokens) / self.refill_rate
                return RateLimitDecision(
                    allowed=True,
                    limit=int(self.capacity),
                    remaining=int(math.floor(state.tokens)),
                    retry_after_seconds=0.0,
                    reset_at=wall_now + seconds_to_full,
                )

            deficit = tokens - state.tokens
            retry_after = deficit / self.refill_rate
            self._rejected_total += 1
            return RateLimitDecision(
                allowed=False,
                limit=int(self.capacity),
                remaining=0,
                retry_after_seconds=round(retry_after, 3),
                reset_at=wall_now + retry_after,
            )

    def consume_or_raise(self, key: str, *, tokens: float = 1.0) -> RateLimitDecision:
        """Consume tokens or raise :class:`RateLimitError` when throttled."""
        decision = self.allow(key, tokens=tokens)
        if not decision.allowed:
            raise RateLimitError(
                "Rate limit exceeded; retry later",
                details={
                    "key": key,
                    "limit": decision.limit,
                    "retry_after_seconds": decision.retry_after_seconds,
                },
            )
        return decision

    def reset(self, key: str | None = None) -> None:
        """Reset one key's bucket or all buckets when ``key`` is ``None``."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def prune_idle(self, idle_seconds: float = 3600.0) -> int:
        """Evict idle buckets that have refilled to full capacity long ago."""
        now = self._clock()
        with self._lock:
            stale = [
                k for k, st in self._buckets.items() if (now - st.last_refill) >= idle_seconds
            ]
            for k in stale:
                del self._buckets[k]
            return len(stale)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "type": "token_bucket",
                "capacity": self.capacity,
                "refill_rate": self.refill_rate,
                "active_keys": len(self._buckets),
                "allowed_total": self._allowed_total,
                "rejected_total": self._rejected_total,
            }


class SlidingWindowRateLimiter:
    """Thread-safe exact sliding-window log rate limiter per key.

    Enforces a strict maximum of ``max_requests`` within any rolling
    ``window_seconds`` interval, preventing boundary burst spikes.
    """

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self.max_requests = max_requests
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.RLock()
        self._windows: dict[str, deque[float]] = {}
        self._allowed_total = 0
        self._rejected_total = 0

    def allow(self, key: str) -> RateLimitDecision:
        """Check and record an incoming request for ``key``."""
        now = self._clock()
        wall_now = self._wall_clock()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._windows.get(key)
            if timestamps is None:
                timestamps = deque()
                self._windows[key] = timestamps

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                self._allowed_total += 1
                remaining = self.max_requests - len(timestamps)
                oldest = timestamps[0]
                reset_in = max(0.0, self.window_seconds - (now - oldest))
                return RateLimitDecision(
                    allowed=True,
                    limit=self.max_requests,
                    remaining=remaining,
                    retry_after_seconds=0.0,
                    reset_at=wall_now + reset_in,
                )

            oldest = timestamps[0]
            retry_after = max(0.001, self.window_seconds - (now - oldest))
            self._rejected_total += 1
            return RateLimitDecision(
                allowed=False,
                limit=self.max_requests,
                remaining=0,
                retry_after_seconds=round(retry_after, 3),
                reset_at=wall_now + retry_after,
            )

    def consume_or_raise(self, key: str) -> RateLimitDecision:
        """Record a request or raise :class:`RateLimitError` when over quota."""
        decision = self.allow(key)
        if not decision.allowed:
            raise RateLimitError(
                "Sliding window rate limit exceeded",
                details={
                    "key": key,
                    "limit": decision.limit,
                    "window_seconds": self.window_seconds,
                    "retry_after_seconds": decision.retry_after_seconds,
                },
            )
        return decision

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._windows.clear()
            else:
                self._windows.pop(key, None)

    def prune_idle(self) -> int:
        """Remove keys with no timestamps remaining inside the active window."""
        cutoff = self._clock() - self.window_seconds
        with self._lock:
            empty_keys: list[str] = []
            for key, timestamps in self._windows.items():
                while timestamps and timestamps[0] <= cutoff:
                    timestamps.popleft()
                if not timestamps:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._windows[key]
            return len(empty_keys)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "type": "sliding_window",
                "max_requests": self.max_requests,
                "window_seconds": self.window_seconds,
                "active_keys": len(self._windows),
                "allowed_total": self._allowed_total,
                "rejected_total": self._rejected_total,
            }


# ---------------------------------------------------------------------------
# Named cache registry
# ---------------------------------------------------------------------------


class CacheRegistry:
    """Central registry for managing named :class:`TTLCache` instances."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._caches: dict[str, TTLCache[Any]] = {}

    def get_or_create(
        self,
        name: str,
        *,
        max_size: int = 1024,
        default_ttl: float | None = 300.0,
    ) -> TTLCache[Any]:
        with self._lock:
            cache = self._caches.get(name)
            if cache is None:
                cache = TTLCache(max_size=max_size, default_ttl=default_ttl, name=name)
                self._caches[name] = cache
            return cache

    def get(self, name: str) -> TTLCache[Any] | None:
        with self._lock:
            return self._caches.get(name)

    def all_stats(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: cache.stats().to_dict() for name, cache in self._caches.items()}

    def clear_all(self) -> None:
        with self._lock:
            for cache in self._caches.values():
                cache.clear()


_registry = CacheRegistry()


def get_cache(
    name: str = "default",
    *,
    max_size: int = 1024,
    default_ttl: float | None = 300.0,
) -> TTLCache[Any]:
    """Return a named singleton :class:`TTLCache` from the global registry."""
    return _registry.get_or_create(name, max_size=max_size, default_ttl=default_ttl)


def get_cache_registry() -> CacheRegistry:
    """Return the global :class:`CacheRegistry`."""
    return _registry
