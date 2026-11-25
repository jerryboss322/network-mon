"""Structured logging, correlation context, secret redaction, and timing helpers.

Provides production-grade logging infrastructure for NetPulse:
- Structured JSON log formatting for log aggregators (ELK, Loki, Datadog, CloudWatch).
- ANSI-colored human-readable console formatting for local development.
- Async-safe request and tenant context propagation via ``contextvars``.
- Automatic secret redaction filter protecting passwords, Bearer tokens, JWTs,
  SNMP community strings, API keys (``npm_*``), and private keys.
- Synchronous and asynchronous performance timing context managers.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import sys
import time
import traceback
import uuid
from collections.abc import Generator, Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from types import TracebackType
from typing import Any, TextIO

# ---------------------------------------------------------------------------
# Context variables for async-safe correlation & structured logging context
# ---------------------------------------------------------------------------

_request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "netpulse_request_id", default=None
)
_org_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "netpulse_org_id", default=None
)
_user_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "netpulse_user_id", default=None
)
_log_context_var: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "netpulse_log_context", default=None
)

# Standard LogRecord attributes that should not be copied into custom "extra" fields
_STANDARD_RECORD_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def generate_request_id() -> str:
    """Generate a compact, sortable-friendly correlation ID."""
    return f"req_{uuid.uuid4().hex[:16]}"


def set_request_id(request_id: str | None) -> contextvars.Token[str | None]:
    """Set the correlation/request ID for the current execution context."""
    return _request_id_var.set(request_id)


def get_request_id() -> str | None:
    """Return the active correlation/request ID, or ``None`` if unset."""
    return _request_id_var.get()


def set_org_id(org_id: str | None) -> contextvars.Token[str | None]:
    """Set the active organization/tenant ID in logging context."""
    return _org_id_var.set(org_id)


def get_org_id() -> str | None:
    """Return the active organization/tenant ID, or ``None``."""
    return _org_id_var.get()


def set_user_id(user_id: str | None) -> contextvars.Token[str | None]:
    """Set the active user ID in logging context."""
    return _user_id_var.set(user_id)


def get_user_id() -> str | None:
    """Return the active user ID, or ``None``."""
    return _user_id_var.get()


def get_context() -> dict[str, Any]:
    """Return a shallow copy of the current bound structured logging context."""
    ctx = _log_context_var.get()
    merged: dict[str, Any] = dict(ctx) if ctx else {}
    req_id = _request_id_var.get()
    org_id = _org_id_var.get()
    user_id = _user_id_var.get()
    if req_id is not None:
        merged.setdefault("request_id", req_id)
    if org_id is not None:
        merged.setdefault("org_id", org_id)
    if user_id is not None:
        merged.setdefault("user_id", user_id)
    return merged


def bind_context(**kwargs: Any) -> contextvars.Token[dict[str, Any] | None]:
    """Bind arbitrary key-value pairs into the current task/thread log context.

    Special keys ``request_id``, ``org_id``, and ``user_id`` also update their
    dedicated context variables so getters stay synchronized.
    """
    current = dict(_log_context_var.get() or {})
    for key, value in kwargs.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
    if "request_id" in kwargs:
        _request_id_var.set(kwargs["request_id"])
    if "org_id" in kwargs:
        _org_id_var.set(kwargs["org_id"])
    if "user_id" in kwargs:
        _user_id_var.set(kwargs["user_id"])
    return _log_context_var.set(current)


def unbind_context(*keys: str) -> None:
    """Remove specific keys from the current structured logging context."""
    current = dict(_log_context_var.get() or {})
    for key in keys:
        current.pop(key, None)
        if key == "request_id":
            _request_id_var.set(None)
        elif key == "org_id":
            _org_id_var.set(None)
        elif key == "user_id":
            _user_id_var.set(None)
    _log_context_var.set(current)


def clear_context() -> None:
    """Clear all correlation IDs and bound logging context for the current task."""
    _request_id_var.set(None)
    _org_id_var.set(None)
    _user_id_var.set(None)
    _log_context_var.set(None)


@contextmanager
def request_context(
    request_id: str | None = None,
    *,
    org_id: str | None = None,
    user_id: str | None = None,
    **extra: Any,
) -> Generator[str, None, None]:
    """Scoped context manager that binds request metadata and restores prior state."""
    rid = request_id or generate_request_id()
    tok_req = _request_id_var.set(rid)
    tok_org = _org_id_var.set(org_id if org_id is not None else _org_id_var.get())
    tok_usr = _user_id_var.set(user_id if user_id is not None else _user_id_var.get())
    prev_ctx = dict(_log_context_var.get() or {})
    next_ctx = dict(prev_ctx)
    next_ctx.update({k: v for k, v in extra.items() if v is not None})
    tok_ctx = _log_context_var.set(next_ctx)
    try:
        yield rid
    finally:
        _log_context_var.reset(tok_ctx)
        _user_id_var.reset(tok_usr)
        _org_id_var.reset(tok_org)
        _request_id_var.reset(tok_req)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

REDACTED_VALUE = "[REDACTED]"

# Sensitive field names (case-insensitive substring match) for dict/extra scrubbing
SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "community",
    "snmp_community",
    "auth_passphrase",
    "priv_passphrase",
    "private_key",
    "client_secret",
    "encryption_key",
    "vault_key",
    "credential",
    "cookie",
    "set-cookie",
)

# Compiled regex patterns applied to log messages and string values
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # NetPulse API keys: npm_<prefix>_<secret> or npm_<token>
    (
        re.compile(r"\bnpm_[A-Za-z0-9_-]{4,}(?:_[A-Za-z0-9_-]{6,})?\b"),
        "npm_[REDACTED]",
    ),
    # HTTP Bearer / Basic Authorization tokens
    (
        re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*"),
        r"\1 [REDACTED]",
    ),
    # JWT tokens (header.payload.signature)
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    # SNMP community flags in command strings (-c public, -c 'secret')
    (
        re.compile(r"(?i)(\bsnmp\w*\b[^\n]*?\s-c\s+)(?:'[^']+'|\"[^\"]+\"|\S+)"),
        r"\1[REDACTED]",
    ),
    # Key=value or key: value forms for passwords, communities, secrets, tokens, api_keys
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|snmp[_-]?community|community[_-]?string|community|"
            r"auth[_-]?pass(?:phrase)?|priv[_-]?pass(?:phrase)?|private[_-]?key|"
            r"vault[_-]?key|encryption[_-]?key)\b\s*[:=]\s*)"
            r"(?:'[^']*'|\"[^\"]*\"|[^\s,;}\]]+)"
        ),
        r"\1[REDACTED]",
    ),
    # URL embedded credentials: scheme://user:password@host
    (
        re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^/\s@]+)(@)"),
        r"\1[REDACTED]\3",
    ),
    # PEM private key blocks
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_text(text: str) -> str:
    """Apply all secret redaction regexes to a string value."""
    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_secrets(value: Any, *, max_depth: int = 8) -> Any:
    """Recursively scrub secrets from strings, mappings, and sequences."""
    if max_depth <= 0:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        sanitized: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _is_sensitive_key(k):
                sanitized[k] = REDACTED_VALUE
            else:
                sanitized[k] = redact_secrets(v, max_depth=max_depth - 1)
        return sanitized
    if isinstance(value, list):
        return [redact_secrets(item, max_depth=max_depth - 1) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item, max_depth=max_depth - 1) for item in value)
    return value


class SecretRedactionFilter(logging.Filter):
    """Logging filter that scrubs sensitive credentials from messages and extras."""

    def __init__(self, name: str = "", extra_patterns: Iterable[tuple[str, str]] = ()) -> None:
        super().__init__(name)
        self._extra_patterns: tuple[tuple[re.Pattern[str], str], ...] = tuple(
            (re.compile(pat), repl) for pat, repl in extra_patterns
        )

    def _redact_string(self, text: str) -> str:
        scrubbed = redact_text(text)
        for pat, repl in self._extra_patterns:
            scrubbed = pat.sub(repl, scrubbed)
        return scrubbed

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact_string(record.msg)
        if record.args:
            if isinstance(record.args, Mapping):
                record.args = redact_secrets(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._redact_string(arg) if isinstance(arg, str) else redact_secrets(arg)
                    for arg in record.args
                )
        for attr_name in list(record.__dict__.keys()):
            if attr_name in _STANDARD_RECORD_ATTRS:
                continue
            attr_val = record.__dict__[attr_name]
            if _is_sensitive_key(attr_name):
                record.__dict__[attr_name] = REDACTED_VALUE
            elif isinstance(attr_val, str):
                record.__dict__[attr_name] = self._redact_string(attr_val)
            elif isinstance(attr_val, (Mapping, list, tuple)):
                record.__dict__[attr_name] = redact_secrets(attr_val)
        return True


class ContextInjectionFilter(logging.Filter):
    """Injects correlation IDs and bound contextvars into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_context()
        record.request_id = ctx.get("request_id")  # type: ignore[attr-defined]
        record.org_id = ctx.get("org_id")  # type: ignore[attr-defined]
        record.user_id = ctx.get("user_id")  # type: ignore[attr-defined]
        for key, value in ctx.items():
            if key not in record.__dict__ and key not in _STANDARD_RECORD_ATTRS:
                record.__dict__[key] = value
        return True


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _json_default(obj: Any) -> Any:
    """Safe JSON serialization fallback for non-primitive objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    if isinstance(obj, BaseException):
        return f"{type(obj).__name__}: {obj}"
    return str(obj)


def _extract_extras(record: logging.LogRecord) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _STANDARD_RECORD_ATTRS or key.startswith("_"):
            continue
        if key in {"request_id", "org_id", "user_id"}:
            continue
        extras[key] = value
    return extras


class JSONLogFormatter(logging.Formatter):
    """Formats log records as single-line structured JSON objects."""

    def __init__(
        self,
        *,
        service_name: str = "netpulse",
        environment: str | None = None,
        include_source: bool = True,
    ) -> None:
        super().__init__()
        self.service_name = service_name
        self.environment = environment or os.getenv("NETMON_ENV", "development")
        self.include_source = include_source

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "service": self.service_name,
            "env": self.environment,
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", None) or get_request_id()
        org_id = getattr(record, "org_id", None) or get_org_id()
        user_id = getattr(record, "user_id", None) or get_user_id()
        if request_id is not None:
            payload["request_id"] = request_id
        if org_id is not None:
            payload["org_id"] = org_id
        if user_id is not None:
            payload["user_id"] = user_id

        if self.include_source:
            payload["source"] = {
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            }

        extras = _extract_extras(record)
        if extras:
            payload["context"] = extras

        if record.exc_info and record.exc_info[0] is not None:
            exc_type, exc_val, exc_tb = record.exc_info
            payload["exception"] = {
                "type": exc_type.__name__,
                "message": redact_text(str(exc_val)),
                "traceback": redact_text(
                    "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
                ),
            }
        elif record.stack_info:
            payload["stack_info"] = redact_text(record.stack_info)

        return json.dumps(payload, default=_json_default, ensure_ascii=False)


class ColoredConsoleFormatter(logging.Formatter):
    """Human-friendly ANSI colored formatter for interactive development terminals."""

    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"

    LEVEL_COLORS: dict[int, str] = {
        logging.DEBUG: "\033[36m",  # Cyan
        logging.INFO: "\033[32m",  # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",  # Red
        logging.CRITICAL: "\033[1;31m",  # Bold Red
    }

    def __init__(self, *, use_color: bool | None = None, show_context: bool = True) -> None:
        super().__init__()
        if use_color is None:
            self.use_color = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
        else:
            self.use_color = use_color
        self.show_context = show_context

    def _paint(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"{code}{text}{self.RESET}"

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]
        level_color = self.LEVEL_COLORS.get(record.levelno, "")
        level_label = self._paint(f"{record.levelname:<8}", level_color)
        ts_label = self._paint(ts, self.DIM)
        logger_label = self._paint(record.name, self.CYAN)

        parts: list[str] = [ts_label, level_label, logger_label]

        req_id = getattr(record, "request_id", None) or get_request_id()
        if req_id:
            parts.append(self._paint(f"[{req_id}]", self.MAGENTA))

        parts.append("-")
        parts.append(record.getMessage())

        if self.show_context:
            ctx_items: dict[str, Any] = {}
            org_id = getattr(record, "org_id", None) or get_org_id()
            user_id = getattr(record, "user_id", None) or get_user_id()
            if org_id:
                ctx_items["org_id"] = org_id
            if user_id:
                ctx_items["user_id"] = user_id
            ctx_items.update(_extract_extras(record))
            if ctx_items:
                kv_str = " ".join(f"{k}={v!r}" for k, v in ctx_items.items())
                parts.append(self._paint(f"| {kv_str}", self.DIM))

        rendered = " ".join(parts)
        if record.exc_info and record.exc_info[0] is not None:
            tb_text = redact_text(self.formatException(record.exc_info))
            rendered = f"{rendered}\n{tb_text}"
        elif record.stack_info:
            rendered = f"{rendered}\n{redact_text(record.stack_info)}"
        return rendered


# ---------------------------------------------------------------------------
# Performance timing context manager
# ---------------------------------------------------------------------------


class PerformanceTimer:
    """Sync & async context manager that logs execution duration with slow thresholds.

    Example::

        with PerformanceTimer("snmp_poll", device_id="dev-1", warn_ms=500) as timer:
            poll_device()
        print(timer.elapsed_ms)
    """

    def __init__(
        self,
        operation: str,
        *,
        logger: logging.Logger | None = None,
        level: int = logging.INFO,
        warn_ms: float | None = None,
        log_on_exit: bool = True,
        **fields: Any,
    ) -> None:
        self.operation = operation
        self.logger = logger or logging.getLogger("netpulse.perf")
        self.level = level
        self.warn_ms = warn_ms
        self.log_on_exit = log_on_exit
        self.fields: dict[str, Any] = dict(fields)
        self._start_ns: int = 0
        self._end_ns: int | None = None

    @property
    def elapsed_ms(self) -> float:
        """Elapsed time in milliseconds (live while running, frozen after exit)."""
        if self._start_ns == 0:
            return 0.0
        end = self._end_ns if self._end_ns is not None else time.perf_counter_ns()
        return round((end - self._start_ns) / 1_000_000.0, 3)

    @property
    def elapsed_seconds(self) -> float:
        """Elapsed time in seconds."""
        return self.elapsed_ms / 1000.0

    def add_field(self, key: str, value: Any) -> None:
        """Attach additional structured fields to be emitted when the timer ends."""
        self.fields[key] = value

    def _start(self) -> PerformanceTimer:
        self._start_ns = time.perf_counter_ns()
        self._end_ns = None
        return self

    def _finish(self, exc_type: type[BaseException] | None) -> None:
        self._end_ns = time.perf_counter_ns()
        if not self.log_on_exit:
            return
        duration = self.elapsed_ms
        status = "error" if exc_type is not None else "ok"
        extra = {
            "operation": self.operation,
            "duration_ms": duration,
            "status": status,
            **self.fields,
        }
        if exc_type is not None:
            extra["error_type"] = exc_type.__name__
            self.logger.error(
                "Operation %s failed after %.2fms",
                self.operation,
                duration,
                extra=extra,
            )
        elif self.warn_ms is not None and duration >= self.warn_ms:
            extra["slow_threshold_ms"] = self.warn_ms
            self.logger.warning(
                "Slow operation %s completed in %.2fms (threshold=%.2fms)",
                self.operation,
                duration,
                self.warn_ms,
                extra=extra,
            )
        else:
            self.logger.log(
                self.level,
                "Operation %s completed in %.2fms",
                self.operation,
                duration,
                extra=extra,
            )

    def __enter__(self) -> PerformanceTimer:
        return self._start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._finish(exc_type)

    async def __aenter__(self) -> PerformanceTimer:
        return self._start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._finish(exc_type)


def log_duration(
    operation: str,
    *,
    logger: logging.Logger | None = None,
    level: int = logging.INFO,
    warn_ms: float | None = None,
    **fields: Any,
) -> PerformanceTimer:
    """Factory helper returning a :class:`PerformanceTimer` context manager."""
    return PerformanceTimer(
        operation,
        logger=logger,
        level=level,
        warn_ms=warn_ms,
        **fields,
    )


# ---------------------------------------------------------------------------
# Configuration entrypoint
# ---------------------------------------------------------------------------

_DEFAULT_QUIET_LOGGERS: dict[str, int] = {
    "uvicorn.access": logging.WARNING,
    "sqlalchemy.engine": logging.WARNING,
    "urllib3": logging.WARNING,
    "asyncio": logging.WARNING,
}


def _resolve_level(level: int | str) -> int:
    if isinstance(level, int):
        return level
    resolved = getattr(logging, level.strip().upper(), None)
    if not isinstance(resolved, int):
        return logging.INFO
    return resolved


def configure_logging(
    level: int | str = "INFO",
    json_format: bool = False,
    *,
    service_name: str = "netpulse",
    stream: TextIO | None = None,
    enable_redaction: bool = True,
    use_color: bool | None = None,
    quiet_loggers: Mapping[str, int | str] | None = None,
) -> logging.Logger:
    """Configure root logging with structured formatting, context, and redaction.

    Args:
        level: Root logging level (name or numeric constant).
        json_format: When True, emits structured JSON lines; otherwise emits
            ANSI-colored human-readable output.
        service_name: Service identifier embedded in JSON log entries.
        stream: Target output stream (defaults to ``sys.stderr``).
        enable_redaction: Attach :class:`SecretRedactionFilter` to the handler.
        use_color: Explicit override for ANSI color output in console mode.
        quiet_loggers: Mapping of noisy third-party logger names to levels.

    Returns:
        The configured root logger.
    """
    resolved_level = _resolve_level(level)
    root = logging.getLogger()
    root.setLevel(resolved_level)

    # Remove previously attached handlers to make repeated calls idempotent
    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setLevel(resolved_level)

    if json_format:
        handler.setFormatter(JSONLogFormatter(service_name=service_name))
    else:
        handler.setFormatter(ColoredConsoleFormatter(use_color=use_color))

    handler.addFilter(ContextInjectionFilter())
    if enable_redaction:
        handler.addFilter(SecretRedactionFilter())

    root.addHandler(handler)

    merged_quiet: dict[str, int] = dict(_DEFAULT_QUIET_LOGGERS)
    if quiet_loggers:
        for logger_name, logger_level in quiet_loggers.items():
            merged_quiet[logger_name] = _resolve_level(logger_level)
    for logger_name, logger_level in merged_quiet.items():
        logging.getLogger(logger_name).setLevel(logger_level)

    return root


def get_logger(name: str) -> logging.Logger:
    """Return a named logger under the application namespace."""
    return logging.getLogger(name)
