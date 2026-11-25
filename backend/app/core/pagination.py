"""Pagination (offset & cursor), filter DSL parsing, multi-field sorting, and API envelopes.

Provides consistent query parsing and response formatting across all NetPulse
collection endpoints:
- Validated offset/page pagination (:class:`OffsetParams`, :class:`OffsetPage`).
- Opaque URL-safe Base64 cursor encoding/decoding (:func:`encode_cursor`,
  :func:`decode_cursor`) with optional HMAC integrity signatures.
- Structured query filter DSL parser supporting ``eq``, ``ne``, ``gt``, ``gte``,
  ``lt``, ``lte``, ``in``, ``nin``, ``contains``, ``icontains``, ``startswith``,
  ``endswith``, ``isnull``, and ``between`` operators across both query-parameter
  and string-expression formats, with in-memory & SQLAlchemy 2.0 application.
- Multi-field sort specification parser (``-created_at,+hostname,latency_ms:desc``).
- Standardized JSON API response envelope builders.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, TypeVar
from urllib.parse import urlencode

from app.core.exceptions import QuerySyntaxError, ValidationError

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Offset Pagination
# ---------------------------------------------------------------------------

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200


@dataclass(frozen=True)
class OffsetParams:
    """Validated page/limit parameters for offset-based pagination."""

    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    max_page_size: int = MAX_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.page < 1:
            raise ValidationError("page must be >= 1", details={"page": self.page})
        if self.page_size < 1 or self.page_size > self.max_page_size:
            raise ValidationError(
                f"page_size must be between 1 and {self.max_page_size}",
                details={"page_size": self.page_size, "max_page_size": self.max_page_size},
            )

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


@dataclass(frozen=True)
class OffsetPage(Generic[T]):
    """Slice of items paired with offset pagination metadata."""

    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        if self.total <= 0:
            return 0
        return math.ceil(self.total / self.page_size)

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1


def paginate_sequence(
    items: Sequence[T],
    params: OffsetParams | None = None,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> OffsetPage[T]:
    """Slice an in-memory sequence into an :class:`OffsetPage`."""
    resolved = params or OffsetParams(page=page, page_size=page_size)
    total = len(items)
    sliced = list(items[resolved.offset : resolved.offset + resolved.limit])
    return OffsetPage(
        items=sliced,
        total=total,
        page=resolved.page,
        page_size=resolved.page_size,
    )


# ---------------------------------------------------------------------------
# Base64 Cursor Pagination
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CursorPayload:
    """Decoded keyset cursor state."""

    sort_value: Any
    tie_breaker: str | None = None
    direction: str = "next"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CursorParams:
    """Validated parameters for cursor-based pagination."""

    cursor: str | None = None
    limit: int = DEFAULT_PAGE_SIZE
    max_limit: int = MAX_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.limit < 1 or self.limit > self.max_limit:
            raise ValidationError(
                f"limit must be between 1 and {self.max_limit}",
                details={"limit": self.limit, "max_limit": self.max_limit},
            )


@dataclass(frozen=True)
class CursorPage(Generic[T]):
    """Cursor-paginated result slice."""

    items: list[T]
    next_cursor: str | None
    prev_cursor: str | None
    has_more: bool
    limit: int


def _sign_cursor_bytes(raw: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:12]).decode("ascii").rstrip("=")


def encode_cursor(
    sort_value: Any,
    *,
    tie_breaker: str | None = None,
    direction: str = "next",
    extra: dict[str, Any] | None = None,
    secret: str | None = None,
) -> str:
    """Encode pagination state into an opaque URL-safe Base64 cursor token."""
    serialized_val = (
        sort_value.isoformat() if isinstance(sort_value, datetime) else sort_value
    )
    body: dict[str, Any] = {
        "v": 1,
        "s": serialized_val,
        "d": direction,
    }
    if tie_breaker is not None:
        body["id"] = tie_breaker
    if extra:
        body["x"] = extra

    raw = json.dumps(body, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if secret:
        sig = _sign_cursor_bytes(raw, secret)
        return f"{encoded}.{sig}"
    return encoded


def decode_cursor(cursor: str, *, secret: str | None = None) -> CursorPayload:
    """Decode and validate an opaque Base64 cursor token."""
    if not cursor or not isinstance(cursor, str):
        raise ValidationError("Cursor must be a non-empty string")

    token = cursor.strip()
    provided_sig: str | None = None
    if "." in token:
        token, provided_sig = token.rsplit(".", 1)

    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + padding).encode("ascii"))
    except Exception as exc:
        raise ValidationError("Malformed pagination cursor", details={"cursor": cursor}) from exc

    if secret is not None:
        if not provided_sig:
            raise ValidationError("Unsigned pagination cursor rejected")
        expected_sig = _sign_cursor_bytes(raw, secret)
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise ValidationError("Invalid pagination cursor signature")

    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("Corrupted pagination cursor payload") from exc

    if not isinstance(body, dict) or body.get("v") != 1 or "s" not in body:
        raise ValidationError("Unsupported pagination cursor schema")

    return CursorPayload(
        sort_value=body["s"],
        tie_breaker=body.get("id"),
        direction=str(body.get("d", "next")),
        extra=dict(body.get("x") or {}),
    )


# ---------------------------------------------------------------------------
# Query Filter DSL Parser & Evaluators
# ---------------------------------------------------------------------------


class FilterOperator(str, Enum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NIN = "nin"
    CONTAINS = "contains"
    ICONTAINS = "icontains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    ISNULL = "isnull"
    BETWEEN = "between"


_VALID_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_BRACKET_PARAM_RE = re.compile(r"^filter\[([A-Za-z_][A-Za-z0-9_.]*)\](?:\[([a-z]+)\])?$")
_DSL_CLAUSE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?::([a-z]+):|\s+(eq|ne|gt|gte|lt|lte|in|nin|contains|icontains|startswith|endswith|isnull|between)\s+)\s*(.+?)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FilterCondition:
    """Single parsed filter predicate."""

    field: str
    operator: FilterOperator
    value: Any


def _coerce_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise QuerySyntaxError(f"Expected boolean value, got {raw!r}")


def _coerce_scalar(raw: Any, target_type: type[Any] | None) -> Any:
    if raw is None or target_type is None:
        return raw
    if target_type is bool:
        return _coerce_bool(raw)
    if target_type is datetime:
        if isinstance(raw, datetime):
            return raw
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError as exc:
            raise QuerySyntaxError(f"Invalid ISO-8601 datetime value: {raw!r}") from exc
    if isinstance(raw, target_type):
        return raw
    try:
        return target_type(raw)
    except (ValueError, TypeError) as exc:
        raise QuerySyntaxError(
            f"Cannot coerce {raw!r} to {target_type.__name__}",
            details={"value": raw, "expected_type": target_type.__name__},
        ) from exc


def _split_list_value(raw: Any) -> list[str]:
    if isinstance(raw, (list, tuple, set)):
        return [str(v).strip() for v in raw]
    text = str(raw).strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    elif text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    sep = "|" if "|" in text and "," not in text else ","
    return [part.strip().strip("'\"") for part in text.split(sep) if part.strip()]


def _validate_and_build_condition(
    field_name: str,
    op_str: str,
    raw_value: Any,
    *,
    allowed_fields: Iterable[str] | None = None,
    field_types: Mapping[str, type[Any]] | None = None,
) -> FilterCondition:
    if not _VALID_FIELD_RE.match(field_name):
        raise QuerySyntaxError(f"Invalid filter field name: {field_name!r}")
    if allowed_fields is not None and field_name not in set(allowed_fields):
        raise QuerySyntaxError(
            f"Filtering by field {field_name!r} is not allowed",
            details={"field": field_name},
        )
    try:
        op = FilterOperator(op_str.lower())
    except ValueError as exc:
        raise QuerySyntaxError(
            f"Unsupported filter operator: {op_str!r}",
            details={"operator": op_str, "supported": [o.value for o in FilterOperator]},
        ) from exc

    target_type = field_types.get(field_name) if field_types else None

    if op == FilterOperator.ISNULL:
        value: Any = _coerce_bool(raw_value)
    elif op in {FilterOperator.IN, FilterOperator.NIN}:
        items = _split_list_value(raw_value)
        value = [_coerce_scalar(v, target_type) for v in items]
    elif op == FilterOperator.BETWEEN:
        items = _split_list_value(raw_value)
        if len(items) != 2:
            raise QuerySyntaxError(
                f"Operator 'between' requires exactly 2 bounds for {field_name!r}",
                details={"value": raw_value},
            )
        value = (_coerce_scalar(items[0], target_type), _coerce_scalar(items[1], target_type))
    else:
        cleaned = raw_value.strip("'\"") if isinstance(raw_value, str) else raw_value
        value = _coerce_scalar(cleaned, target_type)

    return FilterCondition(field=field_name, operator=op, value=value)


def parse_filter_params(
    params: Mapping[str, Any],
    *,
    allowed_fields: Iterable[str] | None = None,
    field_types: Mapping[str, type[Any]] | None = None,
    ignored_keys: Iterable[str] = ("page", "page_size", "limit", "cursor", "sort", "q"),
) -> list[FilterCondition]:
    """Parse HTTP query parameters into :class:`FilterCondition` objects.

    Supports:
    - ``status__eq=up``, ``latency_ms__gte=50``, ``vendor__in=cisco,arista``
    - ``filter[status][eq]=up``, ``filter[status]=up``
    - Bare ``status=up`` (interpreted as ``eq``)
    """
    ignore_set = set(ignored_keys)
    conditions: list[FilterCondition] = []

    for raw_key, raw_val in params.items():
        if raw_key in ignore_set or raw_val is None or raw_val == "":
            continue

        bracket = _BRACKET_PARAM_RE.match(raw_key)
        if bracket:
            field_name = bracket.group(1)
            op_str = bracket.group(2) or FilterOperator.EQ.value
        elif "__" in raw_key:
            field_name, op_str = raw_key.rsplit("__", 1)
        else:
            field_name = raw_key
            op_str = FilterOperator.EQ.value

        conditions.append(
            _validate_and_build_condition(
                field_name,
                op_str,
                raw_val,
                allowed_fields=allowed_fields,
                field_types=field_types,
            )
        )
    return conditions


def parse_filter_dsl(
    expression: str | None,
    *,
    allowed_fields: Iterable[str] | None = None,
    field_types: Mapping[str, type[Any]] | None = None,
) -> list[FilterCondition]:
    """Parse a filter DSL string into :class:`FilterCondition` objects.

    Examples::

        "status:eq:up;latency_ms:gt:25;vendor:in:cisco|arista"
        "status eq up AND cpu_pct gte 80"
    """
    if not expression or not expression.strip():
        return []

    clauses = re.split(r"\s*;\s*|\s+AND\s+", expression.strip(), flags=re.IGNORECASE)
    conditions: list[FilterCondition] = []

    for clause in clauses:
        if not clause.strip():
            continue
        match = _DSL_CLAUSE_RE.match(clause)
        if not match:
            raise QuerySyntaxError(
                f"Invalid filter clause syntax: {clause!r}",
                details={"clause": clause},
            )
        field_name = match.group(1)
        op_str = match.group(2) or match.group(3)
        raw_val = match.group(4)
        conditions.append(
            _validate_and_build_condition(
                field_name,
                op_str,
                raw_val,
                allowed_fields=allowed_fields,
                field_types=field_types,
            )
        )
    return conditions


def _extract_attr(item: Any, field_path: str) -> Any:
    current = item
    for part in field_path.split("."):
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def evaluate_filter(item: Any, condition: FilterCondition) -> bool:
    """Evaluate a single :class:`FilterCondition` against a dict or object."""
    actual = _extract_attr(item, condition.field)
    op = condition.operator
    target = condition.value

    if op == FilterOperator.ISNULL:
        return (actual is None) is bool(target)
    if actual is None:
        return op == FilterOperator.NE and target is not None

    if op == FilterOperator.EQ:
        return bool(actual == target)
    if op == FilterOperator.NE:
        return bool(actual != target)
    if op == FilterOperator.GT:
        return bool(actual > target)
    if op == FilterOperator.GTE:
        return bool(actual >= target)
    if op == FilterOperator.LT:
        return bool(actual < target)
    if op == FilterOperator.LTE:
        return bool(actual <= target)
    if op == FilterOperator.IN:
        return actual in target
    if op == FilterOperator.NIN:
        return actual not in target
    if op == FilterOperator.CONTAINS:
        return str(target) in str(actual)
    if op == FilterOperator.ICONTAINS:
        return str(target).lower() in str(actual).lower()
    if op == FilterOperator.STARTSWITH:
        return str(actual).startswith(str(target))
    if op == FilterOperator.ENDSWITH:
        return str(actual).endswith(str(target))
    if op == FilterOperator.BETWEEN:
        low, high = target
        return bool(low <= actual <= high)
    return False


def evaluate_filters(items: Iterable[T], conditions: Sequence[FilterCondition]) -> list[T]:
    """Filter an in-memory iterable using AND semantics across all conditions."""
    if not conditions:
        return list(items)
    return [item for item in items if all(evaluate_filter(item, cond) for cond in conditions)]


def apply_sqlalchemy_filters(
    stmt: Any,
    model: Any,
    conditions: Sequence[FilterCondition],
) -> Any:
    """Apply parsed :class:`FilterCondition` predicates onto a SQLAlchemy 2.0 Select statement."""
    for cond in conditions:
        column = getattr(model, cond.field, None)
        if column is None:
            raise QuerySyntaxError(
                f"Unknown filter column {cond.field!r} on {getattr(model, '__name__', model)}"
            )
        op = cond.operator
        val = cond.value
        if op == FilterOperator.EQ:
            stmt = stmt.where(column == val)
        elif op == FilterOperator.NE:
            stmt = stmt.where(column != val)
        elif op == FilterOperator.GT:
            stmt = stmt.where(column > val)
        elif op == FilterOperator.GTE:
            stmt = stmt.where(column >= val)
        elif op == FilterOperator.LT:
            stmt = stmt.where(column < val)
        elif op == FilterOperator.LTE:
            stmt = stmt.where(column <= val)
        elif op == FilterOperator.IN:
            stmt = stmt.where(column.in_(val))
        elif op == FilterOperator.NIN:
            stmt = stmt.where(~column.in_(val))
        elif op == FilterOperator.CONTAINS:
            stmt = stmt.where(column.contains(str(val)))
        elif op == FilterOperator.ICONTAINS:
            stmt = stmt.where(column.ilike(f"%{val}%"))
        elif op == FilterOperator.STARTSWITH:
            stmt = stmt.where(column.startswith(str(val)))
        elif op == FilterOperator.ENDSWITH:
            stmt = stmt.where(column.endswith(str(val)))
        elif op == FilterOperator.ISNULL:
            stmt = stmt.where(column.is_(None) if val else column.is_not(None))
        elif op == FilterOperator.BETWEEN:
            low, high = val
            stmt = stmt.where(column.between(low, high))
    return stmt


# ---------------------------------------------------------------------------
# Multi-Field Sort Parser
# ---------------------------------------------------------------------------


class SortDirection(str, Enum):
    ASC = "asc"
    DESC = "desc"


@dataclass(frozen=True)
class SortField:
    """Single sort directive."""

    field: str
    direction: SortDirection = SortDirection.ASC


def parse_sort_string(
    sort_expr: str | None,
    *,
    allowed_fields: Iterable[str] | None = None,
    default: Sequence[SortField] = (),
) -> list[SortField]:
    """Parse multi-field sort directives such as ``-created_at,+hostname,latency_ms:desc``."""
    if not sort_expr or not sort_expr.strip():
        return list(default)

    allowed_set = set(allowed_fields) if allowed_fields is not None else None
    fields: list[SortField] = []
    seen: set[str] = set()

    for raw_token in sort_expr.split(","):
        token = raw_token.strip()
        if not token:
            continue

        direction = SortDirection.ASC
        field_name = token

        if token.startswith("-"):
            direction = SortDirection.DESC
            field_name = token[1:].strip()
        elif token.startswith("+"):
            direction = SortDirection.ASC
            field_name = token[1:].strip()
        elif ":" in token:
            field_name, dir_part = token.rsplit(":", 1)
            field_name = field_name.strip()
            try:
                direction = SortDirection(dir_part.strip().lower())
            except ValueError as exc:
                raise QuerySyntaxError(
                    f"Invalid sort direction {dir_part!r} for field {field_name!r}"
                ) from exc

        if not _VALID_FIELD_RE.match(field_name):
            raise QuerySyntaxError(f"Invalid sort field name: {field_name!r}")
        if allowed_set is not None and field_name not in allowed_set:
            raise QuerySyntaxError(
                f"Sorting by field {field_name!r} is not allowed",
                details={"field": field_name},
            )
        if field_name not in seen:
            seen.add(field_name)
            fields.append(SortField(field=field_name, direction=direction))

    return fields or list(default)


def sort_sequence(items: Iterable[T], sort_fields: Sequence[SortField]) -> list[T]:
    """Stably sort an in-memory collection by multiple :class:`SortField` directives."""
    result = list(items)
    for sf in reversed(sort_fields):
        reverse = sf.direction == SortDirection.DESC
        # Partition None values so they always sort last regardless of direction
        non_null = [item for item in result if _extract_attr(item, sf.field) is not None]
        nulls = [item for item in result if _extract_attr(item, sf.field) is None]
        non_null.sort(key=lambda it: _extract_attr(it, sf.field), reverse=reverse)
        result = non_null + nulls
    return result


def apply_sqlalchemy_sorts(stmt: Any, model: Any, sort_fields: Sequence[SortField]) -> Any:
    """Apply multi-field ordering onto a SQLAlchemy 2.0 Select statement."""
    order_clauses = []
    for sf in sort_fields:
        column = getattr(model, sf.field, None)
        if column is None:
            raise QuerySyntaxError(
                f"Unknown sort column {sf.field!r} on {getattr(model, '__name__', model)}"
            )
        order_clauses.append(column.desc() if sf.direction == SortDirection.DESC else column.asc())
    if order_clauses:
        stmt = stmt.order_by(*order_clauses)
    return stmt


# ---------------------------------------------------------------------------
# Standardized API Response Envelope Builders
# ---------------------------------------------------------------------------


def _build_page_url(base_url: str, page: int, page_size: int, extra_params: Mapping[str, Any] | None) -> str:
    query: dict[str, Any] = dict(extra_params or {})
    query["page"] = page
    query["page_size"] = page_size
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{urlencode(query, doseq=True)}"


def build_offset_envelope(
    page: OffsetPage[Any],
    *,
    base_url: str | None = None,
    extra_query: Mapping[str, Any] | None = None,
    meta: Mapping[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Construct a standardized JSON response envelope for offset-paginated data."""
    pagination: dict[str, Any] = {
        "mode": "offset",
        "total": page.total,
        "page": page.page,
        "page_size": page.page_size,
        "total_pages": page.total_pages,
        "has_next": page.has_next,
        "has_prev": page.has_prev,
    }
    envelope_meta: dict[str, Any] = {
        "pagination": pagination,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if request_id is not None:
        envelope_meta["request_id"] = request_id
    if meta:
        envelope_meta.update(meta)

    envelope: dict[str, Any] = {
        "data": page.items,
        "meta": envelope_meta,
    }

    if base_url:
        links: dict[str, str | None] = {
            "self": _build_page_url(base_url, page.page, page.page_size, extra_query),
            "next": (
                _build_page_url(base_url, page.page + 1, page.page_size, extra_query)
                if page.has_next
                else None
            ),
            "prev": (
                _build_page_url(base_url, page.page - 1, page.page_size, extra_query)
                if page.has_prev
                else None
            ),
        }
        envelope["links"] = links

    return envelope


def build_cursor_envelope(
    page: CursorPage[Any],
    *,
    meta: Mapping[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Construct a standardized JSON response envelope for cursor-paginated data."""
    envelope_meta: dict[str, Any] = {
        "pagination": {
            "mode": "cursor",
            "limit": page.limit,
            "count": len(page.items),
            "has_more": page.has_more,
            "next_cursor": page.next_cursor,
            "prev_cursor": page.prev_cursor,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if request_id is not None:
        envelope_meta["request_id"] = request_id
    if meta:
        envelope_meta.update(meta)
    return {
        "data": page.items,
        "meta": envelope_meta,
    }


def build_item_envelope(
    item: Any,
    *,
    meta: Mapping[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Construct a standardized JSON response envelope for a single resource."""
    envelope_meta: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat()}
    if request_id is not None:
        envelope_meta["request_id"] = request_id
    if meta:
        envelope_meta.update(meta)
    return {"data": item, "meta": envelope_meta}


def build_error_envelope(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Construct a standardized JSON error response envelope."""
    err: dict[str, Any] = {
        "code": code,
        "message": message,
        "details": dict(details or {}),
    }
    if request_id is not None:
        err["request_id"] = request_id
    return {"error": err}
