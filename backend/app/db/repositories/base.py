"""Generic SQLAlchemy 2.0 repository base with dynamic filtering, pagination, and tenant scoping.

This module implements :class:`BaseRepository`, a strongly typed generic data-access
layer built on SQLAlchemy 2.0's ``select()`` API. It provides:

- Automatic tenant (``org_id``) isolation for models using :class:`TenantScopedMixin`.
- Automatic soft-delete filtering for models using :class:`SoftDeleteMixin`.
- Declarative dynamic filtering (``eq``, ``ne``, ``in``, ``not_in``, ``contains``,
  ``icontains``, ``startswith``, ``endswith``, ``gte``, ``gt``, ``lte``, ``lt``,
  ``is_null``) via mapping syntax (``field__op``) or :class:`FilterSpec` instances.
- Multi-column ordering via ``"-created_at"``, ``"name:desc"``, or :class:`SortSpec`.
- Offset/page pagination returning a structured :class:`PageResult`.
- Safe CRUD, chunked bulk creation, soft-delete/restore, upsert, and conflict mapping.
- Lazy ORM model resolution so repository modules can be imported independently of
  model initialization order without circular-import issues.
"""

from __future__ import annotations

import importlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Generic, Literal, Self, TypeVar

from sqlalchemy import Select, and_, asc, delete as sa_delete, desc, false, func, inspect as sa_inspect, nullslast, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.db.base import Base, utcnow

ModelT = TypeVar("ModelT", bound=Base)

FilterOperator = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "icontains",
    "startswith",
    "endswith",
    "gte",
    "gt",
    "lte",
    "lt",
    "is_null",
]

VALID_OPERATORS: frozenset[str] = frozenset(
    {
        "eq",
        "ne",
        "in",
        "not_in",
        "contains",
        "icontains",
        "startswith",
        "endswith",
        "gte",
        "gt",
        "lte",
        "lt",
        "is_null",
    }
)

IMMUTABLE_FIELDS: frozenset[str] = frozenset({"id", "created_at"})


@lru_cache(maxsize=128)
def resolve_model(module_path: str, class_name: str) -> type[Any]:
    """Lazily import and cache an ORM model class by module path and attribute name.

    Args:
        module_path: Dotted Python module path (e.g. ``"app.models.inventory"``).
        class_name: Class name exported from that module (e.g. ``"Device"``).

    Returns:
        The resolved SQLAlchemy declarative model class.

    Raises:
        ImportError: If the target module or attribute cannot be resolved.
    """
    module = importlib.import_module(module_path)
    model_cls = getattr(module, class_name, None)
    if model_cls is None:
        raise ImportError(f"Model '{class_name}' not found in module '{module_path}'")
    return model_cls


@dataclass(frozen=True, slots=True)
class FilterSpec:
    """Structured predicate applied to a SQLAlchemy ``select()`` query."""

    field: str
    operator: FilterOperator = "eq"
    value: Any = None

    @classmethod
    def parse(cls, key: str, value: Any) -> FilterSpec:
        """Parse a ``field__operator`` filter key into a :class:`FilterSpec`.

        Examples:
            ``FilterSpec.parse("status", "online")`` -> ``FilterSpec("status", "eq", "online")``
            ``FilterSpec.parse("cpu_pct__gte", 80.0)`` -> ``FilterSpec("cpu_pct", "gte", 80.0)``
            ``FilterSpec.parse("hostname__contains", "core")`` -> ``FilterSpec("hostname", "contains", "core")``
        """
        if "__" in key:
            field_name, op = key.rsplit("__", 1)
            if op in VALID_OPERATORS:
                return cls(field=field_name, operator=op, value=value)  # type: ignore[arg-type]
            raise ValidationError(
                f"Unsupported filter operator '{op}' for field '{field_name}'",
                details={"field": field_name, "operator": op, "supported": sorted(VALID_OPERATORS)},
            )
        return cls(field=key, operator="eq", value=value)


@dataclass(frozen=True, slots=True)
class SortSpec:
    """Structured ordering directive for a single column."""

    field: str
    direction: Literal["asc", "desc"] = "asc"
    nulls_last: bool = True

    @classmethod
    def parse(cls, expression: str | SortSpec) -> SortSpec:
        """Parse a sort expression such as ``"-created_at"``, ``"name:desc"``, or ``"name"``."""
        if isinstance(expression, SortSpec):
            return expression
        expr = expression.strip()
        if not expr:
            raise ValidationError("Sort expression cannot be empty")
        if expr.startswith("-"):
            return cls(field=expr[1:].strip(), direction="desc")
        if expr.startswith("+"):
            return cls(field=expr[1:].strip(), direction="asc")
        if ":" in expr:
            field_name, raw_dir = expr.rsplit(":", 1)
            direction = raw_dir.strip().lower()
            if direction not in {"asc", "desc"}:
                raise ValidationError(
                    f"Invalid sort direction '{raw_dir}' for field '{field_name}'",
                    details={"field": field_name, "direction": raw_dir},
                )
            return cls(field=field_name.strip(), direction=direction)  # type: ignore[arg-type]
        return cls(field=expr, direction="asc")


@dataclass(slots=True)
class PageResult(Generic[ModelT]):
    """Container for paginated repository query results."""

    items: list[ModelT]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool

    def to_dict(self, serializer: Any | None = None) -> dict[str, Any]:
        """Serialize pagination metadata and items into a JSON-friendly dictionary."""
        serialized = [serializer(item) for item in self.items] if serializer is not None else self.items
        return {
            "items": serialized,
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "total_pages": self.total_pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }


def normalize_filters(
    filters: Mapping[str, Any] | Sequence[FilterSpec] | None,
) -> list[FilterSpec]:
    """Convert filter mappings or sequences into a canonical list of :class:`FilterSpec`."""
    if filters is None:
        return []
    if isinstance(filters, Mapping):
        specs: list[FilterSpec] = []
        for raw_key, raw_value in filters.items():
            specs.append(FilterSpec.parse(raw_key, raw_value))
        return specs
    return list(filters)


def normalize_ordering(
    order_by: Sequence[str | SortSpec] | str | SortSpec | None,
) -> list[SortSpec]:
    """Convert sort strings or :class:`SortSpec` inputs into a list of :class:`SortSpec`."""
    if order_by is None:
        return []
    if isinstance(order_by, (str, SortSpec)):
        return [SortSpec.parse(order_by)]
    return [SortSpec.parse(item) for item in order_by]


class BaseRepository(Generic[ModelT]):
    """Generic SQLAlchemy 2.0 CRUD, query, pagination, and multi-tenant repository.

    Subclasses can either set the class attribute ``model = SomeOrmModel`` directly
    or define ``_model_spec = ("app.models.module", "SomeOrmModel")`` for lazy loading.
    """

    model: type[ModelT] | None = None
    _model_spec: tuple[str, str] | None = None
    default_order_by: tuple[str, ...] = ("-created_at",)

    def __init__(
        self,
        session: Session,
        model: type[ModelT] | None = None,
        *,
        org_id: str | None = None,
        include_deleted: bool = False,
    ) -> None:
        self.session = session
        if model is not None:
            self._resolved_model: type[ModelT] | None = model
        else:
            self._resolved_model = type(self).model
        self.org_id = org_id
        self.include_deleted = include_deleted

    @property
    def model_cls(self) -> type[ModelT]:
        """Return the bound SQLAlchemy ORM model class, resolving lazily if needed."""
        if self._resolved_model is None:
            spec = type(self)._model_spec
            if spec is None:
                raise RuntimeError(
                    f"{type(self).__name__} must define 'model', '_model_spec', or pass 'model' to __init__"
                )
            self._resolved_model = resolve_model(spec[0], spec[1])
        return self._resolved_model

    @property
    def entity_name(self) -> str:
        """Human-readable model name used in domain error messages."""
        if self._resolved_model is not None:
            return self._resolved_model.__name__
        if type(self)._model_spec is not None:
            return type(self)._model_spec[1]
        return type(self).__name__.removesuffix("Repository")

    def with_org(self, org_id: str) -> Self:
        """Return a new repository instance scoped to a specific organization tenant."""
        return type(self)(
            self.session,
            model=self._resolved_model,
            org_id=org_id,
            include_deleted=self.include_deleted,
        )

    # ── Model Introspection Helpers ──────────────────────────────────────────

    def _column_names(self) -> set[str]:
        mapper = sa_inspect(self.model_cls)
        return {attr.key for attr in mapper.column_attrs}

    def _has_column(self, name: str) -> bool:
        return name in self._column_names()

    def _get_column(self, name: str) -> InstrumentedAttribute[Any]:
        if not self._has_column(name):
            raise ValidationError(
                f"Unknown field '{name}' on {self.entity_name}",
                details={"entity": self.entity_name, "field": name},
            )
        return getattr(self.model_cls, name)

    def _resolve_column(self, *candidates: str) -> InstrumentedAttribute[Any]:
        """Return the first matching ORM column from candidate attribute names."""
        cols = self._column_names()
        for candidate in candidates:
            if candidate in cols:
                return getattr(self.model_cls, candidate)
        raise ValidationError(
            f"None of fields {candidates!r} exist on {self.entity_name}",
            details={"entity": self.entity_name, "candidates": list(candidates)},
        )

    def _optional_column(self, *candidates: str) -> InstrumentedAttribute[Any] | None:
        """Return the first matching ORM column from candidates, or ``None``."""
        cols = self._column_names()
        for candidate in candidates:
            if candidate in cols:
                return getattr(self.model_cls, candidate)
        return None

    def _is_tenant_scoped(self) -> bool:
        return self._has_column("org_id")

    def _is_soft_deletable(self) -> bool:
        return self._has_column("is_deleted")

    def _effective_org_id(self, org_id: str | None) -> str | None:
        return org_id if org_id is not None else self.org_id

    def _effective_include_deleted(self, include_deleted: bool | None) -> bool:
        return self.include_deleted if include_deleted is None else include_deleted

    # ── Query Construction ───────────────────────────────────────────────────

    def _base_query(
        self,
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> Select[tuple[ModelT]]:
        """Build a base ``select(model)`` statement with tenant and soft-delete guards."""
        stmt: Select[tuple[ModelT]] = select(self.model_cls)
        effective_org = self._effective_org_id(org_id)
        if effective_org is not None and self._is_tenant_scoped():
            stmt = stmt.where(self._get_column("org_id") == effective_org)
        if not self._effective_include_deleted(include_deleted) and self._is_soft_deletable():
            stmt = stmt.where(self._get_column("is_deleted").is_(False))
        return stmt

    def _build_predicate(self, spec: FilterSpec) -> Any:
        """Translate a single :class:`FilterSpec` into a SQLAlchemy column expression."""
        col = self._get_column(spec.field)
        op = spec.operator
        val = spec.value

        if op == "eq":
            return col.is_(None) if val is None else col == val
        if op == "ne":
            return col.is_not(None) if val is None else col != val
        if op == "in":
            if val is None:
                return false()
            seq = list(val) if not isinstance(val, (str, bytes)) else [val]
            return col.in_(seq) if seq else false()
        if op == "not_in":
            if val is None:
                return col.is_not(None)
            seq = list(val) if not isinstance(val, (str, bytes)) else [val]
            return col.not_in(seq) if seq else col.is_not(None) | col.is_(None)
        if op == "contains":
            return col.ilike(f"%{val}%")
        if op == "icontains":
            return col.ilike(f"%{val}%")
        if op == "startswith":
            return col.ilike(f"{val}%")
        if op == "endswith":
            return col.ilike(f"%{val}")
        if op == "gte":
            return col >= val
        if op == "gt":
            return col > val
        if op == "lte":
            return col <= val
        if op == "lt":
            return col < val
        if op == "is_null":
            return col.is_(None) if bool(val) else col.is_not(None)

        raise ValidationError(
            f"Unsupported filter operator '{op}'",
            details={"field": spec.field, "operator": op},
        )

    def _apply_filters(
        self,
        stmt: Select[Any],
        filters: Mapping[str, Any] | Sequence[FilterSpec] | None,
    ) -> Select[Any]:
        """Apply dynamic filter predicates to a SQLAlchemy ``select()`` statement."""
        specs = normalize_filters(filters)
        if not specs:
            return stmt
        predicates = [self._build_predicate(spec) for spec in specs]
        return stmt.where(and_(*predicates))

    def _apply_ordering(
        self,
        stmt: Select[Any],
        order_by: Sequence[str | SortSpec] | str | SortSpec | None,
        *,
        use_default: bool = True,
    ) -> Select[Any]:
        """Apply single or multi-column ordering to a SQLAlchemy ``select()`` statement."""
        specs = normalize_ordering(order_by)
        if not specs and use_default:
            for expr in self.default_order_by:
                parsed = SortSpec.parse(expr)
                if self._has_column(parsed.field):
                    specs.append(parsed)

        if not specs:
            return stmt

        order_clauses: list[Any] = []
        for spec in specs:
            col = self._get_column(spec.field)
            expr = desc(col) if spec.direction == "desc" else asc(col)
            order_clauses.append(nullslast(expr) if spec.nulls_last else expr)
        return stmt.order_by(*order_clauses)

    # ── Read Operations ──────────────────────────────────────────────────────

    def get_by_id(
        self,
        entity_id: str,
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> ModelT | None:
        """Fetch a single entity by its primary key ``id``, respecting tenant and soft-delete scope."""
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted).where(
            self._get_column("id") == entity_id
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_id_or_raise(
        self,
        entity_id: str,
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> ModelT:
        """Fetch an entity by ``id`` or raise :class:`NotFoundError`."""
        entity = self.get_by_id(entity_id, org_id=org_id, include_deleted=include_deleted)
        if entity is None:
            raise NotFoundError(
                f"{self.entity_name} with id '{entity_id}' was not found",
                details={"entity": self.entity_name, "id": entity_id},
            )
        return entity

    def get_many_by_ids(
        self,
        entity_ids: Sequence[str],
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> list[ModelT]:
        """Fetch all entities matching a list of primary key IDs."""
        if not entity_ids:
            return []
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted).where(
            self._get_column("id").in_(list(entity_ids))
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_one_by(
        self,
        *,
        filters: Mapping[str, Any] | Sequence[FilterSpec],
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> ModelT | None:
        """Return the first entity matching ``filters``, or ``None``."""
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted)
        stmt = self._apply_filters(stmt, filters).limit(1)
        return self.session.execute(stmt).scalar_one_or_none()

    def list(
        self,
        *,
        filters: Mapping[str, Any] | Sequence[FilterSpec] | None = None,
        order_by: Sequence[str | SortSpec] | str | SortSpec | None = None,
        limit: int | None = None,
        offset: int | None = None,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> list[ModelT]:
        """Return a filtered, ordered list of entities."""
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted)
        stmt = self._apply_filters(stmt, filters)
        stmt = self._apply_ordering(stmt, order_by)
        if offset is not None:
            if offset < 0:
                raise ValidationError("offset must be >= 0", details={"offset": offset})
            stmt = stmt.offset(offset)
        if limit is not None:
            if limit < 0:
                raise ValidationError("limit must be >= 0", details={"limit": limit})
            stmt = stmt.limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def paginate(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        max_page_size: int = 500,
        filters: Mapping[str, Any] | Sequence[FilterSpec] | None = None,
        order_by: Sequence[str | SortSpec] | str | SortSpec | None = None,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> PageResult[ModelT]:
        """Execute a paginated query returning items alongside total counts and page metadata."""
        if page < 1:
            raise ValidationError("page must be >= 1", details={"page": page})
        if page_size < 1 or page_size > max_page_size:
            raise ValidationError(
                f"page_size must be between 1 and {max_page_size}",
                details={"page_size": page_size, "max_page_size": max_page_size},
            )

        total = self.count(filters=filters, org_id=org_id, include_deleted=include_deleted)
        total_pages = math.ceil(total / page_size) if total > 0 else 0
        offset = (page - 1) * page_size

        items: list[ModelT] = []
        if total > 0 and offset < total:
            items = self.list(
                filters=filters,
                order_by=order_by,
                limit=page_size,
                offset=offset,
                org_id=org_id,
                include_deleted=include_deleted,
            )

        return PageResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1 and total_pages > 0,
        )

    def count(
        self,
        *,
        filters: Mapping[str, Any] | Sequence[FilterSpec] | None = None,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> int:
        """Count entities matching the given filters within tenant and soft-delete scope."""
        base_stmt = self._base_query(org_id=org_id, include_deleted=include_deleted)
        base_stmt = self._apply_filters(base_stmt, filters)
        count_stmt = select(func.count()).select_from(base_stmt.subquery())
        result = self.session.execute(count_stmt).scalar_one()
        return int(result)

    def exists(
        self,
        *,
        filters: Mapping[str, Any] | Sequence[FilterSpec] | None = None,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> bool:
        """Return ``True`` if at least one matching entity exists."""
        stmt = self._base_query(org_id=org_id, include_deleted=include_deleted)
        stmt = self._apply_filters(stmt, filters).limit(1)
        return self.session.execute(select(stmt.exists())).scalar_one()

    def exists_by_id(
        self,
        entity_id: str,
        *,
        org_id: str | None = None,
        include_deleted: bool | None = None,
    ) -> bool:
        """Return ``True`` if an entity with ``entity_id`` exists within scope."""
        return self.exists(filters={"id": entity_id}, org_id=org_id, include_deleted=include_deleted)

    # ── Write Operations ─────────────────────────────────────────────────────

    def _instantiate(self, data: Mapping[str, Any] | ModelT, *, org_id: str | None = None) -> ModelT:
        effective_org = self._effective_org_id(org_id)
        if isinstance(data, self.model_cls):
            entity = data
            if effective_org is not None and self._is_tenant_scoped() and getattr(entity, "org_id", None) is None:
                setattr(entity, "org_id", effective_org)
            return entity

        payload = dict(data)
        if effective_org is not None and self._is_tenant_scoped() and "org_id" not in payload:
            payload["org_id"] = effective_org

        valid_cols = self._column_names()
        unknown = [key for key in payload if key not in valid_cols]
        if unknown:
            raise ValidationError(
                f"Unknown fields for {self.entity_name}: {', '.join(sorted(unknown))}",
                details={"entity": self.entity_name, "unknown_fields": sorted(unknown)},
            )
        return self.model_cls(**payload)

    def create(
        self,
        data: Mapping[str, Any] | ModelT,
        *,
        flush: bool = True,
        org_id: str | None = None,
    ) -> ModelT:
        """Insert a new entity from a dictionary or model instance."""
        entity = self._instantiate(data, org_id=org_id)
        self.session.add(entity)
        if flush:
            try:
                self.session.flush()
            except IntegrityError as exc:
                self.session.rollback()
                raise ConflictError(
                    f"Could not create {self.entity_name} due to integrity constraint",
                    details={"entity": self.entity_name, "reason": str(exc.orig)},
                ) from exc
        return entity

    def bulk_create(
        self,
        items: Sequence[Mapping[str, Any] | ModelT],
        *,
        chunk_size: int = 500,
        flush: bool = True,
        org_id: str | None = None,
    ) -> list[ModelT]:
        """Insert multiple entities efficiently in chunks."""
        if not items:
            return []
        if chunk_size < 1:
            raise ValidationError("chunk_size must be >= 1", details={"chunk_size": chunk_size})

        created: list[ModelT] = []
        for start in range(0, len(items), chunk_size):
            batch = [self._instantiate(raw, org_id=org_id) for raw in items[start : start + chunk_size]]
            self.session.add_all(batch)
            if flush:
                try:
                    self.session.flush()
                except IntegrityError as exc:
                    self.session.rollback()
                    raise ConflictError(
                        f"Bulk create failed for {self.entity_name}",
                        details={"entity": self.entity_name, "batch_offset": start, "reason": str(exc.orig)},
                    ) from exc
            created.extend(batch)
        return created

    def update(
        self,
        entity_or_id: ModelT | str,
        data: Mapping[str, Any],
        *,
        flush: bool = True,
        org_id: str | None = None,
        allowed_fields: set[str] | None = None,
    ) -> ModelT:
        """Update an existing entity by instance or ID with field validation."""
        entity = (
            self.get_by_id_or_raise(entity_or_id, org_id=org_id)
            if isinstance(entity_or_id, str)
            else entity_or_id
        )
        valid_cols = self._column_names()
        for key, value in data.items():
            if key in IMMUTABLE_FIELDS:
                continue
            if allowed_fields is not None and key not in allowed_fields:
                raise ValidationError(
                    f"Field '{key}' is not updatable on {self.entity_name}",
                    details={"entity": self.entity_name, "field": key},
                )
            if key not in valid_cols:
                raise ValidationError(
                    f"Unknown field '{key}' on {self.entity_name}",
                    details={"entity": self.entity_name, "field": key},
                )
            setattr(entity, key, value)

        if self._has_column("updated_at"):
            setattr(entity, "updated_at", utcnow())

        self.session.add(entity)
        if flush:
            try:
                self.session.flush()
            except IntegrityError as exc:
                self.session.rollback()
                raise ConflictError(
                    f"Could not update {self.entity_name} due to integrity constraint",
                    details={"entity": self.entity_name, "reason": str(exc.orig)},
                ) from exc
        return entity

    def delete(
        self,
        entity_or_id: ModelT | str,
        *,
        flush: bool = True,
        org_id: str | None = None,
    ) -> bool:
        """Permanently delete an entity by instance or ID.

        Returns ``True`` if deleted, or ``False`` if an ID was supplied and no row existed.
        """
        if isinstance(entity_or_id, str):
            entity = self.get_by_id(entity_or_id, org_id=org_id, include_deleted=True)
            if entity is None:
                return False
        else:
            entity = entity_or_id

        self.session.delete(entity)
        if flush:
            self.session.flush()
        return True

    def soft_delete(
        self,
        entity_or_id: ModelT | str,
        *,
        flush: bool = True,
        org_id: str | None = None,
    ) -> ModelT:
        """Mark an entity as soft-deleted without physically removing the row."""
        if not self._is_soft_deletable():
            raise ValidationError(
                f"{self.entity_name} does not support soft deletion",
                details={"entity": self.entity_name},
            )
        entity = (
            self.get_by_id_or_raise(entity_or_id, org_id=org_id)
            if isinstance(entity_or_id, str)
            else entity_or_id
        )
        mark_deleted = getattr(entity, "mark_deleted", None)
        if callable(mark_deleted):
            mark_deleted()
        else:
            setattr(entity, "is_deleted", True)
            if self._has_column("deleted_at"):
                setattr(entity, "deleted_at", utcnow())
        if self._has_column("updated_at"):
            setattr(entity, "updated_at", utcnow())

        self.session.add(entity)
        if flush:
            self.session.flush()
        return entity

    def restore(
        self,
        entity_id: str,
        *,
        flush: bool = True,
        org_id: str | None = None,
    ) -> ModelT:
        """Restore a previously soft-deleted entity."""
        if not self._is_soft_deletable():
            raise ValidationError(
                f"{self.entity_name} does not support soft deletion",
                details={"entity": self.entity_name},
            )
        entity = self.get_by_id_or_raise(entity_id, org_id=org_id, include_deleted=True)
        setattr(entity, "is_deleted", False)
        if self._has_column("deleted_at"):
            setattr(entity, "deleted_at", None)
        if self._has_column("updated_at"):
            setattr(entity, "updated_at", utcnow())
        self.session.add(entity)
        if flush:
            self.session.flush()
        return entity

    def upsert_by(
        self,
        lookup: Mapping[str, Any],
        defaults: Mapping[str, Any] | None = None,
        *,
        flush: bool = True,
        org_id: str | None = None,
    ) -> tuple[ModelT, bool]:
        """Find an entity matching ``lookup`` or create/update it.

        Returns:
            Tuple of ``(entity, created)`` where ``created`` is ``True`` if inserted.
        """
        existing = self.get_one_by(filters=lookup, org_id=org_id)
        if existing is not None:
            if defaults:
                self.update(existing, defaults, flush=flush, org_id=org_id)
            return existing, False
        payload = {**lookup, **(defaults or {})}
        entity = self.create(payload, flush=flush, org_id=org_id)
        return entity, True

    def delete_where(
        self,
        *,
        filters: Mapping[str, Any] | Sequence[FilterSpec],
        org_id: str | None = None,
        flush: bool = True,
    ) -> int:
        """Delete all rows matching ``filters`` in a single SQL DELETE statement."""
        specs = normalize_filters(filters)
        predicates = [self._build_predicate(spec) for spec in specs]
        effective_org = self._effective_org_id(org_id)
        if effective_org is not None and self._is_tenant_scoped():
            predicates.append(self._get_column("org_id") == effective_org)

        stmt = sa_delete(self.model_cls)
        if predicates:
            stmt = stmt.where(and_(*predicates))
        result = self.session.execute(stmt)
        if flush:
            self.session.flush()
        return int(result.rowcount or 0)

    def flush(self) -> None:
        """Flush pending unit-of-work changes to the database."""
        self.session.flush()

    def refresh(self, entity: ModelT) -> ModelT:
        """Reload column state on an attached entity from the database."""
        self.session.refresh(entity)
        return entity


__all__ = [
    "BaseRepository",
    "FilterOperator",
    "FilterSpec",
    "IMMUTABLE_FIELDS",
    "ModelT",
    "PageResult",
    "SortSpec",
    "VALID_OPERATORS",
    "normalize_filters",
    "normalize_ordering",
    "resolve_model",
]
