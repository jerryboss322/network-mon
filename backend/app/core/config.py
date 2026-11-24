"""Centralized environment-aware application configuration.

Supports both full local/self-hosted execution (persistent SQLite/PostgreSQL,
live collectors, WebSockets) and Vercel serverless execution (`VERCEL=1`,
using `/tmp` ephemeral SQLite or external `DATABASE_URL` plus live-seeded
telemetry fallback).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class SecuritySettings:
    secret_key: str = field(
        default_factory=lambda: os.getenv(
            "NETMON_SECRET_KEY", "dev-netpulse-change-in-production-9f8e7d6c5b4a"
        )
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = field(
        default_factory=lambda: _env_int("NETMON_ACCESS_TOKEN_MINUTES", 60)
    )
    refresh_token_expire_days: int = field(
        default_factory=lambda: _env_int("NETMON_REFRESH_TOKEN_DAYS", 14)
    )
    encryption_key: str = field(
        default_factory=lambda: os.getenv(
            "NETMON_VAULT_KEY", "netpulse-vault-default-dev-key-32b"
        )
    )
    password_min_length: int = 8
    api_key_prefix: str = "npm_"
    max_login_attempts: int = 5
    lockout_minutes: int = 15
    cors_origins: list[str] = field(
        default_factory=lambda: _env_list(
            "NETMON_CORS_ORIGINS",
            [
                "http://localhost:5173",
                "http://localhost:3000",
                "http://127.0.0.1:5173",
                "*",
            ],
        )
    )


@dataclass(frozen=True)
class CollectorSettings:
    enabled: bool = field(
        default_factory=lambda: _env_bool("NETMON_COLLECTORS_ENABLED", not _env_bool("VERCEL", False))
    )
    icmp_interval_seconds: int = field(default_factory=lambda: _env_int("NETMON_ICMP_INTERVAL", 30))
    snmp_interval_seconds: int = field(default_factory=lambda: _env_int("NETMON_SNMP_INTERVAL", 60))
    synthetic_interval_seconds: int = field(default_factory=lambda: _env_int("NETMON_SYNTHETIC_INTERVAL", 45))
    host_interval_seconds: int = field(default_factory=lambda: _env_int("NETMON_HOST_INTERVAL", 15))
    max_concurrent_probes: int = field(default_factory=lambda: _env_int("NETMON_MAX_CONCURRENT_PROBES", 64))
    default_timeout_seconds: float = field(default_factory=lambda: _env_float("NETMON_PROBE_TIMEOUT", 3.0))
    syslog_udp_port: int = field(default_factory=lambda: _env_int("NETMON_SYSLOG_PORT", 5514))
    netflow_udp_port: int = field(default_factory=lambda: _env_int("NETMON_NETFLOW_PORT", 2055))
    simulate_demo_telemetry: bool = field(
        default_factory=lambda: _env_bool("NETMON_SIMULATE_DEMO", _env_bool("VERCEL", False))
    )


@dataclass(frozen=True)
class RetentionSettings:
    raw_metrics_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_RAW_DAYS", 7))
    rollup_1m_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_1M_DAYS", 30))
    rollup_5m_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_5M_DAYS", 90))
    rollup_1h_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_1H_DAYS", 365))
    syslog_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_SYSLOG_DAYS", 30))
    netflow_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_NETFLOW_DAYS", 14))
    audit_log_days: int = field(default_factory=lambda: _env_int("NETMON_RETENTION_AUDIT_DAYS", 365))


@dataclass(frozen=True)
class Settings:
    app_name: str = "NetPulse Observability Platform"
    version: str = "2.0.0"
    environment: Literal["development", "staging", "production", "test"] = field(
        default_factory=lambda: os.getenv("NETMON_ENV", "development")  # type: ignore[arg-type]
    )
    debug: bool = field(default_factory=lambda: _env_bool("NETMON_DEBUG", False))
    is_vercel: bool = field(default_factory=lambda: _env_bool("VERCEL", False))
    api_v1_prefix: str = "/api/v1"
    log_level: str = field(default_factory=lambda: os.getenv("NETMON_LOG_LEVEL", "INFO").upper())
    database_url: str = field(default_factory=lambda: _default_database_url())
    db_echo: bool = field(default_factory=lambda: _env_bool("NETMON_DB_ECHO", False))
    db_pool_size: int = field(default_factory=lambda: _env_int("NETMON_DB_POOL_SIZE", 10))
    db_max_overflow: int = field(default_factory=lambda: _env_int("NETMON_DB_MAX_OVERFLOW", 20))
    security: SecuritySettings = field(default_factory=SecuritySettings)
    collectors: CollectorSettings = field(default_factory=CollectorSettings)
    retention: RetentionSettings = field(default_factory=RetentionSettings)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parents[3]


def _default_database_url() -> str:
    explicit = os.getenv("DATABASE_URL") or os.getenv("NETMON_DATABASE_URL")
    if explicit:
        return explicit
    if _env_bool("VERCEL", False):
        return "sqlite:////tmp/netpulse_vercel.db"
    return "sqlite:///./netpulse.db"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton application settings."""
    return Settings()
