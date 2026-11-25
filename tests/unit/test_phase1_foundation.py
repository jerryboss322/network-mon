"""Phase 1 unit tests: core utilities, ORM models, repositories, schemas, and seeding."""

from __future__ import annotations

from app.core.cache import SlidingWindowRateLimiter, TokenBucketRateLimiter, TTLCache
from app.core.config import get_settings
from app.core.events import Event, EventBus
from app.core.exceptions import NetPulseError, NotFoundError, ValidationError
from app.core.network_utils import (
    calculate_subnet,
    format_bps,
    format_mac,
    is_valid_ip,
    is_valid_oid,
    lookup_oui_vendor,
)
from app.core.security import (
    CredentialVault,
    Permission,
    Role,
    check_permission,
    create_access_token,
    decode_token,
    generate_api_key,
    has_permission,
    hash_password,
    verify_api_key,
    verify_password,
)
from app.db.repositories import (
    AlertEventRepository,
    AlertRuleRepository,
    ComplianceRepository,
    ConfigSnapshotRepository,
    DeviceRepository,
    IncidentRepository,
    InterfaceRepository,
    NetFlowRepository,
    OrganizationRepository,
    PlaybookRepository,
    SiteRepository,
    SloRepository,
    SyslogRepository,
    TopologyRepository,
    UserRepository,
)
from app.db.seed import DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, seed_enterprise_demo
from app.models.enums import DeviceStatus
from app.schemas.inventory import DeviceCreate, SiteCreate


def test_settings_and_exceptions() -> None:
    cfg = get_settings()
    assert cfg.version == "2.0.0"
    assert cfg.api_v1_prefix == "/api/v1"

    err = NotFoundError("Device missing", details={"id": "dev-1"})
    assert err.status_code == 404
    payload = err.to_dict()
    assert payload["error"]["code"] == "NOT_FOUND"
    assert isinstance(err, NetPulseError)

    val_err = ValidationError("Invalid CIDR")
    assert val_err.status_code == 422


def test_security_password_jwt_apikey_vault_rbac() -> None:
    pw_hash = hash_password("StrongPass!2026")
    assert verify_password("StrongPass!2026", pw_hash)
    assert not verify_password("WrongPass!2026", pw_hash)

    token = create_access_token("user-1", org_id="org-1", role=Role.ORG_ADMIN)
    claims = decode_token(token)
    assert claims.sub == "user-1"
    assert claims.org_id == "org-1"

    generated = generate_api_key()
    assert generated.raw_key.startswith("npm_")
    assert generated.prefix
    assert verify_api_key(generated.raw_key, generated.key_hash)
    assert not verify_api_key("npm_fake_invalid", generated.key_hash)

    vault = CredentialVault()
    secret_payload = {"community": "private_ro", "auth_pass": "supersecret"}
    token_enc = vault.encrypt_json(secret_payload)
    assert "supersecret" not in token_enc
    assert vault.decrypt_json(token_enc) == secret_payload

    assert has_permission(Role.SUPER_ADMIN, Permission.DEVICES_CREATE)
    assert has_permission(Role.VIEWER, Permission.DEVICES_READ)
    assert not has_permission(Role.VIEWER, Permission.DEVICES_DELETE)
    check_permission(Role.SUPER_ADMIN, Permission.DEVICES_CREATE)


def test_event_bus_pubsub_and_wildcards() -> None:
    bus = EventBus()
    received: list[str] = []

    bus.subscribe("device.*", lambda ev: received.append(f"wild:{ev.topic}"))
    bus.subscribe("device.created", lambda ev: received.append(f"exact:{ev.payload['hostname']}"))

    bus.publish_sync(Event(topic="device.created", payload={"hostname": "core-rtr-01"}))
    assert "wild:device.created" in received
    assert "exact:core-rtr-01" in received


def test_cache_and_rate_limiters() -> None:
    cache: TTLCache[str] = TTLCache(max_size=4, default_ttl=60.0)
    cache.set("k1", "v1", tags={"devices"})
    cache.set("k2", "v2", tags={"devices"})
    assert cache.get("k1") == "v1"
    removed = cache.invalidate_tag("devices")
    assert removed == 2
    assert cache.get("k1") is None

    tb = TokenBucketRateLimiter(refill_rate=10.0, capacity=2)
    assert tb.allow("client-a").allowed
    assert tb.allow("client-a").allowed
    assert not tb.allow("client-a").allowed

    sw = SlidingWindowRateLimiter(max_requests=2, window_seconds=60.0)
    assert sw.allow("ip-1").allowed
    assert sw.allow("ip-1").allowed
    assert not sw.allow("ip-1").allowed


def test_network_utils() -> None:
    assert is_valid_ip("10.10.0.1")
    assert is_valid_ip("2001:db8::1")
    assert not is_valid_ip("999.999.1.1")

    sub = calculate_subnet("10.10.0.0/24")
    assert sub.network_address == "10.10.0.0"
    assert sub.broadcast_address == "10.10.0.255"
    assert sub.usable_hosts == 254

    mac = format_mac("001B.21AA.BBCC")
    assert mac == "00:1b:21:aa:bb:cc"
    assert lookup_oui_vendor("00:1b:21:aa:bb:cc") is not None

    assert is_valid_oid("1.3.6.1.2.1.1.1.0")
    assert not is_valid_oid("invalid.oid")
    assert "Gbps" in format_bps(10_000_000_000)


def test_pydantic_schemas() -> None:
    site = SiteCreate(name="US-East DC1", slug="us-east-dc1", region="us-east", country="US", city="Ashburn")
    assert site.slug == "us-east-dc1"

    dev = DeviceCreate(
        name="Core Router 99",
        hostname="core-rtr-99",
        management_ip="10.99.0.1",
        device_type="router",
        vendor="cisco",
    )
    assert dev.hostname == "core-rtr-99"


def test_seeded_enterprise_database_and_repositories(seeded_db) -> None:
    db, summary = seeded_db
    assert summary["seeded"] is True
    org_id = summary["org_id"]

    # Idempotency check
    again = seed_enterprise_demo(db, commit=True)
    assert again["seeded"] is False

    org_repo = OrganizationRepository(db)
    user_repo = UserRepository(db)
    site_repo = SiteRepository(db)
    dev_repo = DeviceRepository(db)
    if_repo = InterfaceRepository(db)
    topo_repo = TopologyRepository(db)
    rule_repo = AlertRuleRepository(db)
    alert_repo = AlertEventRepository(db)
    inc_repo = IncidentRepository(db)
    slo_repo = SloRepository(db)
    syslog_repo = SyslogRepository(db)
    netflow_repo = NetFlowRepository(db)
    cfg_repo = ConfigSnapshotRepository(db)
    comp_repo = ComplianceRepository(db)
    pb_repo = PlaybookRepository(db)

    org = org_repo.get_by_id(org_id)
    assert org is not None
    admin = user_repo.get_by_email(DEFAULT_ADMIN_EMAIL)
    assert admin is not None
    assert verify_password(DEFAULT_ADMIN_PASSWORD, admin.password_hash)

    assert site_repo.count(org_id=org_id) == 3
    assert dev_repo.count(org_id=org_id) >= 18
    assert if_repo.count(org_id=org_id) >= 40
    assert topo_repo.count(org_id=org_id) >= 18
    assert len(topo_repo.list_links(org_id=org_id)) >= 15
    assert rule_repo.count(org_id=org_id) >= 5
    assert alert_repo.count(org_id=org_id) >= 4
    assert inc_repo.count(org_id=org_id) >= 2
    assert slo_repo.count(org_id=org_id) >= 3
    assert syslog_repo.count(org_id=org_id) >= 20
    assert netflow_repo.count(org_id=org_id) >= 30
    assert cfg_repo.count(org_id=org_id) >= 5
    assert comp_repo.count(org_id=org_id) >= 3
    assert pb_repo.count(org_id=org_id) >= 3
    assert DeviceStatus.UP == "up"
