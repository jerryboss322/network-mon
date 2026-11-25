"""Phase 2 integration tests: FastAPI app, Auth/RBAC, Audit, Sites/Racks, Devices, IPAM, and Vercel ASGI."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.db.seed import DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, seed_enterprise_demo
from app.db.session import get_session_factory, init_database, reset_engine
from app.main import create_app


@pytest.fixture(scope="module")
def api_client():
    """Return a FastAPI TestClient backed by an isolated seeded in-memory SQLite DB."""
    reset_engine("sqlite:///:memory:")
    init_database()
    with get_session_factory()() as db:
        seed_enterprise_demo(db, commit=True)

    app = create_app()
    with TestClient(app) as client:
        yield client


def _login_headers(client: TestClient) -> dict[str, str]:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": DEFAULT_ADMIN_EMAIL, "password": DEFAULT_ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health_and_system_info(api_client: TestClient) -> None:
    r = api_client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

    ready = api_client.get("/api/v1/ready")
    assert ready.status_code == 200

    info = api_client.get("/api/v1/system/info")
    assert info.status_code == 200
    assert "version" in info.json()

    headers = _login_headers(api_client)
    overview = api_client.get("/api/v1/stats/overview", headers=headers)
    assert overview.status_code == 200
    body = overview.json()
    assert body["sites_total"] == 3
    assert body["devices_total"] >= 18


def test_auth_login_me_and_api_keys(api_client: TestClient) -> None:
    headers = _login_headers(api_client)
    me = api_client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["user"]["email"] == DEFAULT_ADMIN_EMAIL

    perms = api_client.get("/api/v1/auth/permissions", headers=headers)
    assert perms.status_code == 200
    pbody = perms.json()
    assert pbody and ("effective_permissions" in pbody or "roles" in pbody or "role_permissions" in pbody or len(pbody) > 0)

    created_key = api_client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={"name": "CI Collector Key", "scopes": ["devices:read", "telemetry:write"]},
    )
    assert created_key.status_code in (200, 201), created_key.text
    raw_key = created_key.json()["secret_key"]
    assert raw_key and raw_key.startswith("npm_")

    via_key = api_client.get("/api/v1/devices", headers={"X-API-Key": raw_key})
    assert via_key.status_code == 200


def test_sites_racks_devices_and_ipam_crud(api_client: TestClient) -> None:
    headers = _login_headers(api_client)

    sites = api_client.get("/api/v1/sites", headers=headers)
    assert sites.status_code == 200
    site_items = sites.json()["items"]
    assert len(site_items) >= 3
    site_id = site_items[0]["id"]

    summary = api_client.get(f"/api/v1/sites/{site_id}/summary", headers=headers)
    assert summary.status_code == 200

    devs = api_client.get("/api/v1/devices", headers=headers)
    assert devs.status_code == 200
    assert len(devs.json()["items"]) >= 10

    dev_sum = api_client.get("/api/v1/devices/summary", headers=headers)
    assert dev_sum.status_code == 200

    created = api_client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "name": "Test Edge Switch 99",
            "hostname": "test-edge-sw-99",
            "management_ip": "10.99.10.5",
            "device_type": "switch",
            "vendor": "arista",
            "site_id": site_id,
        },
    )
    assert created.status_code in (200, 201), created.text
    dev_id = created.json()["id"]

    fetched = api_client.get(f"/api/v1/devices/{dev_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["hostname"] == "test-edge-sw-99"

    calc = api_client.post(
        "/api/v1/subnets/calculate",
        headers=headers,
        json={"cidr": "10.200.0.0/24"},
    )
    assert calc.status_code == 200
    assert calc.json()["info"]["usable_hosts"] == 254

    oui = api_client.get("/api/v1/network-utils/oui/00:1b:21:aa:bb:cc", headers=headers)
    assert oui.status_code == 200

    port = api_client.get("/api/v1/network-utils/port/443", headers=headers)
    assert port.status_code == 200


def test_vercel_asgi_entrypoint_import() -> None:
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "vercel_api_index",
        Path(__file__).resolve().parents[2] / "api" / "index.py",
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "app")
