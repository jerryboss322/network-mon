"""Idempotent enterprise demo dataset seeder for NetPulse Observability Platform.

Populates a complete, realistic multi-site global enterprise network
(**NetPulse Global Corp**) spanning 3 geographic data centers/POPs:

- **US-East Ashburn DC1** (Tier-4 primary core data center)
- **EU-Central Frankfurt DC2** (Tier-4 European regional hub)
- **AP-South Singapore Edge** (Tier-3 APAC edge POP)

Seeded domains include:
- Multi-tenant organization, RBAC users (including default ``admin@netpulse.io`` /
  ``NetPulseAdmin123!``), scoped demo API key, webhooks, and audit logs
- Sites, physical racks, encrypted credential vault profiles, 21 devices (18 enterprise
  routers/switches/firewalls/load-balancers/servers + 3 legacy external DNS targets),
  network interfaces, IPAM subnets/VLANs/allocations, and device groups
- L2/L3 topology nodes, WAN/campus links, root-cause dependency edges, and discovery results
- 24 hours of realistic diurnal SNMP, ICMP, Host OS, Synthetic probe, and rollup telemetry,
  plus syslog events, NetFlow traffic flows, BGP peer sessions, and edge collector agents
- Alert rules, firing/acknowledged/resolved alert events, active & resolved incidents with
  timelines, escalation policies, on-call schedules, notification channels/deliveries,
  maintenance windows, and SLO definitions
- Realistic Cisco IOS-XR, Juniper JunOS, Arista EOS, Palo Alto PAN-OS, and Linux configuration
  snapshots with a live unified diff, CIS compliance policies & evaluations, remediation
  playbooks & run logs, scheduled/generated reports, and registered plugins
"""

from __future__ import annotations

import hashlib
import math
import random
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_credential_vault, hash_api_key, hash_password
from app.db.base import new_uuid, utcnow

DEFAULT_ORG_SLUG = "netpulse-global"
DEFAULT_ADMIN_EMAIL = "admin@netpulse.io"
DEFAULT_ADMIN_PASSWORD = "NetPulseAdmin123!"
DEFAULT_DEMO_API_KEY = "npm_demo2026_netpulseGlobalEnterpriseApiKey9f8e7d6c5b4a3210"
DEFAULT_DEMO_API_KEY_PREFIX = DEFAULT_DEMO_API_KEY[:12]


# ── Realistic Device Configuration Templates ─────────────────────────────────

CISCO_IOSXR_BASE_CONFIG = """!! IOS XR Configuration 7.9.2
hostname iad-core-rtr-01
domain name netpulse.corp
domain name-server 10.10.0.53
ntp
 server 169.254.169.123 prefer
 server 10.10.0.123
 update-calendar
!
aaa authentication login default local
aaa authorization exec default local
ssh server v2
ssh server logging
logging 10.10.0.200 vrf MGMT severity info
logging trap notifications
snmp-server view NETPULSE-RO iso included
snmp-server group NETPULSE-V3 v3 priv read NETPULSE-RO
snmp-server user netpulse-poller NETPULSE-V3 v3 auth sha encrypted 094F471A priv aes 128 encrypted 05080F1C
!
interface Loopback0
 ipv4 address 10.10.0.1 255.255.255.255
!
interface HundredGigE0/0/0/0
 description TRANSATLANTIC-WAN-TO-FRA-CORE-RTR-01
 mtu 9216
 ipv4 address 172.16.10.1 255.255.255.252
 lldp
!
interface HundredGigE0/0/0/1
 description CORE-PEER-TO-IAD-CORE-RTR-02
 mtu 9216
 ipv4 address 172.16.10.5 255.255.255.252
!
router bgp 65001
 bgp router-id 10.10.0.1
 bgp log neighbor changes detail
 address-family ipv4 unicast
  network 10.10.0.0/20
 !
 neighbor 198.51.100.1
  remote-as 3356
  description LUMEN-TRANSIT-PRIMARY
  address-family ipv4 unicast
   maximum-prefix 950000 85
 !
 neighbor 172.16.10.2
  remote-as 65002
  description EU-CENTRAL-FRA-CORE-RTR-01
  address-family ipv4 unicast
 !
end
"""

CISCO_IOSXR_UPDATED_CONFIG = CISCO_IOSXR_BASE_CONFIG.replace(
    "   maximum-prefix 950000 85",
    "   maximum-prefix 1050000 80\n   soft-reconfiguration inbound always",
).replace(
    "logging trap notifications",
    "logging trap informational\nflow exporter-map NETPULSE-IPFIX\n destination 10.10.0.205\n transport udp 2055",
)

CISCO_UNIFIED_DIFF = """--- a/iad-core-rtr-01-running-v1.cfg
+++ b/iad-core-rtr-01-running-v2.cfg
@@ -13,7 +13,10 @@
 ssh server v2
 ssh server logging
 logging 10.10.0.200 vrf MGMT severity info
-logging trap notifications
+logging trap informational
+flow exporter-map NETPULSE-IPFIX
+ destination 10.10.0.205
+ transport udp 2055
 snmp-server view NETPULSE-RO iso included
@@ -37,7 +40,8 @@
  neighbor 198.51.100.1
   remote-as 3356
   description LUMEN-TRANSIT-PRIMARY
   address-family ipv4 unicast
-   maximum-prefix 950000 85
+   maximum-prefix 1050000 80
+   soft-reconfiguration inbound always
"""

JUNIPER_JUNOS_CONFIG = """## Last commit: 2026-11-22 04:15:09 UTC by netops
version 23.4R2-S1;
system {
    host-name fra-core-rtr-01;
    domain-name netpulse.corp;
    time-zone UTC;
    services {
        ssh {
            protocol-version v2;
            root-login deny;
        }
        netconf {
            ssh;
        }
    }
    syslog {
        host 10.20.0.200 {
            any info;
            authorization info;
        }
    }
    ntp {
        server 10.20.0.123 prefer;
    }
}
interfaces {
    et-0/0/0 {
        description "TRANSATLANTIC-WAN-TO-IAD-CORE-RTR-01";
        mtu 9216;
        unit 0 {
            family inet {
                address 172.16.10.2/30;
            }
        }
    }
    et-0/0/1 {
        description "APAC-WAN-TO-SIN-EDGE-RTR-01";
        mtu 9216;
        unit 0 {
            family inet {
                address 172.16.20.1/30;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                address 10.20.0.1/32;
            }
        }
    }
}
routing-options {
    autonomous-system 65002;
    router-id 10.20.0.1;
}
protocols {
    bgp {
        log-updown;
        group DE-CIX-PEERING {
            type external;
            neighbor 80.81.192.15 {
                description "DE-CIX Frankfurt Route Server";
                peer-as 6695;
            }
        }
    }
    lldp {
        interface all;
    }
}
"""

ARISTA_EOS_CONFIG = """! Arista EOS 4.31.2F
hostname iad-dist-sw-01
ip domain-name netpulse.corp
ntp server 10.10.0.123 prefer
logging host 10.10.0.200
logging trap informational
!
vlan 10
   name CORE-TRANSIT
vlan 100
   name PROD-APP-TIER
vlan 200
   name PROD-DB-TIER
vlan 400
   name OOB-MANAGEMENT
!
interface Ethernet1
   description UPLINK-IAD-CORE-RTR-01
   mtu 9214
   no switchport
   ip address 172.16.10.9/30
!
interface Ethernet2
   description DOWNLINK-IAD-LB-01
   switchport mode trunk
   switchport trunk allowed vlan 100,200
!
management ssh
   idle-timeout 15
   authentication mode keyboard-interactive
!
end
"""

PALO_ALTO_CONFIG = """set deviceconfig system hostname iad-edge-fw-01
set deviceconfig system domain netpulse.corp
set deviceconfig system ip-address 10.10.2.1
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.10.0.123
set deviceconfig setting management enable-log-high-dp-load yes
set shared log-settings syslog NETPULSE-SYSLOG server iad-collector server 10.10.0.200 port 5514
set rulebase security rules ALLOW-HTTPS-INGRESS from untrust to dmz application ssl service application-default action allow log-end yes
set rulebase security rules BLOCK-MALICIOUS-EGRESS from trust to untrust destination edl-threat-feed action deny log-end yes
"""

LINUX_DB_CONFIG = """# /etc/sysctl.d/99-netpulse-db.conf (iad-db-01.netpulse.corp)
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.ip_forward = 0
net.core.somaxconn = 4096
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
vm.swappiness = 10
vm.dirty_ratio = 15
# sshd_config hardened: PermitRootLogin no, PasswordAuthentication no, Protocol 2
"""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _diurnal_factor(hour_utc: float, phase_shift: float = 0.0) -> float:
    """Return a smooth 0.65..1.35 diurnal traffic curve peaking during work hours."""
    return 1.0 + 0.32 * math.sin(((hour_utc + phase_shift - 8.0) / 24.0) * 2.0 * math.pi)


def seed_enterprise_demo(
    session: Session,
    *,
    commit: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Idempotently populate the NetPulse Global Corp enterprise demo dataset.

    Args:
        session: Active SQLAlchemy 2.0 session.
        commit: Whether to call ``session.commit()`` after seeding completes.
        force: If ``False`` (default), returns immediately when the default
            ``netpulse-global`` organization already exists.

    Returns:
        Summary dictionary describing seeded entity counts and demo credentials.
    """
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
    from app.models.identity import (
        ApiKey,
        AuditLog,
        Organization,
        OrgWebhookEndpoint,
        User,
    )
    from app.models.inventory import (
        CredentialProfile,
        Device,
        DeviceGroup,
        DeviceGroupMember,
        DeviceInterface,
        IpAllocation,
        Rack,
        Site,
        Subnet,
        Vlan,
    )
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
    from app.models.topology import (
        DependencyEdge,
        DiscoveryFinding,
        DiscoveryJob,
        TopologyLink,
        TopologyNode,
    )

    existing_org = session.execute(
        select(Organization).where(Organization.slug == DEFAULT_ORG_SLUG)
    ).scalar_one_or_none()

    if existing_org is not None and not force:
        return {
            "seeded": False,
            "reason": "already_exists",
            "org_id": existing_org.id,
            "org_slug": existing_org.slug,
            "admin_email": DEFAULT_ADMIN_EMAIL,
        }

    rng = random.Random(20261124)
    now = utcnow()
    vault = get_credential_vault()

    # ── 1. Organization, Users, API Key, Webhooks ────────────────────────────
    org = Organization(
        id=new_uuid(),
        name="NetPulse Global Corp",
        slug=DEFAULT_ORG_SLUG,
        plan_tier="enterprise",
        max_devices=5000,
        max_users=250,
        retention_days=365,
        is_active=True,
        settings_json={
            "timezone": "UTC",
            "default_polling_interval_s": 30,
            "enable_anomaly_detection": True,
            "enable_auto_remediation": True,
            "compliance_frameworks": ["cis_benchmark", "nist_800_53", "soc2"],
        },
    )
    session.add(org)
    session.flush()
    org_id = org.id

    admin_user = User(
        id=new_uuid(),
        org_id=org_id,
        email=DEFAULT_ADMIN_EMAIL,
        username="admin",
        full_name="Elena Vance",
        password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
        role="super_admin",
        is_active=True,
        is_verified=True,
        mfa_enabled=False,
        last_login_at=now - timedelta(minutes=18),
        last_login_ip="10.10.40.15",
        preferences_json={"theme": "dark", "default_time_range": "24h", "refresh_seconds": 30},
    )
    netops_user = User(
        id=new_uuid(),
        org_id=org_id,
        email="netops@netpulse.io",
        username="mchen",
        full_name="Marcus Chen",
        password_hash=hash_password("NetOpsSecure123!"),
        role="netops",
        is_active=True,
        is_verified=True,
        last_login_at=now - timedelta(hours=2),
        last_login_ip="10.10.40.22",
    )
    sre_user = User(
        id=new_uuid(),
        org_id=org_id,
        email="sre@netpulse.io",
        username="psharma",
        full_name="Priya Sharma",
        password_hash=hash_password("SreOnCall123!"),
        role="operator",
        is_active=True,
        is_verified=True,
        last_login_at=now - timedelta(hours=5),
        last_login_ip="10.20.40.18",
    )
    viewer_user = User(
        id=new_uuid(),
        org_id=org_id,
        email="viewer@netpulse.io",
        username="dokafor",
        full_name="David Okafor",
        password_hash=hash_password("ReadOnlyDemo123!"),
        role="viewer",
        is_active=True,
        is_verified=True,
    )
    session.add_all([admin_user, netops_user, sre_user, viewer_user])
    session.flush()

    demo_api_key = ApiKey(
        id=new_uuid(),
        org_id=org_id,
        created_by_user_id=admin_user.id,
        name="NetPulse Demo Automation Key",
        key_prefix=DEFAULT_DEMO_API_KEY_PREFIX,
        key_hash=hash_api_key(DEFAULT_DEMO_API_KEY),
        scopes_json=[
            "devices:read",
            "devices:write",
            "telemetry:read",
            "telemetry:write",
            "alerts:read",
            "alerts:write",
            "topology:read",
            "playbooks:execute",
        ],
        allowed_cidrs_json=["0.0.0.0/0"],
        expires_at=now + timedelta(days=365),
        last_used_at=now - timedelta(minutes=4),
        is_active=True,
    )
    session.add(demo_api_key)

    webhooks = [
        OrgWebhookEndpoint(
            id=new_uuid(),
            org_id=org_id,
            name="NOC Slack Event Bridge",
            url="https://hooks.slack.example.netpulse.io/services/T0001/B0002/demo",
            secret_encrypted=vault.encrypt_json({"hmac_secret": "whsec_slack_demo_99182736"}),
            event_patterns_json=["alert.*", "incident.*", "bgp.flap"],
            is_active=True,
            failure_count=0,
            last_triggered_at=now - timedelta(minutes=12),
        ),
        OrgWebhookEndpoint(
            id=new_uuid(),
            org_id=org_id,
            name="ServiceNow CMDB Change Hook",
            url="https://cmdb.example.netpulse.io/api/v2/netpulse/events",
            secret_encrypted=vault.encrypt_json({"hmac_secret": "whsec_snow_demo_11223344"}),
            event_patterns_json=["config.drift", "compliance.violation", "device.discovered"],
            is_active=True,
            failure_count=0,
            last_triggered_at=now - timedelta(hours=3),
        ),
    ]
    session.add_all(webhooks)

    # ── 2. Sites, Racks, Credentials, Groups ─────────────────────────────────
    site_us = Site(
        id=new_uuid(),
        org_id=org_id,
        name="US-East Ashburn DC1",
        code="US-EAST-DC1",
        region="North America",
        country="United States",
        city="Ashburn, VA",
        address="21715 Filigree Ct, Ashburn, VA 20147",
        timezone="America/New_York",
        latitude=39.0438,
        longitude=-77.4874,
        contact_name="Marcus Chen",
        contact_email="netops@netpulse.io",
        tier="tier4",
        metadata_json={"asn": 65001, "provider": "Equinix DC11", "uplink_capacity_gbps": 400},
    )
    site_eu = Site(
        id=new_uuid(),
        org_id=org_id,
        name="EU-Central Frankfurt DC2",
        code="EU-CENTRAL-DC2",
        region="Europe",
        country="Germany",
        city="Frankfurt",
        address="Hanauer Landstrasse 302, 60314 Frankfurt am Main",
        timezone="Europe/Berlin",
        latitude=50.1109,
        longitude=8.6821,
        contact_name="Priya Sharma",
        contact_email="sre@netpulse.io",
        tier="tier4",
        metadata_json={"asn": 65002, "provider": "Equinix FR5", "uplink_capacity_gbps": 200},
    )
    site_ap = Site(
        id=new_uuid(),
        org_id=org_id,
        name="AP-South Singapore Edge",
        code="AP-SOUTH-SG1",
        region="Asia-Pacific",
        country="Singapore",
        city="Singapore",
        address="20 Ayer Rajah Crescent, Singapore 139964",
        timezone="Asia/Singapore",
        latitude=1.3521,
        longitude=103.8198,
        contact_name="Elena Vance",
        contact_email=DEFAULT_ADMIN_EMAIL,
        tier="tier3",
        metadata_json={"asn": 65003, "provider": "Equinix SG3", "uplink_capacity_gbps": 100},
    )
    session.add_all([site_us, site_eu, site_ap])
    session.flush()

    racks_spec = [
        ("US1-A01", site_us.id, "Aisle-A", "Row-01", 42, 18000, "Cold-Aisle-North"),
        ("US1-A02", site_us.id, "Aisle-A", "Row-02", 42, 22000, "Cold-Aisle-North"),
        ("EU2-B01", site_eu.id, "Aisle-B", "Row-01", 42, 16000, "Cold-Aisle-West"),
        ("EU2-B02", site_eu.id, "Aisle-B", "Row-02", 42, 20000, "Cold-Aisle-West"),
        ("SG1-C01", site_ap.id, "Aisle-C", "Row-01", 42, 14000, "Edge-Cage-01"),
        ("SG1-C02", site_ap.id, "Aisle-C", "Row-02", 42, 14000, "Edge-Cage-01"),
    ]
    racks: dict[str, Rack] = {}
    for rname, sid, aisle, row, total_u, watts, zone in racks_spec:
        rack = Rack(
            id=new_uuid(),
            org_id=org_id,
            site_id=sid,
            name=rname,
            aisle=aisle,
            row=row,
            total_u=total_u,
            power_capacity_watts=watts,
            cooling_zone=zone,
        )
        racks[rname] = rack
        session.add(rack)

    cred_snmpv3 = CredentialProfile(
        id=new_uuid(),
        org_id=org_id,
        name="Global Core SNMPv3 AuthPriv",
        description="SHA-256 + AES-128 SNMPv3 read-only credentials for core routers and switches",
        credential_type="snmp_v3",
        snmp_version="v3",
        encrypted_payload=vault.encrypt_json(
            {
                "username": "netpulse-poller",
                "auth_protocol": "sha256",
                "auth_passphrase": "DemoAuthPass#2026!",
                "priv_protocol": "aes128",
                "priv_passphrase": "DemoPrivPass#2026!",
            }
        ),
        port=161,
        timeout_seconds=3.0,
        retries=2,
        is_default=True,
    )
    cred_ssh = CredentialProfile(
        id=new_uuid(),
        org_id=org_id,
        name="NetOps Automation SSH Key",
        description="Ed25519 SSH key for NCM config backups and remediation playbooks",
        credential_type="ssh_key",
        encrypted_payload=vault.encrypt_json(
            {"username": "netpulse-ncm", "private_key_id": "ed25519-netops-2026"}
        ),
        port=22,
        timeout_seconds=8.0,
        retries=2,
        is_default=False,
    )
    cred_api = CredentialProfile(
        id=new_uuid(),
        org_id=org_id,
        name="Firewall & Load Balancer REST API",
        description="API token for Palo Alto PAN-OS, FortiOS, and F5 iControl REST",
        credential_type="api_token",
        encrypted_payload=vault.encrypt_json({"token": "demo-panos-f5-token-2026"}),
        port=443,
        timeout_seconds=5.0,
        retries=2,
        is_default=False,
    )
    session.add_all([cred_snmpv3, cred_ssh, cred_api])
    session.flush()

    # ── 3. Devices (18 Enterprise + 3 Legacy External DNS Targets) ───────────
    device_specs: list[dict[str, Any]] = [
        # US-East Ashburn DC1 (8)
        {
            "hostname": "iad-core-rtr-01",
            "fqdn": "iad-core-rtr-01.us-east.netpulse.corp",
            "management_ip": "10.10.0.1",
            "mac_address": "00:1B:21:AA:10:01",
            "site_id": site_us.id,
            "rack_id": racks["US1-A01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "router",
            "vendor": "cisco",
            "model": "ASR 9904",
            "os_version": "IOS XR 7.9.2",
            "serial_number": "FOX2410P01A",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier0", "core", "bgp", "us-east", "wan"],
            "sys_descr": "Cisco IOS XR Software (ASR9K), Version 7.9.2",
            "sys_object_id": "1.3.6.1.4.1.9.1.1639",
            "uptime_seconds": 14_820_400,
            "layer": "core",
            "x": 220.0,
            "y": 140.0,
            "base_rtt": 1.4,
            "base_cpu": 34.0,
            "base_mem": 48.0,
        },
        {
            "hostname": "iad-core-rtr-02",
            "fqdn": "iad-core-rtr-02.us-east.netpulse.corp",
            "management_ip": "10.10.0.2",
            "mac_address": "00:1B:21:AA:10:02",
            "site_id": site_us.id,
            "rack_id": racks["US1-A01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "router",
            "vendor": "cisco",
            "model": "ASR 9904",
            "os_version": "IOS XR 7.9.2",
            "serial_number": "FOX2410P02B",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier0", "core", "bgp", "us-east", "wan"],
            "sys_descr": "Cisco IOS XR Software (ASR9K), Version 7.9.2",
            "sys_object_id": "1.3.6.1.4.1.9.1.1639",
            "uptime_seconds": 14_819_100,
            "layer": "core",
            "x": 380.0,
            "y": 140.0,
            "base_rtt": 1.6,
            "base_cpu": 31.0,
            "base_mem": 45.0,
        },
        {
            "hostname": "iad-dist-sw-01",
            "fqdn": "iad-dist-sw-01.us-east.netpulse.corp",
            "management_ip": "10.10.1.1",
            "mac_address": "28:99:3A:10:01:01",
            "site_id": site_us.id,
            "rack_id": racks["US1-A01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "distribution_switch",
            "vendor": "arista",
            "model": "DCS-7280SR3-48YC8",
            "os_version": "EOS 4.31.2F",
            "serial_number": "JPE23180112",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "distribution", "spine", "us-east"],
            "sys_descr": "Arista Networks EOS version 4.31.2F running on DCS-7280SR3",
            "sys_object_id": "1.3.6.1.4.1.30065.1.3011.7280",
            "uptime_seconds": 11_240_900,
            "layer": "distribution",
            "x": 180.0,
            "y": 300.0,
            "base_rtt": 0.9,
            "base_cpu": 26.0,
            "base_mem": 42.0,
        },
        {
            "hostname": "iad-dist-sw-02",
            "fqdn": "iad-dist-sw-02.us-east.netpulse.corp",
            "management_ip": "10.10.1.2",
            "mac_address": "28:99:3A:10:01:02",
            "site_id": site_us.id,
            "rack_id": racks["US1-A01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "distribution_switch",
            "vendor": "arista",
            "model": "DCS-7280SR3-48YC8",
            "os_version": "EOS 4.31.2F",
            "serial_number": "JPE23180113",
            "status": "warning",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "distribution", "spine", "us-east"],
            "sys_descr": "Arista Networks EOS version 4.31.2F running on DCS-7280SR3",
            "sys_object_id": "1.3.6.1.4.1.30065.1.3011.7280",
            "uptime_seconds": 11_240_500,
            "layer": "distribution",
            "x": 340.0,
            "y": 300.0,
            "base_rtt": 2.4,
            "base_cpu": 68.0,
            "base_mem": 64.0,
        },
        {
            "hostname": "iad-edge-fw-01",
            "fqdn": "iad-edge-fw-01.us-east.netpulse.corp",
            "management_ip": "10.10.2.1",
            "mac_address": "00:86:9C:10:02:01",
            "site_id": site_us.id,
            "rack_id": racks["US1-A01"].id,
            "cred": cred_api.id,
            "device_type": "firewall",
            "vendor": "palo_alto",
            "model": "PA-5250",
            "os_version": "PAN-OS 11.1.4",
            "serial_number": "013201018842",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier0", "security", "firewall", "dmz", "us-east"],
            "sys_descr": "Palo Alto Networks PA-5200 series firewall",
            "sys_object_id": "1.3.6.1.4.1.25461.2.3.37",
            "uptime_seconds": 9_450_100,
            "layer": "edge",
            "x": 80.0,
            "y": 140.0,
            "base_rtt": 1.8,
            "base_cpu": 44.0,
            "base_mem": 57.0,
        },
        {
            "hostname": "iad-lb-01",
            "fqdn": "iad-lb-01.us-east.netpulse.corp",
            "management_ip": "10.10.3.10",
            "mac_address": "00:23:E9:10:03:10",
            "site_id": site_us.id,
            "rack_id": racks["US1-A02"].id,
            "cred": cred_api.id,
            "device_type": "load_balancer",
            "vendor": "f5",
            "model": "BIG-IP i5800",
            "os_version": "TMOS 17.1.1.3",
            "serial_number": "F5-US-992817",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "adc", "ingress", "us-east"],
            "sys_descr": "BIG-IP i5800 TMOS 17.1.1.3",
            "sys_object_id": "1.3.6.1.4.1.3375.2.1.3.4.104",
            "uptime_seconds": 8_210_000,
            "layer": "distribution",
            "x": 110.0,
            "y": 440.0,
            "base_rtt": 1.2,
            "base_cpu": 38.0,
            "base_mem": 52.0,
        },
        {
            "hostname": "iad-app-01",
            "fqdn": "iad-app-01.us-east.netpulse.corp",
            "management_ip": "10.10.10.21",
            "mac_address": "52:54:00:10:10:21",
            "site_id": site_us.id,
            "rack_id": racks["US1-A02"].id,
            "cred": cred_ssh.id,
            "device_type": "server",
            "vendor": "linux",
            "model": "Dell PowerEdge R760",
            "os_version": "Ubuntu 24.04.1 LTS",
            "serial_number": "DL-R760-US01",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "is_host": True,
            "tags_json": ["compute", "prod-api", "linux", "us-east"],
            "sys_descr": "Linux iad-app-01 6.8.0-48-generic x86_64",
            "uptime_seconds": 4_120_300,
            "layer": "compute",
            "x": 230.0,
            "y": 480.0,
            "base_rtt": 0.7,
            "base_cpu": 42.0,
            "base_mem": 61.0,
        },
        {
            "hostname": "iad-db-01",
            "fqdn": "iad-db-01.us-east.netpulse.corp",
            "management_ip": "10.10.20.11",
            "mac_address": "52:54:00:10:20:11",
            "site_id": site_us.id,
            "rack_id": racks["US1-A02"].id,
            "cred": cred_ssh.id,
            "device_type": "server",
            "vendor": "linux",
            "model": "Dell PowerEdge R760xs",
            "os_version": "RHEL 9.4",
            "serial_number": "DL-R760-DB01",
            "status": "degraded",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "is_host": True,
            "tags_json": ["database", "postgresql", "tier0", "linux", "us-east"],
            "sys_descr": "Linux iad-db-01 5.14.0-427.el9.x86_64",
            "uptime_seconds": 6_910_000,
            "layer": "compute",
            "x": 360.0,
            "y": 480.0,
            "base_rtt": 1.1,
            "base_cpu": 84.0,
            "base_mem": 86.0,
        },
        # EU-Central Frankfurt DC2 (6)
        {
            "hostname": "fra-core-rtr-01",
            "fqdn": "fra-core-rtr-01.eu-central.netpulse.corp",
            "management_ip": "10.20.0.1",
            "mac_address": "2C:6B:F5:20:00:01",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "router",
            "vendor": "juniper",
            "model": "MX480",
            "os_version": "JunOS 23.4R2-S1",
            "serial_number": "JN12458823AA",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier0", "core", "bgp", "eu-central", "wan"],
            "sys_descr": "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 23.4R2-S1",
            "sys_object_id": "1.3.6.1.4.1.2636.1.1.1.2.25",
            "uptime_seconds": 13_400_200,
            "layer": "core",
            "x": 640.0,
            "y": 140.0,
            "base_rtt": 82.5,
            "base_cpu": 29.0,
            "base_mem": 46.0,
        },
        {
            "hostname": "fra-dist-sw-01",
            "fqdn": "fra-dist-sw-01.eu-central.netpulse.corp",
            "management_ip": "10.20.1.1",
            "mac_address": "28:99:3A:20:01:01",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "distribution_switch",
            "vendor": "arista",
            "model": "DCS-7050SX3-48YC8",
            "os_version": "EOS 4.31.2F",
            "serial_number": "JPE23290441",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "distribution", "eu-central"],
            "sys_descr": "Arista Networks EOS version 4.31.2F running on DCS-7050SX3",
            "uptime_seconds": 10_180_000,
            "layer": "distribution",
            "x": 640.0,
            "y": 300.0,
            "base_rtt": 83.4,
            "base_cpu": 24.0,
            "base_mem": 39.0,
        },
        {
            "hostname": "fra-edge-fw-01",
            "fqdn": "fra-edge-fw-01.eu-central.netpulse.corp",
            "management_ip": "10.20.2.1",
            "mac_address": "90:6C:AC:20:02:01",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B01"].id,
            "cred": cred_api.id,
            "device_type": "firewall",
            "vendor": "fortinet",
            "model": "FortiGate 1800F",
            "os_version": "FortiOS 7.4.5",
            "serial_number": "FG180FTK2200192",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier0", "security", "firewall", "eu-central"],
            "sys_descr": "FortiGate-1800F v7.4.5,build2702",
            "uptime_seconds": 7_820_000,
            "layer": "edge",
            "x": 790.0,
            "y": 140.0,
            "base_rtt": 84.1,
            "base_cpu": 37.0,
            "base_mem": 51.0,
        },
        {
            "hostname": "fra-lb-01",
            "fqdn": "fra-lb-01.eu-central.netpulse.corp",
            "management_ip": "10.20.3.10",
            "mac_address": "00:23:E9:20:03:10",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B02"].id,
            "cred": cred_api.id,
            "device_type": "load_balancer",
            "vendor": "f5",
            "model": "BIG-IP i4800",
            "os_version": "TMOS 17.1.1.3",
            "serial_number": "F5-EU-441209",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "adc", "eu-central"],
            "sys_descr": "BIG-IP i4800 TMOS 17.1.1.3",
            "uptime_seconds": 6_410_000,
            "layer": "distribution",
            "x": 540.0,
            "y": 430.0,
            "base_rtt": 83.9,
            "base_cpu": 33.0,
            "base_mem": 49.0,
        },
        {
            "hostname": "fra-app-01",
            "fqdn": "fra-app-01.eu-central.netpulse.corp",
            "management_ip": "10.20.10.21",
            "mac_address": "52:54:00:20:10:21",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B02"].id,
            "cred": cred_ssh.id,
            "device_type": "server",
            "vendor": "linux",
            "model": "HPE ProLiant DL380 Gen11",
            "os_version": "Ubuntu 24.04.1 LTS",
            "serial_number": "HPE-DL380-EU01",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "is_host": True,
            "tags_json": ["compute", "prod-api", "linux", "eu-central"],
            "sys_descr": "Linux fra-app-01 6.8.0-48-generic x86_64",
            "uptime_seconds": 3_950_000,
            "layer": "compute",
            "x": 650.0,
            "y": 480.0,
            "base_rtt": 84.5,
            "base_cpu": 39.0,
            "base_mem": 58.0,
        },
        {
            "hostname": "fra-db-01",
            "fqdn": "fra-db-01.eu-central.netpulse.corp",
            "management_ip": "10.20.20.11",
            "mac_address": "52:54:00:20:20:11",
            "site_id": site_eu.id,
            "rack_id": racks["EU2-B02"].id,
            "cred": cred_ssh.id,
            "device_type": "server",
            "vendor": "linux",
            "model": "HPE ProLiant DL380 Gen11",
            "os_version": "RHEL 9.4",
            "serial_number": "HPE-DL380-DBEU",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "is_host": True,
            "tags_json": ["database", "postgresql", "replica", "linux", "eu-central"],
            "sys_descr": "Linux fra-db-01 5.14.0-427.el9.x86_64",
            "uptime_seconds": 5_810_000,
            "layer": "compute",
            "x": 770.0,
            "y": 480.0,
            "base_rtt": 85.0,
            "base_cpu": 47.0,
            "base_mem": 72.0,
        },
        # AP-South Singapore Edge (4)
        {
            "hostname": "sin-edge-rtr-01",
            "fqdn": "sin-edge-rtr-01.ap-south.netpulse.corp",
            "management_ip": "10.30.0.1",
            "mac_address": "2C:6B:F5:30:00:01",
            "site_id": site_ap.id,
            "rack_id": racks["SG1-C01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "router",
            "vendor": "juniper",
            "model": "MX204",
            "os_version": "JunOS 23.4R2-S1",
            "serial_number": "JN20499812SG",
            "status": "degraded",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "edge", "bgp", "ap-south", "wan"],
            "sys_descr": "Juniper Networks, Inc. mx204 internet router, kernel JUNOS 23.4R2-S1",
            "uptime_seconds": 8_730_000,
            "layer": "core",
            "x": 1020.0,
            "y": 140.0,
            "base_rtt": 158.0,
            "base_cpu": 52.0,
            "base_mem": 55.0,
        },
        {
            "hostname": "sin-access-sw-01",
            "fqdn": "sin-access-sw-01.ap-south.netpulse.corp",
            "management_ip": "10.30.1.1",
            "mac_address": "00:1B:21:30:01:01",
            "site_id": site_ap.id,
            "rack_id": racks["SG1-C01"].id,
            "cred": cred_snmpv3.id,
            "device_type": "access_switch",
            "vendor": "cisco",
            "model": "Catalyst 9300-48P",
            "os_version": "IOS-XE 17.12.3",
            "serial_number": "FCW2419L04Z",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier2", "access", "ap-south"],
            "sys_descr": "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software, Version 17.12.3",
            "uptime_seconds": 9_120_000,
            "layer": "distribution",
            "x": 1020.0,
            "y": 300.0,
            "base_rtt": 161.0,
            "base_cpu": 21.0,
            "base_mem": 38.0,
        },
        {
            "hostname": "sin-edge-fw-01",
            "fqdn": "sin-edge-fw-01.ap-south.netpulse.corp",
            "management_ip": "10.30.2.1",
            "mac_address": "00:86:9C:30:02:01",
            "site_id": site_ap.id,
            "rack_id": racks["SG1-C02"].id,
            "cred": cred_api.id,
            "device_type": "firewall",
            "vendor": "palo_alto",
            "model": "PA-3260",
            "os_version": "PAN-OS 11.1.4",
            "serial_number": "012801077213",
            "status": "up",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "tags_json": ["tier1", "security", "firewall", "ap-south"],
            "sys_descr": "Palo Alto Networks PA-3200 series firewall",
            "uptime_seconds": 7_410_000,
            "layer": "edge",
            "x": 1160.0,
            "y": 140.0,
            "base_rtt": 160.2,
            "base_cpu": 34.0,
            "base_mem": 49.0,
        },
        {
            "hostname": "sin-app-01",
            "fqdn": "sin-app-01.ap-south.netpulse.corp",
            "management_ip": "10.30.10.21",
            "mac_address": "52:54:00:30:10:21",
            "site_id": site_ap.id,
            "rack_id": racks["SG1-C02"].id,
            "cred": cred_ssh.id,
            "device_type": "server",
            "vendor": "linux",
            "model": "Dell PowerEdge R660",
            "os_version": "Ubuntu 24.04.1 LTS",
            "serial_number": "DL-R660-SG01",
            "status": "down",
            "snmp_enabled": True,
            "icmp_enabled": True,
            "is_host": True,
            "tags_json": ["compute", "edge-api", "linux", "ap-south"],
            "sys_descr": "Linux sin-app-01 6.8.0-48-generic x86_64",
            "uptime_seconds": 0,
            "layer": "compute",
            "x": 1060.0,
            "y": 480.0,
            "base_rtt": 164.0,
            "base_cpu": 45.0,
            "base_mem": 63.0,
        },
        # Legacy External DNS Targets (matching config.py HOSTS)
        {
            "hostname": "google-dns-primary",
            "fqdn": "dns.google",
            "management_ip": "8.8.8.8",
            "site_id": site_us.id,
            "rack_id": None,
            "cred": None,
            "device_type": "gateway",
            "vendor": "generic",
            "model": "Anycast DNS Resolver",
            "os_version": "External",
            "status": "up",
            "snmp_enabled": False,
            "icmp_enabled": True,
            "tags_json": ["external", "dns", "anycast", "legacy-target"],
            "sys_descr": "Google Public DNS Primary (8.8.8.8)",
            "layer": "external",
            "x": 140.0,
            "y": 20.0,
            "base_rtt": 8.4,
        },
        {
            "hostname": "cloudflare-dns-primary",
            "fqdn": "one.one.one.one",
            "management_ip": "1.1.1.1",
            "site_id": site_eu.id,
            "rack_id": None,
            "cred": None,
            "device_type": "gateway",
            "vendor": "generic",
            "model": "Anycast DNS Resolver",
            "os_version": "External",
            "status": "up",
            "snmp_enabled": False,
            "icmp_enabled": True,
            "tags_json": ["external", "dns", "anycast", "legacy-target"],
            "sys_descr": "Cloudflare Public DNS (1.1.1.1)",
            "layer": "external",
            "x": 640.0,
            "y": 20.0,
            "base_rtt": 6.1,
        },
        {
            "hostname": "google-dns-secondary",
            "fqdn": "dns.google",
            "management_ip": "8.8.4.4",
            "site_id": site_ap.id,
            "rack_id": None,
            "cred": None,
            "device_type": "gateway",
            "vendor": "generic",
            "model": "Anycast DNS Resolver",
            "os_version": "External",
            "status": "up",
            "snmp_enabled": False,
            "icmp_enabled": True,
            "tags_json": ["external", "dns", "anycast", "legacy-target"],
            "sys_descr": "Google Public DNS Secondary (8.8.4.4)",
            "layer": "external",
            "x": 1020.0,
            "y": 20.0,
            "base_rtt": 11.2,
        },
    ]

    devices: dict[str, Device] = {}
    for spec in device_specs:
        is_down = spec["status"] == "down"
        dev = Device(
            id=new_uuid(),
            org_id=org_id,
            site_id=spec["site_id"],
            rack_id=spec["rack_id"],
            credential_profile_id=spec["cred"],
            hostname=spec["hostname"],
            fqdn=spec["fqdn"],
            management_ip=spec["management_ip"],
            mac_address=spec.get("mac_address"),
            device_type=spec["device_type"],
            vendor=spec["vendor"],
            model=spec.get("model"),
            os_version=spec.get("os_version"),
            serial_number=spec.get("serial_number"),
            status=spec["status"],
            polling_enabled=True,
            snmp_enabled=spec["snmp_enabled"],
            icmp_enabled=spec["icmp_enabled"],
            polling_interval_seconds=30,
            tags_json=spec["tags_json"],
            sys_descr=spec.get("sys_descr"),
            sys_object_id=spec.get("sys_object_id"),
            uptime_seconds=spec.get("uptime_seconds", 0),
            last_seen_at=now - timedelta(minutes=22 if is_down else 1),
            last_polled_at=now - timedelta(seconds=25),
        )
        devices[spec["hostname"]] = dev
        session.add(dev)
    session.flush()

    # Device Groups & Members
    group_specs = [
        ("Core Routing Backbone", "Tier-0 WAN & BGP core routers", "#6366f1", ["iad-core-rtr-01", "iad-core-rtr-02", "fra-core-rtr-01", "sin-edge-rtr-01"]),
        ("Edge Security Firewalls", "Perimeter NGFW appliances", "#ef4444", ["iad-edge-fw-01", "fra-edge-fw-01", "sin-edge-fw-01"]),
        ("Production Compute & DB", "Linux application and PostgreSQL nodes", "#10b981", ["iad-app-01", "iad-db-01", "fra-app-01", "fra-db-01", "sin-app-01"]),
        ("External DNS Targets", "Public anycast DNS reachability targets", "#0ea5e9", ["google-dns-primary", "cloudflare-dns-primary", "google-dns-secondary"]),
    ]
    for gname, gdesc, color, hostnames in group_specs:
        grp = DeviceGroup(
            id=new_uuid(),
            org_id=org_id,
            name=gname,
            description=gdesc,
            group_type="static",
            color=color,
        )
        session.add(grp)
        session.flush()
        for hn in hostnames:
            session.add(DeviceGroupMember(id=new_uuid(), group_id=grp.id, device_id=devices[hn].id))

    # ── 4. Interfaces, Subnets, VLANs, IPAM Allocations ──────────────────────
    interfaces_by_host: dict[str, list[DeviceInterface]] = {}
    for spec in device_specs:
        hn = spec["hostname"]
        dev = devices[hn]
        if not spec["snmp_enabled"]:
            continue
        is_router = spec["device_type"] == "router"
        is_switch = "switch" in spec["device_type"]
        if_defs = [
            (1, "HundredGigE0/0/0/0" if is_router else ("Ethernet1" if is_switch else "eth0"), "Primary Uplink", "hundred_gigabit_ethernet" if is_router else "ten_gigabit_ethernet", 100000 if is_router else 10000, True, "up" if dev.status != "down" else "down"),
            (2, "HundredGigE0/0/0/1" if is_router else ("Ethernet2" if is_switch else "eth1"), "Secondary / Peer Link", "forty_gigabit_ethernet" if is_router else "ten_gigabit_ethernet", 40000 if is_router else 10000, True, "up" if dev.status != "down" else "down"),
            (3, "MgmtEth0/RP0/CPU0/0" if is_router else "Management1", "Out-of-Band Management", "management", 1000, False, "up" if dev.status != "down" else "down"),
        ]
        host_ifs: list[DeviceInterface] = []
        for idx, if_name, alias, if_type, speed, uplink, oper in if_defs:
            err_in = 148 if (hn == "iad-dist-sw-02" and idx == 1) else rng.randint(0, 3)
            err_out = 42 if (hn == "iad-dist-sw-02" and idx == 1) else rng.randint(0, 2)
            iface = DeviceInterface(
                id=new_uuid(),
                org_id=org_id,
                device_id=dev.id,
                if_index=idx,
                name=if_name,
                alias=alias,
                ip_address=dev.management_ip if idx == 3 else None,
                interface_type=if_type,
                speed_mbps=speed,
                mtu=9216 if uplink else 1500,
                admin_status="up",
                oper_status=oper,
                duplex="full",
                is_monitored=True,
                is_uplink=uplink,
                in_octets_last=rng.randint(50_000_000_000, 900_000_000_000),
                out_octets_last=rng.randint(40_000_000_000, 800_000_000_000),
                in_errors_last=err_in,
                out_errors_last=err_out,
                utilization_in_pct=round(rng.uniform(18.0, 62.0), 1) if oper == "up" else 0.0,
                utilization_out_pct=round(rng.uniform(14.0, 54.0), 1) if oper == "up" else 0.0,
            )
            host_ifs.append(iface)
            session.add(iface)
        interfaces_by_host[hn] = host_ifs
    session.flush()

    subnets_spec = [
        ("10.10.0.0/22", "US-East Core & Infrastructure", site_us.id, "10.10.0.1", 10, 41.2),
        ("10.10.10.0/24", "US-East Prod Application Tier", site_us.id, "10.10.10.1", 100, 62.5),
        ("10.10.20.0/24", "US-East Prod Database Tier", site_us.id, "10.10.20.1", 200, 38.0),
        ("10.20.0.0/22", "EU-Central Core & Infrastructure", site_eu.id, "10.20.0.1", 10, 34.8),
        ("10.20.10.0/24", "EU-Central Prod Application Tier", site_eu.id, "10.20.10.1", 100, 51.0),
        ("10.30.0.0/22", "AP-South Edge Infrastructure", site_ap.id, "10.30.0.1", 10, 29.5),
    ]
    subnets_by_cidr: dict[str, Subnet] = {}
    for cidr, sname, sid, gw, vnum, util in subnets_spec:
        sub = Subnet(
            id=new_uuid(),
            org_id=org_id,
            site_id=sid,
            cidr=cidr,
            name=sname,
            gateway_ip=gw,
            vlan_number=vnum,
            dns_servers_json=["10.10.0.53", "1.1.1.1"],
            utilization_pct=util,
            scan_enabled=True,
            last_scanned_at=now - timedelta(hours=1),
        )
        subnets_by_cidr[cidr] = sub
        session.add(sub)
    session.flush()

    # IPAM Allocations for internal devices
    for hn, dev in devices.items():
        ip = dev.management_ip
        target_subnet: Subnet | None = None
        if ip.startswith("10.10.10."):
            target_subnet = subnets_by_cidr["10.10.10.0/24"]
        elif ip.startswith("10.10.20."):
            target_subnet = subnets_by_cidr["10.10.20.0/24"]
        elif ip.startswith("10.10."):
            target_subnet = subnets_by_cidr["10.10.0.0/22"]
        elif ip.startswith("10.20.10."):
            target_subnet = subnets_by_cidr["10.20.10.0/24"]
        elif ip.startswith("10.20."):
            target_subnet = subnets_by_cidr["10.20.0.0/22"]
        elif ip.startswith("10.30."):
            target_subnet = subnets_by_cidr["10.30.0.0/22"]
        if target_subnet is not None:
            session.add(
                IpAllocation(
                    id=new_uuid(),
                    org_id=org_id,
                    subnet_id=target_subnet.id,
                    device_id=dev.id,
                    ip_address=ip,
                    mac_address=dev.mac_address,
                    hostname=dev.fqdn,
                    allocation_type="static",
                    status="active",
                    last_seen_at=dev.last_seen_at,
                )
            )

    vlans_spec = [
        (site_us.id, 10, "CORE-TRANSIT", "10.10.0.0/22"),
        (site_us.id, 100, "PROD-APP-TIER", "10.10.10.0/24"),
        (site_us.id, 200, "PROD-DB-TIER", "10.10.20.0/24"),
        (site_us.id, 400, "OOB-MANAGEMENT", "10.10.40.0/24"),
        (site_eu.id, 10, "EU-CORE-TRANSIT", "10.20.0.0/22"),
        (site_ap.id, 10, "AP-EDGE-TRANSIT", "10.30.0.0/22"),
    ]
    for sid, vnum, vname, cidr in vlans_spec:
        session.add(
            Vlan(
                id=new_uuid(),
                org_id=org_id,
                site_id=sid,
                vlan_id_num=vnum,
                name=vname,
                subnet_cidr=cidr,
                status="active",
            )
        )

    # ── 5. Topology Nodes, Links, Dependency Edges, Discovery Job ────────────
    topo_nodes: dict[str, TopologyNode] = {}
    for spec in device_specs:
        hn = spec["hostname"]
        dev = devices[hn]
        node = TopologyNode(
            id=new_uuid(),
            org_id=org_id,
            device_id=dev.id,
            label=hn,
            node_type=spec["device_type"],
            site_id=spec["site_id"],
            x_pos=spec["x"],
            y_pos=spec["y"],
            layer=spec["layer"],
            status=dev.status,
            pinned=True,
            metadata_json={"ip": dev.management_ip, "vendor": dev.vendor, "model": dev.model},
        )
        topo_nodes[hn] = node
        session.add(node)
    session.flush()

    link_specs = [
        ("iad-core-rtr-01", "iad-core-rtr-02", "l3_routed", "lldp", 100000.0, 28.4, 0.4, "up"),
        ("iad-core-rtr-01", "fra-core-rtr-01", "bgp_peering", "bgp", 100000.0, 46.2, 81.2, "up"),
        ("fra-core-rtr-01", "sin-edge-rtr-01", "bgp_peering", "bgp", 40000.0, 39.8, 148.5, "degraded"),
        ("iad-core-rtr-02", "sin-edge-rtr-01", "bgp_peering", "bgp", 40000.0, 31.5, 192.0, "up"),
        ("iad-core-rtr-01", "iad-edge-fw-01", "physical", "lldp", 40000.0, 35.1, 0.6, "up"),
        ("iad-core-rtr-01", "iad-dist-sw-01", "physical", "lldp", 40000.0, 41.0, 0.5, "up"),
        ("iad-core-rtr-02", "iad-dist-sw-02", "physical", "lldp", 40000.0, 58.9, 1.3, "warning"),
        ("iad-dist-sw-01", "iad-lb-01", "l2_ethernet", "lldp", 10000.0, 37.4, 0.4, "up"),
        ("iad-dist-sw-01", "iad-app-01", "l2_ethernet", "lldp", 10000.0, 44.2, 0.3, "up"),
        ("iad-dist-sw-02", "iad-db-01", "l2_ethernet", "lldp", 10000.0, 63.8, 0.5, "up"),
        ("fra-core-rtr-01", "fra-edge-fw-01", "physical", "lldp", 40000.0, 29.0, 0.5, "up"),
        ("fra-core-rtr-01", "fra-dist-sw-01", "physical", "lldp", 40000.0, 33.6, 0.4, "up"),
        ("fra-dist-sw-01", "fra-lb-01", "l2_ethernet", "lldp", 10000.0, 28.1, 0.4, "up"),
        ("fra-dist-sw-01", "fra-app-01", "l2_ethernet", "lldp", 10000.0, 31.7, 0.3, "up"),
        ("fra-dist-sw-01", "fra-db-01", "l2_ethernet", "lldp", 10000.0, 36.2, 0.4, "up"),
        ("sin-edge-rtr-01", "sin-edge-fw-01", "physical", "lldp", 10000.0, 26.4, 0.6, "up"),
        ("sin-edge-rtr-01", "sin-access-sw-01", "physical", "lldp", 10000.0, 24.0, 0.5, "up"),
        ("sin-access-sw-01", "sin-app-01", "l2_ethernet", "lldp", 10000.0, 0.0, 0.0, "down"),
        ("iad-edge-fw-01", "google-dns-primary", "l3_routed", "inferred", 10000.0, 12.0, 8.4, "up"),
        ("fra-edge-fw-01", "cloudflare-dns-primary", "l3_routed", "inferred", 10000.0, 10.5, 6.1, "up"),
        ("sin-edge-fw-01", "google-dns-secondary", "l3_routed", "inferred", 10000.0, 9.8, 11.2, "up"),
    ]
    for src_hn, dst_hn, ltype, proto, bw, util, lat, st in link_specs:
        src_if = interfaces_by_host.get(src_hn, [None])[0]
        dst_if = interfaces_by_host.get(dst_hn, [None])[0]
        session.add(
            TopologyLink(
                id=new_uuid(),
                org_id=org_id,
                source_node_id=topo_nodes[src_hn].id,
                target_node_id=topo_nodes[dst_hn].id,
                source_interface_id=src_if.id if src_if else None,
                target_interface_id=dst_if.id if dst_if else None,
                link_type=ltype,
                discovery_protocol=proto,
                bandwidth_mbps=bw,
                utilization_pct=util,
                latency_ms=lat,
                packet_loss_pct=100.0 if st == "down" else (1.4 if st == "degraded" else 0.0),
                status=st,
                last_verified_at=now - timedelta(minutes=2),
            )
        )

    dep_pairs = [
        ("iad-core-rtr-01", "iad-dist-sw-01", "upstream_network", 1.0),
        ("iad-core-rtr-02", "iad-dist-sw-02", "upstream_network", 1.0),
        ("iad-dist-sw-01", "iad-app-01", "upstream_network", 0.9),
        ("iad-dist-sw-02", "iad-db-01", "upstream_network", 1.0),
        ("iad-db-01", "iad-app-01", "storage", 0.95),
        ("fra-core-rtr-01", "fra-dist-sw-01", "upstream_network", 1.0),
        ("sin-edge-rtr-01", "sin-access-sw-01", "upstream_network", 1.0),
        ("sin-access-sw-01", "sin-app-01", "upstream_network", 1.0),
    ]
    for parent_hn, child_hn, dtype, weight in dep_pairs:
        session.add(
            DependencyEdge(
                id=new_uuid(),
                org_id=org_id,
                parent_device_id=devices[parent_hn].id,
                child_device_id=devices[child_hn].id,
                dependency_type=dtype,
                weight=weight,
                description=f"{child_hn} depends on {parent_hn} ({dtype})",
            )
        )

    disc_job = DiscoveryJob(
        id=new_uuid(),
        org_id=org_id,
        name="Global Multi-Site Nightly LLDP/SNMP Discovery",
        target_cidrs_json=["10.10.0.0/22", "10.20.0.0/22", "10.30.0.0/22"],
        protocols_json=["icmp_sweep", "snmp", "lldp", "bgp"],
        credential_profile_id=cred_snmpv3.id,
        status="completed",
        progress_pct=100.0,
        hosts_scanned=1024,
        devices_found=18,
        links_found=21,
        started_at=now - timedelta(hours=6, minutes=12),
        completed_at=now - timedelta(hours=6, minutes=8),
    )
    session.add(disc_job)
    session.flush()

    for hn in ("iad-core-rtr-01", "fra-core-rtr-01", "sin-edge-rtr-01"):
        dev = devices[hn]
        session.add(
            DiscoveryFinding(
                id=new_uuid(),
                job_id=disc_job.id,
                org_id=org_id,
                ip_address=dev.management_ip,
                mac_address=dev.mac_address,
                hostname=dev.hostname,
                vendor=dev.vendor,
                device_type=dev.device_type,
                open_ports_json=[22, 161, 179, 443],
                snmp_sys_descr=dev.sys_descr,
                matched_device_id=dev.id,
                disposition="matched",
            )
        )

    # ── 6. 24h Time-Series Telemetry (SNMP, ICMP, Host, Synthetic, Rollups) ──
    metric_defs = [
        ("snmp.cpu_pct", "system", "%", "Device CPU utilization via SNMP"),
        ("snmp.mem_pct", "system", "%", "Device memory utilization via SNMP"),
        ("snmp.if_in_mbps", "network", "Mbps", "Aggregate inbound interface throughput"),
        ("snmp.if_out_mbps", "network", "Mbps", "Aggregate outbound interface throughput"),
        ("icmp.avg_rtt_ms", "reachability", "ms", "ICMP echo round-trip time"),
        ("icmp.packet_loss_pct", "reachability", "%", "ICMP probe packet loss percentage"),
        ("host.cpu_total_pct", "host", "%", "Host OS combined user+system CPU percentage"),
        ("synthetic.total_ms", "synthetic", "ms", "End-to-end synthetic check response time"),
    ]
    for mname, cat, unit, desc_txt in metric_defs:
        session.add(
            MetricDefinition(
                id=new_uuid(),
                name=mname,
                category=cat,
                unit=unit,
                description=desc_txt,
                aggregation_default="avg",
                retention_days=30,
                is_counter=False,
            )
        )

    # Generate 48 half-hour samples over the past 24 hours (fast & rich for charts!)
    sample_count = 48
    snmp_samples: list[SnmpMetricSample] = []
    icmp_samples: list[IcmpMetricSample] = []
    host_samples: list[HostMetricSample] = []
    rollup_rows: list[MetricRollup] = []

    for spec in device_specs:
        hn = spec["hostname"]
        dev = devices[hn]
        phase = 0.0 if spec["site_id"] == site_us.id else (6.0 if spec["site_id"] == site_eu.id else 13.0)
        base_rtt = float(spec.get("base_rtt", 2.0))
        base_cpu = float(spec.get("base_cpu", 30.0))
        base_mem = float(spec.get("base_mem", 45.0))
        is_host = bool(spec.get("is_host", False))

        hourly_cpu_acc: dict[int, list[float]] = {}

        for step in range(sample_count):
            ts = now - timedelta(minutes=(sample_count - 1 - step) * 30)
            factor = _diurnal_factor(ts.hour + ts.minute / 60.0, phase_shift=phase)
            recent_outage = hn == "sin-app-01" and step >= sample_count - 2
            db_spike = hn == "iad-db-01" and step >= sample_count - 4

            # ICMP sample for every device
            if recent_outage:
                icmp_samples.append(
                    IcmpMetricSample(
                        id=new_uuid(),
                        org_id=org_id,
                        device_id=dev.id,
                        target_ip=dev.management_ip,
                        timestamp=ts,
                        avg_rtt_ms=None,
                        min_rtt_ms=None,
                        max_rtt_ms=None,
                        p95_rtt_ms=None,
                        packet_loss_pct=100.0,
                        jitter_ms=None,
                        packets_sent=4,
                        packets_received=0,
                        status="down",
                    )
                )
            else:
                rtt = max(0.3, base_rtt * (0.92 + 0.16 * rng.random()) * (1.0 + 0.08 * (factor - 1.0)))
                loss = 0.0 if rng.random() > 0.04 else round(rng.uniform(0.5, 2.5), 1)
                if hn == "sin-edge-rtr-01" and step >= sample_count - 3:
                    loss = round(rng.uniform(4.0, 9.5), 1)
                    rtt *= 1.25
                icmp_samples.append(
                    IcmpMetricSample(
                        id=new_uuid(),
                        org_id=org_id,
                        device_id=dev.id,
                        target_ip=dev.management_ip,
                        timestamp=ts,
                        avg_rtt_ms=round(rtt, 2),
                        min_rtt_ms=round(rtt * 0.85, 2),
                        max_rtt_ms=round(rtt * 1.28, 2),
                        p95_rtt_ms=round(rtt * 1.18, 2),
                        packet_loss_pct=loss,
                        jitter_ms=round(max(0.05, rtt * 0.06 * rng.random()), 2),
                        ttl=64 if is_host else 251,
                        packets_sent=4,
                        packets_received=4 if loss == 0 else 3,
                        status="degraded" if loss >= 4.0 else "up",
                    )
                )

            # SNMP sample for managed devices
            if spec["snmp_enabled"]:
                cpu = min(98.5, max(5.0, base_cpu * factor + rng.uniform(-4.0, 4.5) + (11.0 if db_spike else 0.0)))
                mem = min(96.0, max(15.0, base_mem + rng.uniform(-2.0, 2.5) + (6.0 if db_spike else 0.0)))
                in_mbps = round(max(10.0, (4200.0 if spec["device_type"] == "router" else 950.0) * factor * rng.uniform(0.85, 1.15)), 2)
                out_mbps = round(in_mbps * rng.uniform(0.75, 1.05), 2)
                snmp_samples.append(
                    SnmpMetricSample(
                        id=new_uuid(),
                        org_id=org_id,
                        device_id=dev.id,
                        timestamp=ts,
                        cpu_pct=0.0 if recent_outage else round(cpu, 2),
                        mem_pct=0.0 if recent_outage else round(mem, 2),
                        mem_used_mb=round(mem * 320.0, 1),
                        mem_total_mb=32768.0,
                        temp_celsius=round(38.0 + cpu * 0.22 + rng.uniform(-1.0, 1.0), 1),
                        if_in_mbps=0.0 if recent_outage else in_mbps,
                        if_out_mbps=0.0 if recent_outage else out_mbps,
                        if_errors=(24 if hn == "iad-dist-sw-02" else rng.randint(0, 1)),
                        if_discards=rng.randint(0, 3),
                        active_connections=rng.randint(400, 18500),
                        sys_uptime_seconds=max(0, (spec.get("uptime_seconds") or 0) - (sample_count - step) * 1800),
                        reachable=not recent_outage,
                    )
                )
                hour_bucket = step // 2
                hourly_cpu_acc.setdefault(hour_bucket, []).append(cpu)

            # Host OS sample for Linux servers
            if is_host and not recent_outage:
                cpu_u = min(92.0, max(4.0, base_cpu * 0.72 * factor + (14.0 if db_spike else 0.0) + rng.uniform(-3.0, 3.0)))
                cpu_s = min(25.0, max(2.0, base_cpu * 0.22 * factor + rng.uniform(-1.0, 1.5)))
                iowait = round(rng.uniform(12.0, 22.0) if db_spike else rng.uniform(0.5, 4.0), 2)
                host_samples.append(
                    HostMetricSample(
                        id=new_uuid(),
                        org_id=org_id,
                        device_id=dev.id,
                        timestamp=ts,
                        cpu_user_pct=round(cpu_u, 2),
                        cpu_system_pct=round(cpu_s, 2),
                        cpu_iowait_pct=iowait,
                        load_1m=round((cpu_u + cpu_s) / 14.0, 2),
                        load_5m=round((cpu_u + cpu_s) / 15.0, 2),
                        load_15m=round((cpu_u + cpu_s) / 16.0, 2),
                        mem_used_pct=round(min(96.0, base_mem + rng.uniform(-2.0, 2.5)), 2),
                        swap_used_pct=round(rng.uniform(0.5, 6.0), 2),
                        disk_used_pct=round(78.4 if "db" in hn else 46.2 + rng.uniform(-0.3, 0.3), 2),
                        disk_read_mbps=round(rng.uniform(80.0, 320.0) if "db" in hn else rng.uniform(5.0, 40.0), 2),
                        disk_write_mbps=round(rng.uniform(45.0, 210.0) if "db" in hn else rng.uniform(3.0, 25.0), 2),
                        net_rx_mbps=round(rng.uniform(120.0, 680.0) * factor, 2),
                        net_tx_mbps=round(rng.uniform(90.0, 520.0) * factor, 2),
                        open_fds=rng.randint(1200, 14500),
                        process_count=rng.randint(180, 420),
                    )
                )

        # Hourly 1h rollups for core/DB devices
        if hn in {"iad-core-rtr-01", "fra-core-rtr-01", "sin-edge-rtr-01", "iad-db-01"}:
            for hour_idx, vals in hourly_cpu_acc.items():
                b_start = (now - timedelta(hours=23 - hour_idx)).replace(minute=0, second=0, microsecond=0)
                rollup_rows.append(
                    MetricRollup(
                        id=new_uuid(),
                        org_id=org_id,
                        device_id=dev.id,
                        metric_name="snmp.cpu_pct",
                        bucket_size="1h",
                        bucket_start=b_start,
                        sample_count=len(vals),
                        min_val=round(min(vals), 2),
                        max_val=round(max(vals), 2),
                        avg_val=round(sum(vals) / len(vals), 2),
                        p50_val=round(sorted(vals)[len(vals) // 2], 2),
                        p95_val=round(max(vals), 2),
                        p99_val=round(max(vals), 2),
                        sum_val=round(sum(vals), 2),
                    )
                )

    session.add_all(snmp_samples)
    session.add_all(icmp_samples)
    session.add_all(host_samples)
    session.add_all(rollup_rows)

    # Synthetic Probes & 24h Results
    probe_specs = [
        ("Global API Gateway Health", "https", "https://api.netpulse.corp/healthz", 443, devices["iad-lb-01"].id, 200, 42.0),
        ("EU Customer Portal TLS Check", "https", "https://eu.netpulse.corp/login", 443, devices["fra-lb-01"].id, 200, 68.0),
        ("External Anycast DNS Resolution", "dns", "dns.google", 53, devices["google-dns-primary"].id, None, 12.0),
        ("Singapore Edge API TCP 443", "tcp", "10.30.10.21", 443, devices["sin-app-01"].id, None, 165.0),
    ]
    probe_results: list[SyntheticProbeResult] = []
    for pname, ptype, target, port, dev_id, exp_code, base_ms in probe_specs:
        cfg = SyntheticProbeConfig(
            id=new_uuid(),
            org_id=org_id,
            device_id=dev_id,
            name=pname,
            probe_type=ptype,
            target_url_or_host=target,
            port=port,
            interval_seconds=60,
            timeout_seconds=5.0,
            expected_status_code=exp_code,
            tls_verify=True,
            tls_warn_days=21,
            enabled=True,
            locations_json=["us-east", "eu-central", "ap-south"],
        )
        session.add(cfg)
        session.flush()
        for step in range(24):
            ts = now - timedelta(hours=23 - step)
            is_fail = ("Singapore" in pname and step >= 22)
            tot = round(base_ms * rng.uniform(0.82, 1.32), 2) if not is_fail else 5000.0
            probe_results.append(
                SyntheticProbeResult(
                    id=new_uuid(),
                    org_id=org_id,
                    probe_id=cfg.id,
                    timestamp=ts,
                    location="us-east",
                    success=not is_fail,
                    status_code=None if is_fail else exp_code,
                    dns_ms=round(tot * 0.12, 2),
                    connect_ms=round(tot * 0.22, 2),
                    tls_ms=round(tot * 0.28, 2) if ptype == "https" else None,
                    ttfb_ms=round(tot * 0.38, 2),
                    total_ms=tot,
                    tls_days_remaining=54 if ptype == "https" else None,
                    tls_issuer="DigiCert Global G2 TLS RSA SHA256" if ptype == "https" else None,
                    response_size_bytes=4096 if not is_fail else 0,
                    error_message="TCP connect timed out after 5000ms" if is_fail else None,
                )
            )
    session.add_all(probe_results)

    # ── 7. Syslog Events, NetFlow Records, BGP Sessions, Edge Agents ─────────
    syslog_templates = [
        ("iad-core-rtr-01", 23, 5, "BGP", "%ROUTING-BGP-5-ADJCHANGE : neighbor 198.51.100.1 Up (prefixes: 892410)"),
        ("iad-core-rtr-01", 23, 6, "CONFIG", "%MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'netpulse-ncm'"),
        ("iad-dist-sw-02", 23, 4, "Ebra", "%ETH-4-ERR_RATE : Ethernet1 input CRC error rate exceeded 15/min threshold"),
        ("iad-edge-fw-01", 16, 4, "THREAT", "TRAFFIC/THREAT deny src=185.220.101.44 dst=10.10.3.10 dport=443 rule=BLOCK-SCANNER"),
        ("iad-db-01", 3, 3, "postgresql", "checkpoint complete: wrote 48120 buffers (81.2%); sync=14.821 s; high I/O wait detected"),
        ("fra-core-rtr-01", 23, 6, "rpd", "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 80.81.192.15 (External AS 6695) established"),
        ("fra-edge-fw-01", 16, 5, "fortigate", "action=accept policyid=14 srcip=10.20.10.21 dstip=10.10.20.11 service=PostgreSQL"),
        ("sin-edge-rtr-01", 23, 2, "rpd", "BGP_PREFIX_THRESH_EXCEEDED: peer 203.0.113.54 (AS 4755) hold timer expired, state -> Active"),
        ("sin-app-01", 0, 2, "kernel", "NIC ens192 link is down; carrier lost on VLAN 100"),
    ]
    syslog_rows: list[SyslogEvent] = []
    for idx in range(36):
        hn, fac, sev, app, msg = syslog_templates[idx % len(syslog_templates)]
        dev = devices[hn]
        ts = now - timedelta(minutes=idx * 18 + rng.randint(0, 12))
        syslog_rows.append(
            SyslogEvent(
                id=new_uuid(),
                org_id=org_id,
                device_id=dev.id,
                source_ip=dev.management_ip,
                timestamp=ts,
                received_at=ts + timedelta(milliseconds=45),
                facility=fac,
                severity=sev,
                app_name=app,
                message=msg,
                fingerprint=_sha256(f"{hn}:{app}:{msg}")[:32],
                parsed_fields_json={"host": hn, "vendor": dev.vendor},
            )
        )
    session.add_all(syslog_rows)

    flow_templates = [
        ("iad-core-rtr-01", "10.10.10.21", "10.10.20.11", 51422, 5432, 6, "postgresql", 85_000_000, 62_000),
        ("iad-core-rtr-01", "10.10.3.10", "10.10.10.21", 49112, 8443, 6, "https-api", 142_000_000, 108_000),
        ("iad-core-rtr-01", "10.20.10.21", "10.10.20.11", 44810, 5432, 6, "pg-replication", 210_000_000, 155_000),
        ("fra-core-rtr-01", "10.20.3.10", "10.20.10.21", 52100, 443, 6, "https", 98_000_000, 74_000),
        ("fra-core-rtr-01", "10.20.10.21", "1.1.1.1", 53811, 53, 17, "dns", 4_200_000, 31_000),
        ("iad-edge-fw-01", "198.51.100.88", "10.10.3.10", 60120, 443, 6, "https-ingress", 315_000_000, 240_000),
        ("iad-edge-fw-01", "203.0.113.19", "10.10.3.10", 54102, 443, 17, "quic", 64_000_000, 52_000),
        ("sin-edge-rtr-01", "10.30.10.21", "8.8.4.4", 49811, 53, 17, "dns", 2_800_000, 22_000),
        ("iad-core-rtr-01", "10.10.0.1", "172.16.10.2", 59012, 179, 6, "bgp", 1_900_000, 14_000),
        ("iad-core-rtr-01", "10.10.40.15", "10.10.0.1", 51204, 22, 6, "ssh", 850_000, 4_200),
    ]
    netflow_rows: list[NetFlowRecord] = []
    for idx in range(60):
        exp_hn, src_ip, dst_ip, sp, dp, proto, app_tag, b_base, p_base = flow_templates[idx % len(flow_templates)]
        scale = rng.uniform(0.55, 1.55)
        netflow_rows.append(
            NetFlowRecord(
                id=new_uuid(),
                org_id=org_id,
                exporter_device_id=devices[exp_hn].id,
                timestamp=now - timedelta(minutes=idx * 10),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sp + (idx % 17),
                dst_port=dp,
                protocol=proto,
                bytes_count=int(b_base * scale),
                packets_count=int(p_base * scale),
                input_if_index=1,
                output_if_index=2,
                src_asn=65001,
                dst_asn=65002 if dst_ip.startswith("10.20.") else 3356,
                flow_duration_ms=rng.randint(1200, 59000),
                application_tag=app_tag,
            )
        )
    session.add_all(netflow_rows)

    bgp_specs = [
        ("iad-core-rtr-01", "198.51.100.1", 3356, 65001, "Lumen Tier-1 Transit Primary", "established", 892_410, 48, 8_420_000, 0),
        ("iad-core-rtr-01", "172.16.10.2", 65002, 65001, "EU-Central FRA Core iBGP/eBGP", "established", 1_240, 1_180, 11_200_000, 0),
        ("iad-core-rtr-02", "198.51.100.9", 1299, 65001, "Arelion Tier-1 Transit Backup", "established", 889_105, 48, 7_950_000, 0),
        ("fra-core-rtr-01", "80.81.192.15", 6695, 65002, "DE-CIX Frankfurt Route Server", "established", 248_900, 62, 6_310_000, 1),
        ("sin-edge-rtr-01", "172.16.20.1", 65002, 65003, "EU-Central FRA WAN Tunnel", "established", 1_310, 310, 5_100_000, 1),
        ("sin-edge-rtr-01", "203.0.113.54", 4755, 65003, "Tata APAC Transit Peer", "active", 0, 0, 0, 6),
    ]
    for hn, pip, pasn, lasn, desc_txt, st, prx, ptx, up_s, flaps in bgp_specs:
        session.add(
            BgpPeerSession(
                id=new_uuid(),
                org_id=org_id,
                device_id=devices[hn].id,
                peer_ip=pip,
                peer_asn=pasn,
                local_asn=lasn,
                peer_description=desc_txt,
                state=st,
                prefixes_received=prx,
                prefixes_advertised=ptx,
                uptime_seconds=up_s,
                flaps_24h=flaps,
                last_updated_at=now - timedelta(seconds=30),
            )
        )

    agent_specs = [
        ("edge-collector-iad-01", "collector-01.us-east.netpulse.corp", "10.10.0.200", "us-east", "online", 18.4, 412.0),
        ("edge-collector-fra-01", "collector-01.eu-central.netpulse.corp", "10.20.0.200", "eu-central", "online", 14.2, 368.0),
        ("edge-collector-sin-01", "collector-01.ap-south.netpulse.corp", "10.30.0.200", "ap-south", "degraded", 41.8, 520.0),
    ]
    for aname, ahn, aip, reg, ast, cpu, mem in agent_specs:
        session.add(
            EdgeAgent(
                id=new_uuid(),
                org_id=org_id,
                name=aname,
                hostname=ahn,
                agent_version="2.4.1",
                ip_address=aip,
                region=reg,
                status=ast,
                capabilities_json=["icmp", "snmp_v3", "syslog_udp", "netflow_v9", "synthetic"],
                auth_token_hash=_sha256(f"agent-token-{aname}"),
                last_heartbeat_at=now - timedelta(seconds=18),
                metrics_sent_total=rng.randint(1_500_000, 9_200_000),
                buffer_depth=0 if ast == "online" else 142,
                cpu_pct=cpu,
                mem_mb=mem,
            )
        )

    # ── 8. Alerting, Incidents, Escalation, On-Call, Maintenance, SLOs ───────
    ch_slack = NotificationChannel(
        id=new_uuid(),
        org_id=org_id,
        name="Slack #netops-alerts",
        channel_type="slack",
        encrypted_config=vault.encrypt_json({"webhook_url": "https://hooks.slack.example/netops"}),
        severity_filter_json=["warning", "high", "critical", "emergency"],
        enabled=True,
        last_tested_at=now - timedelta(days=1),
        last_status="delivered",
    )
    ch_pd = NotificationChannel(
        id=new_uuid(),
        org_id=org_id,
        name="PagerDuty 24x7 NetOps",
        channel_type="pagerduty",
        encrypted_config=vault.encrypt_json({"routing_key": "pd-demo-routing-key-2026"}),
        severity_filter_json=["critical", "emergency"],
        enabled=True,
        last_tested_at=now - timedelta(days=2),
        last_status="delivered",
    )
    ch_email = NotificationChannel(
        id=new_uuid(),
        org_id=org_id,
        name="NOC Distribution Email",
        channel_type="email",
        encrypted_config=vault.encrypt_json({"recipients": ["noc@netpulse.corp", "sre@netpulse.corp"]}),
        severity_filter_json=["info", "warning", "high", "critical"],
        enabled=True,
        last_tested_at=now - timedelta(days=3),
        last_status="delivered",
    )
    session.add_all([ch_slack, ch_pd, ch_email])
    session.flush()

    esc_policy = EscalationPolicy(
        id=new_uuid(),
        org_id=org_id,
        name="Critical Infrastructure 24x7 Escalation",
        description="Immediate Slack + PagerDuty page, escalate to Principal NetOps after 15 minutes",
        repeat_count=3,
        is_default=True,
        steps_json=[
            {"delay_minutes": 0, "channel_ids": [ch_slack.id, ch_pd.id], "notify_user_ids": [netops_user.id]},
            {"delay_minutes": 15, "channel_ids": [ch_pd.id, ch_email.id], "notify_user_ids": [sre_user.id, admin_user.id]},
        ],
    )
    session.add(esc_policy)
    session.flush()

    session.add(
        OnCallSchedule(
            id=new_uuid(),
            org_id=org_id,
            name="Global NetOps Primary On-Call",
            timezone="UTC",
            rotation_type="weekly",
            participants_json=[netops_user.id, sre_user.id, admin_user.id],
            handoff_hour_utc=14,
            current_oncall_user_id=netops_user.id,
        )
    )

    rules_spec = [
        ("Device Unreachable (ICMP 100% Loss)", "threshold", "icmp.packet_loss_pct", "gte", 10.0, 50.0, "critical"),
        ("High Device CPU Utilization", "threshold", "snmp.cpu_pct", "gte", 70.0, 90.0, "critical"),
        ("High Memory Utilization", "threshold", "snmp.mem_pct", "gte", 75.0, 90.0, "warning"),
        ("Elevated ICMP Latency (RTT)", "threshold", "icmp.avg_rtt_ms", "gte", 300.0, 800.0, "warning"),
        ("Interface Error Counter Burst", "threshold", "snmp.if_errors", "gte", 5.0, 20.0, "warning"),
        ("BGP Peer Session Down / Flapping", "threshold", "bgp.session_down", "gte", 1.0, 1.0, "critical"),
        ("Synthetic Endpoint Probe Failure", "threshold", "synthetic.success", "eq", 0.0, 0.0, "critical"),
    ]
    alert_rules: dict[str, AlertRule] = {}
    for rname, rtype, metric, op, warn_t, crit_t, sev in rules_spec:
        rule = AlertRule(
            id=new_uuid(),
            org_id=org_id,
            name=rname,
            description=f"Automated alert rule monitoring {metric}",
            rule_type=rtype,
            metric_name=metric,
            operator=op,
            warning_threshold=warn_t,
            critical_threshold=crit_t,
            evaluation_window_seconds=180,
            consecutive_breaches=2,
            severity=sev,
            cooldown_seconds=300,
            auto_resolve=True,
            enabled=True,
            escalation_policy_id=esc_policy.id,
        )
        alert_rules[rname] = rule
        session.add(rule)
    session.flush()

    # Incidents
    inc_active = Incident(
        id=new_uuid(),
        org_id=org_id,
        incident_number="INC-2026-0042",
        title="AP-South Singapore Edge: sin-app-01 Unreachable & Tata Transit BGP Flap",
        description="Edge compute host sin-app-01 lost L2 carrier while sin-edge-rtr-01 experienced BGP hold-timer expiry toward AS 4755.",
        status="investigating",
        priority="p1",
        severity="critical",
        root_cause_device_id=devices["sin-edge-rtr-01"].id,
        assigned_to_user_id=netops_user.id,
        escalation_policy_id=esc_policy.id,
        affected_device_ids_json=[devices["sin-edge-rtr-01"].id, devices["sin-app-01"].id],
        started_at=now - timedelta(minutes=24),
        acknowledged_at=now - timedelta(minutes=19),
        tags_json=["ap-south", "bgp", "outage"],
    )
    inc_resolved = Incident(
        id=new_uuid(),
        org_id=org_id,
        incident_number="INC-2026-0039",
        title="US-East Ashburn: Transient Optical Flap on iad-dist-sw-02 Uplink",
        description="CRC errors spiked on Ethernet1 during patch-panel maintenance; resolved after SFP+ transceiver reseat.",
        status="resolved",
        priority="p2",
        severity="warning",
        root_cause_device_id=devices["iad-dist-sw-02"].id,
        assigned_to_user_id=sre_user.id,
        escalation_policy_id=esc_policy.id,
        affected_device_ids_json=[devices["iad-dist-sw-02"].id],
        started_at=now - timedelta(hours=18),
        acknowledged_at=now - timedelta(hours=17, minutes=52),
        resolved_at=now - timedelta(hours=17, minutes=14),
        mttr_seconds=2760,
        postmortem_markdown="## Summary\nTransient SFP+ optic degradation caused CRC errors on `iad-dist-sw-02:Ethernet1`.\n\n## Remediation\nReplaced 10G-LR transceiver during maintenance window and verified zero CRC errors for 12h.",
        tags_json=["us-east", "optics", "resolved"],
    )
    session.add_all([inc_active, inc_resolved])
    session.flush()

    session.add_all(
        [
            IncidentTimelineEntry(
                id=new_uuid(),
                incident_id=inc_active.id,
                org_id=org_id,
                author_user_id=None,
                entry_type="system",
                content="Incident auto-created by alert correlation engine (2 correlated critical alerts in AP-SOUTH-SG1).",
                created_at=now - timedelta(minutes=24),
            ),
            IncidentTimelineEntry(
                id=new_uuid(),
                incident_id=inc_active.id,
                org_id=org_id,
                author_user_id=netops_user.id,
                entry_type="status_change",
                content="Acknowledged by Marcus Chen. Traffic drained via EU-Central FRA WAN tunnel; opening carrier ticket with Tata (AS 4755).",
                created_at=now - timedelta(minutes=19),
            ),
            IncidentTimelineEntry(
                id=new_uuid(),
                incident_id=inc_resolved.id,
                org_id=org_id,
                author_user_id=sre_user.id,
                entry_type="resolution",
                content="Optic replaced and link validated clean at -4.2 dBm Rx power.",
                created_at=now - timedelta(hours=17, minutes=14),
            ),
        ]
    )

    alert_events_data = [
        (
            alert_rules["Device Unreachable (ICMP 100% Loss)"],
            devices["sin-app-01"],
            "firing",
            "critical",
            "sin-app-01 is unreachable (100% packet loss)",
            "ICMP probe to 10.30.10.21 failed for 2 consecutive intervals.",
            "icmp.packet_loss_pct",
            100.0,
            50.0,
            inc_active.id,
            now - timedelta(minutes=24),
            None,
        ),
        (
            alert_rules["BGP Peer Session Down / Flapping"],
            devices["sin-edge-rtr-01"],
            "acknowledged",
            "critical",
            "BGP peer 203.0.113.54 (AS 4755) is Active (down)",
            "Session flapped 6 times in 24h; 0 prefixes currently received.",
            "bgp.session_down",
            1.0,
            1.0,
            inc_active.id,
            now - timedelta(minutes=22),
            None,
        ),
        (
            alert_rules["High Device CPU Utilization"],
            devices["iad-db-01"],
            "firing",
            "critical",
            "iad-db-01 sustained CPU > 88% with high I/O wait",
            "PostgreSQL primary experiencing heavy checkpoint write load.",
            "snmp.cpu_pct",
            91.4,
            90.0,
            None,
            now - timedelta(minutes=14),
            None,
        ),
        (
            alert_rules["Interface Error Counter Burst"],
            devices["iad-dist-sw-02"],
            "firing",
            "warning",
            "iad-dist-sw-02 Ethernet1 input CRC errors elevated",
            "24 interface errors detected in latest polling interval.",
            "snmp.if_errors",
            24.0,
            20.0,
            None,
            now - timedelta(minutes=35),
            None,
        ),
        (
            alert_rules["High Memory Utilization"],
            devices["fra-app-01"],
            "resolved",
            "warning",
            "fra-app-01 memory utilization briefly exceeded 78%",
            "Auto-resolved after worker pool recycling.",
            "snmp.mem_pct",
            79.2,
            75.0,
            None,
            now - timedelta(hours=11),
            now - timedelta(hours=10, minutes=30),
        ),
    ]
    seeded_alerts: list[AlertEvent] = []
    for rule, dev, st, sev, title, msg, mname, mval, tval, inc_id, trig_at, res_at in alert_events_data:
        ev = AlertEvent(
            id=new_uuid(),
            org_id=org_id,
            rule_id=rule.id,
            device_id=dev.id,
            fingerprint=_sha256(f"{rule.id}:{dev.id}:{mname}")[:40],
            status=st,
            severity=sev,
            title=title,
            message=msg,
            metric_name=mname,
            metric_value=mval,
            threshold_value=tval,
            labels_json={"hostname": dev.hostname, "site_id": dev.site_id},
            triggered_at=trig_at,
            acknowledged_at=(trig_at + timedelta(minutes=5)) if st == "acknowledged" else None,
            acknowledged_by=netops_user.email if st == "acknowledged" else None,
            resolved_at=res_at,
            incident_id=inc_id,
        )
        seeded_alerts.append(ev)
        session.add(ev)
    session.flush()

    session.add(
        NotificationDelivery(
            id=new_uuid(),
            org_id=org_id,
            channel_id=ch_pd.id,
            alert_event_id=seeded_alerts[0].id,
            incident_id=inc_active.id,
            status="sent",
            attempts=1,
            response_code=202,
            sent_at=now - timedelta(minutes=23),
        )
    )

    session.add(
        MaintenanceWindow(
            id=new_uuid(),
            org_id=org_id,
            name="EU-Central Frankfurt FortiOS 7.4.6 Maintenance",
            description="Scheduled HA failover and firmware upgrade for fra-edge-fw-01",
            scope_device_ids_json=[devices["fra-edge-fw-01"].id],
            scope_site_ids_json=[site_eu.id],
            scope_tags_json=["eu-central", "firewall"],
            starts_at=now + timedelta(days=2, hours=2),
            ends_at=now + timedelta(days=2, hours=4),
            suppress_alerts=True,
            created_by_user_id=netops_user.id,
            is_active=True,
        )
    )

    slo_specs = [
        ("Global Core Backbone Availability", "availability", 99.99, 30, "avg(icmp.availability{tier='tier0'})", 99.994, 72.5, 0.4, "healthy"),
        ("Transatlantic WAN Latency (<95ms)", "latency", 99.5, 30, "p95(icmp.avg_rtt_ms{link='iad-fra'}) < 95", 99.78, 84.0, 0.25, "healthy"),
        ("Global API Synthetic Success Rate", "synthetic_success", 99.95, 30, "avg(synthetic.success{tier='prod'})", 99.91, 24.0, 2.1, "at_risk"),
    ]
    for sname, stype, target, wdays, query, cur, rem, burn, status in slo_specs:
        session.add(
            SloDefinition(
                id=new_uuid(),
                org_id=org_id,
                name=sname,
                description=f"30-day rolling {stype} SLO target {target}%",
                target_type=stype,
                target_pct=target,
                window_days=wdays,
                metric_query=query,
                current_sli_pct=cur,
                error_budget_remaining_pct=rem,
                burn_rate=burn,
                status=status,
            )
        )

    # ── 9. NCM Snapshots, Diff, CIS Compliance, Playbooks, Reports, Plugins ──
    snap_cisco_v1 = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["iad-core-rtr-01"].id,
        config_type="running",
        version_number=1,
        sha256_hash=_sha256(CISCO_IOSXR_BASE_CONFIG),
        content_text=CISCO_IOSXR_BASE_CONFIG,
        size_bytes=len(CISCO_IOSXR_BASE_CONFIG.encode("utf-8")),
        captured_by="netpulse-ncm",
        capture_method="ssh",
        has_drift=False,
        created_at=now - timedelta(days=2),
    )
    session.add(snap_cisco_v1)
    session.flush()

    snap_cisco_v2 = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["iad-core-rtr-01"].id,
        config_type="running",
        version_number=2,
        sha256_hash=_sha256(CISCO_IOSXR_UPDATED_CONFIG),
        content_text=CISCO_IOSXR_UPDATED_CONFIG,
        size_bytes=len(CISCO_IOSXR_UPDATED_CONFIG.encode("utf-8")),
        captured_by="netpulse-ncm",
        capture_method="ssh",
        has_drift=True,
        previous_snapshot_id=snap_cisco_v1.id,
        created_at=now - timedelta(hours=4),
    )
    snap_juniper = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["fra-core-rtr-01"].id,
        config_type="running",
        version_number=1,
        sha256_hash=_sha256(JUNIPER_JUNOS_CONFIG),
        content_text=JUNIPER_JUNOS_CONFIG,
        size_bytes=len(JUNIPER_JUNOS_CONFIG.encode("utf-8")),
        captured_by="netpulse-ncm",
        capture_method="netconf",
        has_drift=False,
    )
    snap_arista = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["iad-dist-sw-01"].id,
        config_type="running",
        version_number=1,
        sha256_hash=_sha256(ARISTA_EOS_CONFIG),
        content_text=ARISTA_EOS_CONFIG,
        size_bytes=len(ARISTA_EOS_CONFIG.encode("utf-8")),
        captured_by="netpulse-ncm",
        capture_method="ssh",
        has_drift=False,
    )
    snap_palo = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["iad-edge-fw-01"].id,
        config_type="running",
        version_number=1,
        sha256_hash=_sha256(PALO_ALTO_CONFIG),
        content_text=PALO_ALTO_CONFIG,
        size_bytes=len(PALO_ALTO_CONFIG.encode("utf-8")),
        captured_by="netpulse-ncm",
        capture_method="api",
        has_drift=False,
    )
    snap_linux = ConfigSnapshot(
        id=new_uuid(),
        org_id=org_id,
        device_id=devices["iad-db-01"].id,
        config_type="running",
        version_number=1,
        sha256_hash=_sha256(LINUX_DB_CONFIG),
        content_text=LINUX_DB_CONFIG,
        size_bytes=len(LINUX_DB_CONFIG.encode("utf-8")),
        captured_by="netpulse-agent",
        capture_method="ssh",
        has_drift=False,
    )
    session.add_all([snap_cisco_v2, snap_juniper, snap_arista, snap_palo, snap_linux])
    session.flush()

    session.add(
        ConfigDiff(
            id=new_uuid(),
            org_id=org_id,
            device_id=devices["iad-core-rtr-01"].id,
            base_snapshot_id=snap_cisco_v1.id,
            target_snapshot_id=snap_cisco_v2.id,
            lines_added=6,
            lines_removed=2,
            unified_diff=CISCO_UNIFIED_DIFF,
            severity_assessment="low",
            reviewed_by=netops_user.email,
            reviewed_at=now - timedelta(hours=3),
        )
    )

    pol_cisco = CompliancePolicy(
        id=new_uuid(),
        org_id=org_id,
        name="CIS Cisco IOS-XR Level 2 Hardening",
        framework="cis_benchmark",
        version="2.0.0",
        description="Validates SSHv2, AAA authentication, NTP synchronization, SNMPv3 AuthPriv, and syslog forwarding.",
        target_vendors_json=["cisco"],
        enabled=True,
        rules_json=[
            {"id": "CIS-1.1", "title": "Require SSHv2", "pattern": r"ssh server v2", "must_match": True, "severity": "critical"},
            {"id": "CIS-2.1", "title": "Require AAA Login", "pattern": r"aaa authentication login", "must_match": True, "severity": "high"},
            {"id": "CIS-3.1", "title": "Require SNMPv3 AuthPriv", "pattern": r"snmp-server group .* v3 priv", "must_match": True, "severity": "critical"},
            {"id": "CIS-4.1", "title": "Require Remote Syslog", "pattern": r"logging \d+\.\d+\.\d+\.\d+", "must_match": True, "severity": "medium"},
            {"id": "CIS-5.1", "title": "Forbid Telnet Server", "pattern": r"telnet ipv4 server", "must_match": False, "severity": "critical"},
        ],
    )
    pol_juniper = CompliancePolicy(
        id=new_uuid(),
        org_id=org_id,
        name="CIS Juniper JunOS Baseline",
        framework="cis_benchmark",
        version="1.5.0",
        description="Ensures root SSH login is denied, SSHv2 enforced, and NTP/syslog configured.",
        target_vendors_json=["juniper"],
        enabled=True,
        rules_json=[
            {"id": "JUN-1.1", "title": "Deny Root SSH Login", "pattern": r"root-login deny", "must_match": True, "severity": "critical"},
            {"id": "JUN-1.2", "title": "Enforce SSHv2", "pattern": r"protocol-version v2", "must_match": True, "severity": "high"},
            {"id": "JUN-2.1", "title": "Require NTP Server", "pattern": r"ntp\s*\{", "must_match": True, "severity": "medium"},
        ],
    )
    pol_linux = CompliancePolicy(
        id=new_uuid(),
        org_id=org_id,
        name="CIS Linux Network Kernel Hardening",
        framework="cis_benchmark",
        version="3.0.0",
        description="Checks TCP SYN cookies, reverse path filtering, disabled ICMP redirects, and SSH hardening.",
        target_vendors_json=["linux"],
        enabled=True,
        rules_json=[
            {"id": "LNX-3.1", "title": "Enable TCP SYN Cookies", "pattern": r"tcp_syncookies\s*=\s*1", "must_match": True, "severity": "high"},
            {"id": "LNX-3.2", "title": "Enable Reverse Path Filter", "pattern": r"rp_filter\s*=\s*1", "must_match": True, "severity": "medium"},
            {"id": "LNX-3.3", "title": "Disable ICMP Redirects", "pattern": r"accept_redirects\s*=\s*0", "must_match": True, "severity": "medium"},
        ],
    )
    session.add_all([pol_cisco, pol_juniper, pol_linux])
    session.flush()

    session.add_all(
        [
            ComplianceEvaluation(
                id=new_uuid(),
                org_id=org_id,
                policy_id=pol_cisco.id,
                device_id=devices["iad-core-rtr-01"].id,
                snapshot_id=snap_cisco_v2.id,
                status="compliant",
                score_pct=100.0,
                passed_count=5,
                failed_count=0,
                findings_json=[{"rule_id": "CIS-1.1", "passed": True}, {"rule_id": "CIS-3.1", "passed": True}],
                evaluated_at=now - timedelta(hours=2),
            ),
            ComplianceEvaluation(
                id=new_uuid(),
                org_id=org_id,
                policy_id=pol_juniper.id,
                device_id=devices["fra-core-rtr-01"].id,
                snapshot_id=snap_juniper.id,
                status="compliant",
                score_pct=100.0,
                passed_count=3,
                failed_count=0,
                findings_json=[{"rule_id": "JUN-1.1", "passed": True}],
                evaluated_at=now - timedelta(hours=2),
            ),
            ComplianceEvaluation(
                id=new_uuid(),
                org_id=org_id,
                policy_id=pol_linux.id,
                device_id=devices["iad-db-01"].id,
                snapshot_id=snap_linux.id,
                status="partial",
                score_pct=83.3,
                passed_count=2,
                failed_count=1,
                findings_json=[
                    {"rule_id": "LNX-3.1", "passed": True},
                    {"rule_id": "LNX-3.4", "passed": False, "detail": "net.ipv4.conf.all.log_martians is not explicitly enabled"},
                ],
                evaluated_at=now - timedelta(hours=1),
            ),
        ]
    )

    pb_bgp = PlaybookDefinition(
        id=new_uuid(),
        org_id=org_id,
        name="BGP Peer Diagnostics & Soft-Reset",
        description="Captures BGP neighbor state, route-table summary, and notifies Slack when a transit peer flaps.",
        trigger_type="alert",
        trigger_config_json={"metric_name": "bgp.session_down", "min_severity": "critical"},
        steps_json=[
            {"step": 1, "action": "collect_bgp_summary", "params": {"include_received_routes": False}},
            {"step": 2, "action": "run_traceroute", "params": {"count": 3}},
            {"step": 3, "action": "notify_channel", "params": {"channel": "Slack #netops-alerts"}},
        ],
        timeout_seconds=180,
        require_approval=False,
        enabled=True,
    )
    pb_cpu = PlaybookDefinition(
        id=new_uuid(),
        org_id=org_id,
        name="High-CPU Linux Diagnostics Bundle",
        description="Collects top processes, iostat, and PostgreSQL active query summary on high-CPU alert.",
        trigger_type="alert",
        trigger_config_json={"metric_name": "snmp.cpu_pct", "threshold_gte": 90.0},
        steps_json=[
            {"step": 1, "action": "ssh_command", "params": {"cmd": "ps aux --sort=-%cpu | head -n 15"}},
            {"step": 2, "action": "ssh_command", "params": {"cmd": "iostat -xz 1 3"}},
            {"step": 3, "action": "attach_incident_artifact", "params": {"format": "markdown"}},
        ],
        timeout_seconds=120,
        require_approval=False,
        enabled=True,
    )
    pb_if = PlaybookDefinition(
        id=new_uuid(),
        org_id=org_id,
        name="Interface Error Optical DOM Check & Quarantine",
        description="Inspects SFP+ DOM optical Rx/Tx levels and requests NetOps approval before err-disabling a noisy port.",
        trigger_type="manual",
        trigger_config_json={},
        steps_json=[
            {"step": 1, "action": "read_transceiver_dom", "params": {}},
            {"step": 2, "action": "backup_config_snapshot", "params": {}},
            {"step": 3, "action": "admin_shutdown_interface", "params": {"require_confirmation": True}},
        ],
        timeout_seconds=300,
        require_approval=True,
        enabled=True,
    )
    session.add_all([pb_bgp, pb_cpu, pb_if])
    session.flush()

    session.add(
        PlaybookRun(
            id=new_uuid(),
            org_id=org_id,
            playbook_id=pb_bgp.id,
            triggered_by="alert-engine",
            trigger_context_json={"device": "sin-edge-rtr-01", "peer_ip": "203.0.113.54", "peer_asn": 4755},
            status="succeeded",
            started_at=now - timedelta(minutes=21),
            completed_at=now - timedelta(minutes=20, seconds=42),
            duration_ms=18_240,
            step_results_json=[
                {"step": 1, "status": "ok", "output": "Peer 203.0.113.54 state=Active, last_error=Hold Timer Expired"},
                {"step": 2, "status": "ok", "output": "Traceroute halted at hop 2 (203.0.113.54)"},
                {"step": 3, "status": "ok", "output": "Posted diagnostic summary to #netops-alerts"},
            ],
        )
    )

    sched_weekly = ScheduledReport(
        id=new_uuid(),
        org_id=org_id,
        name="Weekly Executive Network Availability & SLA Digest",
        report_type="sla_executive",
        report_format="markdown",
        cron_expression="0 8 * * 1",
        recipients_json=["admin@netpulse.io", "netops@netpulse.io"],
        parameters_json={"period_days": 7, "include_slos": True, "include_incidents": True},
        enabled=True,
        last_run_at=now - timedelta(days=1),
        next_run_at=now + timedelta(days=6),
    )
    sched_comp = ScheduledReport(
        id=new_uuid(),
        org_id=org_id,
        name="Monthly CIS Benchmark Compliance Report",
        report_type="compliance_posture",
        report_format="pdf",
        cron_expression="0 6 1 * *",
        recipients_json=["admin@netpulse.io"],
        parameters_json={"framework": "cis_benchmark"},
        enabled=True,
        next_run_at=now + timedelta(days=7),
    )
    session.add_all([sched_weekly, sched_comp])
    session.flush()

    rep_md = (
        "# NetPulse Global Corp — Weekly Executive Network Digest\n\n"
        "- **Managed Devices**: 21 (17 Up, 1 Warning, 2 Degraded, 1 Down)\n"
        "- **Global Core Backbone Availability**: 99.994% (Target: 99.99%)\n"
        "- **Transatlantic WAN p95 Latency**: 82.4 ms (Target: <95 ms)\n"
        "- **CIS Compliance Score**: 94.4% across audited core & DB devices\n"
    )
    session.add(
        GeneratedReport(
            id=new_uuid(),
            org_id=org_id,
            scheduled_report_id=sched_weekly.id,
            name="Weekly Executive Network Digest — Nov 2026",
            report_format="markdown",
            period_start=now - timedelta(days=7),
            period_end=now,
            summary_json={"total_devices": 21, "backbone_availability_pct": 99.994, "compliance_pct": 94.4},
            content_text=rep_md,
            size_bytes=len(rep_md.encode("utf-8")),
            generated_by="scheduler",
        )
    )

    session.add_all(
        [
            PluginRegistration(
                id=new_uuid(),
                org_id=org_id,
                name="Cisco IOS-XR gNMI Streaming Collector",
                plugin_type="collector",
                version="1.4.0",
                entrypoint="netpulse_plugins.gnmi:CiscoGnmiCollector",
                config_schema_json={"port": {"type": "integer", "default": 57400}},
                config_values_json={"port": 57400, "sample_interval_ms": 10000},
                enabled=True,
                health_status="healthy",
            ),
            PluginRegistration(
                id=new_uuid(),
                org_id=org_id,
                name="ServiceNow CMDB Bi-Directional Sync",
                plugin_type="exporter",
                version="2.1.2",
                entrypoint="netpulse_plugins.servicenow:CmdbSyncPlugin",
                config_schema_json={"instance_url": {"type": "string"}},
                config_values_json={"instance_url": "https://netpulse.service-now.example.com", "sync_interval_min": 30},
                enabled=True,
                health_status="healthy",
            ),
        ]
    )

    session.add_all(
        [
            AuditLog(
                id=new_uuid(),
                org_id=org_id,
                actor_user_id=admin_user.id,
                actor_email=admin_user.email,
                action="settings_update",
                resource_type="organization",
                resource_id=org_id,
                summary="Initialized NetPulse Global Corp enterprise multi-site telemetry platform",
                ip_address="10.10.40.15",
            ),
            AuditLog(
                id=new_uuid(),
                org_id=org_id,
                actor_user_id=netops_user.id,
                actor_email=netops_user.email,
                action="config_diff",
                resource_type="device",
                resource_id=devices["iad-core-rtr-01"].id,
                summary="Reviewed IOS-XR IPFIX exporter & BGP max-prefix change on iad-core-rtr-01",
                ip_address="10.10.40.22",
            ),
        ]
    )

    session.flush()
    if commit:
        session.commit()

    return {
        "seeded": True,
        "org_id": org_id,
        "org_slug": org.slug,
        "admin_email": DEFAULT_ADMIN_EMAIL,
        "demo_api_key_prefix": DEFAULT_DEMO_API_KEY_PREFIX,
        "counts": {
            "sites": 3,
            "racks": len(racks),
            "devices": len(devices),
            "interfaces": sum(len(v) for v in interfaces_by_host.values()),
            "subnets": len(subnets_by_cidr),
            "vlans": len(vlans_spec),
            "topology_nodes": len(topo_nodes),
            "topology_links": len(link_specs),
            "snmp_samples": len(snmp_samples),
            "icmp_samples": len(icmp_samples),
            "host_samples": len(host_samples),
            "synthetic_results": len(probe_results),
            "metric_rollups": len(rollup_rows),
            "syslog_events": len(syslog_rows),
            "netflow_records": len(netflow_rows),
            "bgp_sessions": len(bgp_specs),
            "alert_rules": len(alert_rules),
            "alert_events": len(seeded_alerts),
            "incidents": 2,
            "slos": len(slo_specs),
            "config_snapshots": 6,
            "compliance_policies": 3,
            "playbooks": 3,
        },
    }


__all__ = [
    "DEFAULT_ADMIN_EMAIL",
    "DEFAULT_ADMIN_PASSWORD",
    "DEFAULT_DEMO_API_KEY",
    "DEFAULT_DEMO_API_KEY_PREFIX",
    "DEFAULT_ORG_SLUG",
    "seed_enterprise_demo",
]
