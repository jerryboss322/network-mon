"""
snmp_monitor.py — SNMP Polling Module
Hybrid Network Monitoring Agent (SNMP + ICMP)

Supports two modes:
  SIMULATE = True  → generates realistic synthetic metrics (no real SNMP needed)
  SIMULATE = False → queries real devices using pysnmp (SNMPv2c)
"""

import time
import random
import threading
import datetime

import database
from config import HOSTS, SNMP_INTERVAL, THRESHOLDS, SIMULATE

# ── OID definitions (MIB-II + Host Resources MIB) ────────────────────────────
OIDS = {
    "cpu":       "1.3.6.1.2.1.25.3.3.1.2.1",   # hrProcessorLoad
    "mem_total": "1.3.6.1.2.1.25.2.3.1.5.1",   # hrStorageSize
    "mem_used":  "1.3.6.1.2.1.25.2.3.1.6.1",   # hrStorageUsed
    "if_in":     "1.3.6.1.2.1.2.2.1.10.1",     # ifInOctets
    "if_out":    "1.3.6.1.2.1.2.2.1.16.1",     # ifOutOctets
    "if_errors": "1.3.6.1.2.1.2.2.1.14.1",     # ifInErrors
    "uptime":    "1.3.6.1.2.1.1.3.0",          # sysUpTime
}

# ── Simulation state (keeps values realistic across poll cycles) ──────────────
_sim_state = {}

def _init_sim_state(ip):
    """Initialise smooth random baseline values for a simulated host."""
    _sim_state[ip] = {
        "cpu":      random.uniform(20, 50),
        "mem_pct":  random.uniform(30, 60),
        "if_in":    random.uniform(1, 10),
        "if_out":   random.uniform(0.5, 5),
        "errors":   0,
        "uptime_s": 0,
    }

def _step_sim(ip):
    """Advance simulated metrics by one small random step (random walk)."""
    s = _sim_state[ip]
    s["cpu"]     = max(0, min(100, s["cpu"]     + random.uniform(-5, 5)))
    s["mem_pct"] = max(0, min(100, s["mem_pct"] + random.uniform(-2, 2)))
    s["if_in"]   = max(0,          s["if_in"]   + random.uniform(-1, 1))
    s["if_out"]  = max(0,          s["if_out"]  + random.uniform(-0.5, 0.5))
    s["errors"]  = max(0, int(     s["errors"]  + random.uniform(-1, 1.5)))
    s["uptime_s"] += SNMP_INTERVAL
    return s


# ── Real SNMP polling (requires pysnmp) ───────────────────────────────────────
def _poll_real(host_cfg):
    """Query a real SNMP agent and return a metrics dict or None on failure."""
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData,
            UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity,
        )
    except ImportError:
        print("[SNMP] pysnmp not installed — falling back to simulation mode.")
        return None

    ip        = host_cfg["ip"]
    community = host_cfg.get("community", "public")
    port      = host_cfg.get("snmp_port", 161)
    raw       = {}

    for name, oid in OIDS.items():
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),           # mpModel=1 → v2c
            UdpTransportTarget((ip, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        errInd, errStat, _, varBinds = next(iterator)
        if not errInd and not errStat:
            raw[name] = varBinds[0][1]

    if not raw:
        return None

    mem_total = int(raw.get("mem_total", 1) or 1)
    mem_used  = int(raw.get("mem_used",  0) or 0)
    mem_pct   = (mem_used / mem_total * 100) if mem_total else 0

    # ifInOctets / ifOutOctets are cumulative counters → convert to Mbps
    # (simplified: treat delta as bytes since last poll / interval)
    if_in_mbps  = (int(raw.get("if_in",  0) or 0) * 8 / 1_000_000) / SNMP_INTERVAL
    if_out_mbps = (int(raw.get("if_out", 0) or 0) * 8 / 1_000_000) / SNMP_INTERVAL

    return {
        "cpu_pct":     float(raw.get("cpu", 0) or 0),
        "mem_pct":     mem_pct,
        "if_in_mbps":  if_in_mbps,
        "if_out_mbps": if_out_mbps,
        "if_errors":   int(raw.get("if_errors", 0) or 0),
        "sys_uptime":  str(raw.get("uptime", "N/A")),
        "reachable":   1,
    }


# ── Alert evaluation ──────────────────────────────────────────────────────────
def _check_alerts(ip, metrics):
    cpu  = metrics.get("cpu_pct")
    mem  = metrics.get("mem_pct")
    errs = metrics.get("if_errors", 0)

    if cpu is not None:
        if cpu >= THRESHOLDS["cpu_critical"]:
            database.write_alert(ip, "High CPU", "CRITICAL", cpu,
                                 THRESHOLDS["cpu_critical"],
                                 f"CPU at {cpu:.1f}% exceeds critical threshold")
        elif cpu >= THRESHOLDS["cpu_warning"]:
            database.write_alert(ip, "High CPU", "WARNING", cpu,
                                 THRESHOLDS["cpu_warning"],
                                 f"CPU at {cpu:.1f}% exceeds warning threshold")

    if mem is not None:
        if mem >= THRESHOLDS["mem_critical"]:
            database.write_alert(ip, "High Memory", "CRITICAL", mem,
                                 THRESHOLDS["mem_critical"],
                                 f"Memory at {mem:.1f}% exceeds critical threshold")
        elif mem >= THRESHOLDS["mem_warning"]:
            database.write_alert(ip, "High Memory", "WARNING", mem,
                                 THRESHOLDS["mem_warning"],
                                 f"Memory at {mem:.1f}% exceeds warning threshold")

    if errs >= THRESHOLDS["errors_critical"]:
        database.write_alert(ip, "Interface Errors", "CRITICAL", errs,
                             THRESHOLDS["errors_critical"],
                             f"{errs} interface errors detected")
    elif errs >= THRESHOLDS["errors_warning"]:
        database.write_alert(ip, "Interface Errors", "WARNING", errs,
                             THRESHOLDS["errors_warning"],
                             f"{errs} interface errors detected")


# ── Main polling loop ─────────────────────────────────────────────────────────
def _poll_loop():
    # Initialise simulation state for all SNMP-enabled hosts
    for h in HOSTS:
        if h["snmp"]:
            _init_sim_state(h["ip"])

    while True:
        for host in HOSTS:
            if not host["snmp"]:
                continue

            ip = host["ip"]

            if SIMULATE:
                s = _step_sim(ip)
                uptime_str = str(datetime.timedelta(seconds=int(s["uptime_s"])))
                metrics = {
                    "cpu_pct":     round(s["cpu"],    1),
                    "mem_pct":     round(s["mem_pct"], 1),
                    "if_in_mbps":  round(s["if_in"],  2),
                    "if_out_mbps": round(s["if_out"],  2),
                    "if_errors":   s["errors"],
                    "sys_uptime":  uptime_str,
                    "reachable":   1,
                }
            else:
                metrics = _poll_real(host)
                if metrics is None:
                    # Record an unreachable row
                    database.write_snmp(ip, None, None, None, None,
                                        None, "N/A", reachable=0)
                    database.write_alert(ip, "SNMP Unreachable", "CRITICAL",
                                         0, 1,
                                         "Host did not respond to SNMP query")
                    print(f"[SNMP] ✗ {ip} — unreachable")
                    continue

            database.write_snmp(
                ip,
                metrics["cpu_pct"],
                metrics["mem_pct"],
                metrics["if_in_mbps"],
                metrics["if_out_mbps"],
                metrics["if_errors"],
                metrics["sys_uptime"],
                metrics["reachable"],
            )
            _check_alerts(ip, metrics)
            print(f"[SNMP] ✓ {ip} — CPU:{metrics['cpu_pct']}%  "
                  f"MEM:{metrics['mem_pct']}%  "
                  f"IN:{metrics['if_in_mbps']}Mbps  "
                  f"OUT:{metrics['if_out_mbps']}Mbps")

        time.sleep(SNMP_INTERVAL)


def start():
    """Start the SNMP polling loop in a background daemon thread."""
    t = threading.Thread(target=_poll_loop, name="snmp-poller", daemon=True)
    t.start()
    print("[SNMP] Polling thread started.")
    return t
