"""
snmp_monitor.py — SNMP Polling Module
Hybrid Network Monitoring Agent (SNMP + ICMP)

Supports two modes:
  SIMULATE = True  -> generates realistic synthetic metrics (no real SNMP needed)
  SIMULATE = False -> queries real devices using pysnmp (SNMPv2c)

Key fix vs. original:
  ifInOctets / ifOutOctets are 32-bit WRAPPING counters. The original code
  divided the raw counter value by SNMP_INTERVAL — this gives a meaningless
  number. The correct method is to store the previous counter reading and
  compute the delta, handling 32-bit wrap-around (counter resets to 0 after
  4,294,967,295 bytes). This is implemented in _compute_mbps() below.
"""

import time
import random
import threading
import datetime

import database
from config import HOSTS, SNMP_INTERVAL, THRESHOLDS, SIMULATE

# ── OID definitions (MIB-II + Host Resources MIB) ────────────────────────────
OIDS = {
    "cpu":       "1.3.6.1.2.1.25.3.3.1.2.1",   # hrProcessorLoad (integer %)
    "mem_total": "1.3.6.1.2.1.25.2.3.1.5.1",   # hrStorageSize (allocation units)
    "mem_used":  "1.3.6.1.2.1.25.2.3.1.6.1",   # hrStorageUsed (allocation units)
    "if_in":     "1.3.6.1.2.1.2.2.1.10.1",     # ifInOctets (cumulative 32-bit counter)
    "if_out":    "1.3.6.1.2.1.2.2.1.16.1",     # ifOutOctets (cumulative 32-bit counter)
    "if_errors": "1.3.6.1.2.1.2.2.1.14.1",     # ifInErrors
    "uptime":    "1.3.6.1.2.1.1.3.0",          # sysUpTime (TimeTicks, 1/100 seconds)
}

# Maximum value of a 32-bit SNMP counter before it wraps back to 0
COUNTER32_MAX = 4_294_967_295

# ── Simulation state (keeps values realistic across poll cycles) ──────────────
_sim_state: dict = {}

def _init_sim_state(ip: str) -> None:
    """Initialise smooth random baseline values for a simulated host."""
    _sim_state[ip] = {
        "cpu":      random.uniform(20, 50),
        "mem_pct":  random.uniform(30, 60),
        "if_in":    random.uniform(1, 10),
        "if_out":   random.uniform(0.5, 5),
        "errors":   0,
        "uptime_s": 0,
    }

def _step_sim(ip: str) -> dict:
    """Advance simulated metrics by one small random step (random walk)."""
    s = _sim_state[ip]
    s["cpu"]     = max(0.0, min(100.0, s["cpu"]     + random.uniform(-5,   5)))
    s["mem_pct"] = max(0.0, min(100.0, s["mem_pct"] + random.uniform(-2,   2)))
    s["if_in"]   = max(0.0,            s["if_in"]   + random.uniform(-1,   1))
    s["if_out"]  = max(0.0,            s["if_out"]  + random.uniform(-0.5, 0.5))
    s["errors"]  = max(0,   int(       s["errors"]  + random.uniform(-1,   1.5)))
    s["uptime_s"] += SNMP_INTERVAL
    return s


# ── Counter delta helper ──────────────────────────────────────────────────────

# Stores the last raw counter values per host so we can compute deltas.
# Structure: { ip: { "if_in": int, "if_out": int } }
_last_counters: dict = {}

def _compute_mbps(ip: str, raw_in: int, raw_out: int) -> tuple[float, float]:
    """
    Compute interface throughput in Mbps by diffing the current counter
    against the previous reading. Handles 32-bit counter wrap-around.

    Returns (in_mbps, out_mbps). Returns (0.0, 0.0) on the first call
    for a given host (no previous reading to diff against yet).
    """
    prev = _last_counters.get(ip)

    # Save current counters for next cycle before returning
    _last_counters[ip] = {"if_in": raw_in, "if_out": raw_out}

    if prev is None:
        # First poll — no delta available yet
        return 0.0, 0.0

    def _delta(current: int, previous: int) -> int:
        """Handle 32-bit counter wrap-around."""
        if current >= previous:
            return current - previous
        # Counter wrapped — add the remaining space before wrap + new value
        return (COUNTER32_MAX - previous) + current + 1

    delta_in  = _delta(raw_in,  prev["if_in"])
    delta_out = _delta(raw_out, prev["if_out"])

    # Convert bytes/interval to Megabits/second
    in_mbps  = round((delta_in  * 8) / 1_000_000 / SNMP_INTERVAL, 3)
    out_mbps = round((delta_out * 8) / 1_000_000 / SNMP_INTERVAL, 3)

    return in_mbps, out_mbps


# ── Real SNMP polling ─────────────────────────────────────────────────────────

def _poll_real(host_cfg: dict) -> dict | None:
    """
    Query a real SNMP agent and return a metrics dict, or None on failure.

    Uses SNMPv2c (community string auth). Each OID is fetched with a
    separate GetRequest — this is less efficient than a single GetBulk
    but is maximally compatible with consumer routers.
    """
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData,
            UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity,
        )
    except ImportError:
        print("[SNMP] ERROR: pysnmp is not installed.")
        print("[SNMP]        Run:  pip install pysnmp")
        return None

    ip        = host_cfg["ip"]
    community = host_cfg.get("community", "public")
    port      = host_cfg.get("snmp_port", 161)
    raw: dict = {}

    for name, oid in OIDS.items():
        error_indication, error_status, _, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),  # mpModel=1 -> SNMPv2c
                UdpTransportTarget((ip, port), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )

        if error_indication:
            # Transport-level failure (timeout, refused, etc.)
            print(f"[SNMP] Transport error for {ip} OID {name}: {error_indication}")
            continue
        if error_status:
            # SNMP protocol-level error (noSuchObject, etc.) — not a hard failure
            print(f"[SNMP] Protocol error for {ip} OID {name}: {error_status.prettyPrint()}")
            continue

        raw[name] = var_binds[0][1]

    if not raw:
        # No OIDs responded — device is unreachable or SNMP is disabled
        return None

    # ── Compute memory percentage ─────────────────────────────────────────────
    mem_total = int(raw.get("mem_total", 1) or 1)
    mem_used  = int(raw.get("mem_used",  0) or 0)
    mem_pct   = round((mem_used / mem_total * 100) if mem_total else 0.0, 1)

    # ── Compute interface throughput with proper delta math ───────────────────
    raw_in  = int(raw.get("if_in",  0) or 0)
    raw_out = int(raw.get("if_out", 0) or 0)
    if_in_mbps, if_out_mbps = _compute_mbps(ip, raw_in, raw_out)

    # ── Parse sysUpTime (TimeTicks = 1/100 seconds) ───────────────────────────
    raw_uptime = raw.get("uptime")
    if raw_uptime is not None:
        total_seconds = int(raw_uptime) // 100
        uptime_str = str(datetime.timedelta(seconds=total_seconds))
    else:
        uptime_str = "N/A"

    return {
        "cpu_pct":     float(raw.get("cpu", 0) or 0),
        "mem_pct":     mem_pct,
        "if_in_mbps":  if_in_mbps,
        "if_out_mbps": if_out_mbps,
        "if_errors":   int(raw.get("if_errors", 0) or 0),
        "sys_uptime":  uptime_str,
        "reachable":   1,
    }


# ── Alert evaluation ──────────────────────────────────────────────────────────

def _check_alerts(ip: str, metrics: dict) -> None:
    """Write threshold breach alerts. Deduplication is handled in database.py."""
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

def _poll_loop() -> None:
    # Initialise simulation state for all SNMP-enabled hosts upfront
    for h in HOSTS:
        if h.get("snmp"):
            _init_sim_state(h["ip"])

    while True:
        for host in HOSTS:
            if not host.get("snmp"):
                continue

            ip = host["ip"]

            if SIMULATE:
                s = _step_sim(ip)
                uptime_str = str(datetime.timedelta(seconds=int(s["uptime_s"])))
                metrics = {
                    "cpu_pct":     round(s["cpu"],     1),
                    "mem_pct":     round(s["mem_pct"], 1),
                    "if_in_mbps":  round(s["if_in"],   2),
                    "if_out_mbps": round(s["if_out"],  2),
                    "if_errors":   s["errors"],
                    "sys_uptime":  uptime_str,
                    "reachable":   1,
                }
            else:
                metrics = _poll_real(host)
                if metrics is None:
                    # Device did not respond — record as unreachable
                    database.write_snmp(ip, None, None, None, None,
                                        None, "N/A", reachable=0)
                    database.write_alert(ip, "SNMP Unreachable", "CRITICAL",
                                         0, 1,
                                         "Host did not respond to SNMP query")
                    print(f"[SNMP] UNREACHABLE  {ip}")
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
            print(
                f"[SNMP] OK  {ip}  "
                f"CPU:{metrics['cpu_pct']}%  "
                f"MEM:{metrics['mem_pct']}%  "
                f"IN:{metrics['if_in_mbps']}Mbps  "
                f"OUT:{metrics['if_out_mbps']}Mbps"
            )

        time.sleep(SNMP_INTERVAL)


def start() -> threading.Thread:
    """Start the SNMP polling loop in a background daemon thread."""
    t = threading.Thread(target=_poll_loop, name="snmp-poller", daemon=True)
    t.start()
    print("[SNMP] Polling thread started.")
    return t
