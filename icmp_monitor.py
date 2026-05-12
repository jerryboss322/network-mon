"""
icmp_monitor.py — Network Probe Module
Hybrid Network Monitoring Agent (SNMP + ICMP)

Uses TCP socket probing instead of raw ICMP ping so it works on cloud
platforms (Streamlit Cloud, Railway, Render, etc.) where ICMP is blocked.
Falls back gracefully: ConnectionRefused still means the host is alive.
"""

import time
import socket
import threading
import statistics

import database
from config import HOSTS, ICMP_INTERVAL, ICMP_COUNT, ICMP_TIMEOUT, THRESHOLDS


# Ports tried in order per probe. DNS/TCP (53) works great for 8.8.8.8 / 1.1.1.1.
# For localhost, port 80 gives an instant "Connection Refused" which is a valid RTT.
PROBE_PORTS = [53, 443, 80]


def _tcp_rtt(ip: str, port: int, timeout: float):
    """Connect to ip:port and return RTT in ms, or None if unreachable."""
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return round((time.perf_counter() - start) * 1000, 2)
    except ConnectionRefusedError:
        # Port refused but host replied → valid RTT
        return round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        return None


def _pick_port(ip: str, timeout: float) -> int:
    """Return the first responsive port, or fallback to port 80."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except ConnectionRefusedError:
            return port
        except OSError:
            continue
    return PROBE_PORTS[-1]


def probe_host(ip: str, count: int = ICMP_COUNT, timeout: float = ICMP_TIMEOUT) -> dict:
    rtts = []
    failed = 0
    port = _pick_port(ip, timeout)

    for _ in range(count):
        rtt = _tcp_rtt(ip, port, timeout)
        if rtt is not None:
            rtts.append(rtt)
        else:
            failed += 1

    packet_loss = round((failed / count) * 100, 1)

    if rtts:
        avg_rtt = round(statistics.mean(rtts), 2)
        min_rtt = round(min(rtts), 2)
        max_rtt = round(max(rtts), 2)
        jitter  = round(statistics.stdev(rtts), 2) if len(rtts) > 1 else 0.0
    else:
        avg_rtt = min_rtt = max_rtt = jitter = None

    if packet_loss >= 100:
        status = "Down"
    elif packet_loss >= THRESHOLDS["loss_warning"]:
        status = "Degraded"
    else:
        status = "Up"

    return {
        "host": ip, "avg_rtt": avg_rtt, "min_rtt": min_rtt,
        "max_rtt": max_rtt, "packet_loss": packet_loss,
        "jitter": jitter, "status": status,
    }


def _down_result(ip: str) -> dict:
    return {
        "host": ip, "avg_rtt": None, "min_rtt": None,
        "max_rtt": None, "packet_loss": 100.0,
        "jitter": None, "status": "Down",
    }


def _check_alerts(result: dict):
    ip   = result["host"]
    loss = result["packet_loss"]
    rtt  = result["avg_rtt"]

    if loss >= THRESHOLDS["loss_critical"]:
        database.write_alert(ip, "Host Unavailable", "CRITICAL", loss,
                             THRESHOLDS["loss_critical"],
                             f"Packet loss {loss:.0f}% — host is DOWN")
    elif loss >= THRESHOLDS["loss_warning"]:
        database.write_alert(ip, "High Packet Loss", "WARNING", loss,
                             THRESHOLDS["loss_warning"],
                             f"Packet loss {loss:.0f}% exceeds warning threshold")
    if rtt is not None:
        if rtt >= THRESHOLDS["rtt_critical"]:
            database.write_alert(ip, "High Latency", "CRITICAL", rtt,
                                 THRESHOLDS["rtt_critical"],
                                 f"RTT {rtt}ms exceeds critical threshold")
        elif rtt >= THRESHOLDS["rtt_warning"]:
            database.write_alert(ip, "High Latency", "WARNING", rtt,
                                 THRESHOLDS["rtt_warning"],
                                 f"RTT {rtt}ms exceeds warning threshold")


def _probe_loop():
    while True:
        for host in HOSTS:
            ip    = host["ip"]
            label = host.get("label", ip)
            result = probe_host(ip)

            database.write_icmp(
                ip,
                result["avg_rtt"], result["min_rtt"], result["max_rtt"],
                result["packet_loss"], result["jitter"], result["status"],
            )
            _check_alerts(result)

            icon = "✓" if result["status"] == "Up" else (
                   "⚠" if result["status"] == "Degraded" else "✗")
            print(f"[PROBE] {icon} {label} ({ip}) — "
                  f"RTT:{result['avg_rtt']}ms  "
                  f"Loss:{result['packet_loss']}%  "
                  f"Status:{result['status']}")

        time.sleep(ICMP_INTERVAL)


def start():
    """Start the TCP probe loop in a background daemon thread."""
    t = threading.Thread(target=_probe_loop, name="icmp-prober", daemon=True)
    t.start()
    print("[PROBE] TCP probe thread started (cloud-safe, no raw ICMP needed).")
    return t
