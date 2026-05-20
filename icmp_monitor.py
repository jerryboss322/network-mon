"""
icmp_monitor.py — Network Probe Module
Hybrid Network Monitoring Agent (SNMP + ICMP)

Uses TCP socket probing instead of raw ICMP ping so it works on cloud
platforms (Streamlit Cloud, Railway, Render, etc.) where ICMP is blocked.
Falls back gracefully: ConnectionRefused still means the host is alive.

Fix vs. original:
  - Alert auto-resolution: when a host recovers (loss drops below warning
    threshold), open alerts for that host are marked resolved so the alert
    log doesn't show stale problems.
  - Localhost port selection: avoids port 53 for loopback addresses since
    DNS is rarely running on localhost and refused-on-53 gives a misleadingly
    fast RTT that doesn't represent actual network conditions.
"""

import time
import socket
import threading
import statistics

import database
from config import HOSTS, ICMP_INTERVAL, ICMP_COUNT, ICMP_TIMEOUT, THRESHOLDS


# Ports tried in order per probe.
# - Port 53 (DNS/TCP) works well for 8.8.8.8 and 1.1.1.1.
# - Port 80 (HTTP) gives an instant ConnectionRefused on most hosts = valid RTT.
# - Port 443 (HTTPS) as second fallback for firewalled port 80.
PROBE_PORTS          = [53, 80, 443]
LOOPBACK_PROBE_PORTS = [80, 443, 8080]  # DNS not reliable on localhost


def _tcp_rtt(ip: str, port: int, timeout: float) -> float | None:
    """
    Attempt a TCP connection to ip:port and return RTT in ms.

    ConnectionRefused counts as a valid RTT — the host responded, the port
    just isn't open. OSError (timeout, network unreachable) returns None.
    """
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return round((time.perf_counter() - start) * 1000, 2)
    except ConnectionRefusedError:
        # Host replied with a RST — it's alive, port just isn't listening
        return round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        return None


def _pick_port(ip: str, timeout: float) -> int:
    """
    Return the first port that produces a response (connect or refused).
    Uses a loopback-specific port list for 127.x.x.x addresses to avoid
    misleading sub-millisecond RTTs from a local DNS service on port 53.
    """
    is_loopback = ip.startswith("127.") or ip == "::1"
    candidates  = LOOPBACK_PROBE_PORTS if is_loopback else PROBE_PORTS

    for port in candidates:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except ConnectionRefusedError:
            return port  # host is alive
        except OSError:
            continue

    return candidates[-1]  # fallback — use last candidate even if all failed


def probe_host(ip: str,
               count: int   = ICMP_COUNT,
               timeout: float = ICMP_TIMEOUT) -> dict:
    """Run `count` TCP probes against `ip` and return aggregated stats."""
    rtts:   list[float] = []
    failed: int         = 0
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
        "host":        ip,
        "avg_rtt":     avg_rtt,
        "min_rtt":     min_rtt,
        "max_rtt":     max_rtt,
        "packet_loss": packet_loss,
        "jitter":      jitter,
        "status":      status,
    }


def _check_alerts(result: dict) -> None:
    """
    Write alerts for threshold breaches and auto-resolve them when
    the host/metric returns to a healthy state.
    """
    ip   = result["host"]
    loss = result["packet_loss"]
    rtt  = result["avg_rtt"]

    # ── Packet loss alerts ────────────────────────────────────────────────────
    if loss >= THRESHOLDS["loss_critical"]:
        database.write_alert(ip, "Host Unavailable", "CRITICAL", loss,
                             THRESHOLDS["loss_critical"],
                             f"Packet loss {loss:.0f}% — host appears DOWN")
    elif loss >= THRESHOLDS["loss_warning"]:
        # Critical has cleared — resolve it if it was open
        database.resolve_alert(ip, "Host Unavailable")
        database.write_alert(ip, "High Packet Loss", "WARNING", loss,
                             THRESHOLDS["loss_warning"],
                             f"Packet loss {loss:.0f}% exceeds warning threshold")
    else:
        # All clear — resolve any open packet-loss alerts
        database.resolve_alert(ip, "Host Unavailable")
        database.resolve_alert(ip, "High Packet Loss")

    # ── RTT / latency alerts ──────────────────────────────────────────────────
    if rtt is not None:
        if rtt >= THRESHOLDS["rtt_critical"]:
            database.write_alert(ip, "High Latency", "CRITICAL", rtt,
                                 THRESHOLDS["rtt_critical"],
                                 f"RTT {rtt}ms exceeds critical threshold")
        elif rtt >= THRESHOLDS["rtt_warning"]:
            database.resolve_alert(ip, "High Latency")
            database.write_alert(ip, "High Latency", "WARNING", rtt,
                                 THRESHOLDS["rtt_warning"],
                                 f"RTT {rtt}ms exceeds warning threshold")
        else:
            # Latency is fine — resolve any open RTT alert
            database.resolve_alert(ip, "High Latency")


def _probe_loop() -> None:
    """Continuously probe all hosts in a tight loop, sleeping between rounds."""
    while True:
        for host in HOSTS:
            ip    = host["ip"]
            label = host.get("label", ip)

            result = probe_host(ip)

            database.write_icmp(
                ip,
                result["avg_rtt"],
                result["min_rtt"],
                result["max_rtt"],
                result["packet_loss"],
                result["jitter"],
                result["status"],
            )
            _check_alerts(result)

            status_icon = (
                "OK      " if result["status"] == "Up"       else
                "DEGRADE " if result["status"] == "Degraded" else
                "DOWN    "
            )
            print(
                f"[PROBE] {status_icon} {label} ({ip})  "
                f"RTT:{result['avg_rtt']}ms  "
                f"Loss:{result['packet_loss']}%  "
                f"Status:{result['status']}"
            )

        time.sleep(ICMP_INTERVAL)


def start() -> threading.Thread:
    """Start the TCP probe loop in a background daemon thread."""
    t = threading.Thread(target=_probe_loop, name="icmp-prober", daemon=True)
    t.start()
    print("[PROBE] TCP probe thread started (cloud-safe, no raw ICMP needed).")
    return t
