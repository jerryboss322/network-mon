"""
config.py — Central configuration for the Hybrid Network Monitoring Agent
"""

# ── Hosts to monitor ──────────────────────────────────────────────────────────
# On Streamlit Cloud, only public internet IPs are reachable.
# Local IPs like 192.168.x.x will always show Down — remove them.
HOSTS = [
    {
        "ip": "8.8.8.8",
        "label": "Google DNS",
        "snmp": False,
    },
    {
        "ip": "1.1.1.1",
        "label": "Cloudflare DNS",
        "snmp": False,
    },
    {
        "ip": "8.8.4.4",
        "label": "Google DNS 2",
        "snmp": False,
    },
]

# ── Polling intervals ────────────────────────────────────────────────────────
SNMP_INTERVAL  = 60
ICMP_INTERVAL  = 30
ICMP_COUNT     = 4
ICMP_TIMEOUT   = 2

# ── Alert thresholds ─────────────────────────────────────────────────────────
THRESHOLDS = {
    "cpu_warning":    70.0,
    "cpu_critical":   90.0,
    "mem_warning":    75.0,
    "mem_critical":   90.0,
    "rtt_warning":   300.0,   # raised — Streamlit Cloud servers have higher baseline RTT
    "rtt_critical":  800.0,
    "loss_warning":   10.0,
    "loss_critical":  50.0,
    "errors_warning":  5,
    "errors_critical": 20,
}

# ── Dashboard settings ───────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECS = 30
MAX_CHART_POINTS       = 200

# ── Simulation mode ──────────────────────────────────────────────────────────
SIMULATE = False

# ── Database path ────────────────────────────────────────────────────────────
DB_PATH = "network_monitor.db"
