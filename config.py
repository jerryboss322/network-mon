"""
config.py — Central configuration for the Hybrid Network Monitoring Agent
"""

# ── Hosts to monitor ──────────────────────────────────────────────────────────
HOSTS = [
    {
        "ip": "127.0.0.1",
        "label": "Localhost / Router-Sim",
        "snmp": True,
        "community": "public",
        "snmp_port": 161,
    },
    {
        "ip": "8.8.8.8",
        "label": "Google DNS (ICMP only)",
        "snmp": False,
    },
    {
        "ip": "1.1.1.1",
        "label": "Cloudflare DNS (ICMP only)",
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
    "cpu_warning": 70.0, "cpu_critical": 90.0,
    "mem_warning": 75.0, "mem_critical": 90.0,
    "rtt_warning": 100.0, "rtt_critical": 500.0,
    "loss_warning": 10.0, "loss_critical": 50.0,
    "errors_warning": 5, "errors_critical": 20,
}

# ── Dashboard settings ───────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECS = 30
MAX_CHART_POINTS       = 200

# ── Simulation mode ──────────────────────────────────────────────────────────
SIMULATE = True

# ── Database path ────────────────────────────────────────────────────────────
DB_PATH = "network_monitor.db"
