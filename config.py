"""
config.py — Central configuration for the Hybrid Network Monitoring Agent
Edit this file to add/remove hosts and adjust thresholds.
"""

# ── Hosts to monitor ──────────────────────────────────────────────────────────
# Each entry is a dict with keys:
#   ip          : IP address or hostname to probe
#   label       : Friendly display name
#   snmp        : True if SNMP polling should be attempted for this host
#   community   : SNMPv2c community string (ignored when snmp=False)
#   snmp_port   : UDP port for SNMP (default 161)
#
# For a real network, replace these with actual device IPs.
# For simulation/demo mode, the SNMP module will generate synthetic data.

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
        "community": "public",
        "snmp_port": 161,
    },
    {
        "ip": "1.1.1.1",
        "label": "Cloudflare DNS (ICMP only)",
        "snmp": False,
        "community": "public",
        "snmp_port": 161,
    },
]

# ── Polling intervals (seconds) ───────────────────────────────────────────────
SNMP_INTERVAL  = 60   # How often to run an SNMP poll cycle
ICMP_INTERVAL  = 30   # How often to run an ICMP probe cycle
ICMP_COUNT     = 4    # Number of pings per probe cycle
ICMP_TIMEOUT   = 2    # Seconds to wait for each ping reply

# ── Alert thresholds ──────────────────────────────────────────────────────────
THRESHOLDS = {
    "cpu_warning":       70.0,   # %
    "cpu_critical":      90.0,   # %
    "mem_warning":       75.0,   # %
    "mem_critical":      90.0,   # %
    "rtt_warning":      100.0,   # ms
    "rtt_critical":     500.0,   # ms
    "loss_warning":      10.0,   # %
    "loss_critical":     50.0,   # %
    "errors_warning":     5,     # absolute error count per poll
    "errors_critical":   20,
}

# ── Dashboard settings ────────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECS = 30   # How often the Streamlit page auto-refreshes
MAX_CHART_POINTS       = 200  # How many data points to show on each chart

# ── Simulation mode ───────────────────────────────────────────────────────────
# When SIMULATE = True the SNMP module generates realistic fake data instead
# of querying real devices.  Set to False when targeting real SNMP agents.
SIMULATE = True
