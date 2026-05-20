"""
config.py — Central configuration for the Hybrid Network Monitoring Agent

HOW TO GO REAL:
  1. Set SIMULATE = False
  2. Update HOSTS with your actual device IPs
  3. For SNMP hosts, enable SNMP on the device (usually under router admin > Advanced > SNMP)
  4. Run:  python main.py   (Terminal 1)
          streamlit run dashboard.py  (Terminal 2)
"""

# ── Hosts to monitor ──────────────────────────────────────────────────────────
# To find your router IP: run `ipconfig` (Windows) or `ip route` (Linux/Mac)
# Look for "Default Gateway" — typically 192.168.1.1 or 192.168.0.1
HOSTS = [
    # --- SNMP-enabled host (your router) ---
    # Uncomment and set to your real router IP once SNMP is enabled on it.
     {
        "ip": "192.168.20.1",
         "label": "Home Router",
         "snmp": True,
         "community": "public",   # match whatever you set in the router admin
         "snmp_port": 161,
     },

    # --- ICMP-only hosts (no SNMP needed) ---
    # These work immediately — no device configuration required.
    {
        "ip": "8.8.8.8",
        "label": "Google DNS",
        "snmp": False,
      "community": "public",      # whatever community string you set
        "snmp_port": 161,
    },
    {
        "ip": "1.1.1.1",
        "label": "Cloudflare DNS",
        "snmp": False,
      "community": "public",      # whatever community string you set
        "snmp_port": 161,
    },
    # Add any device on your local network here (phone, PC, printer, etc.)
    # Find device IPs with:  arp -a  (Windows) or  arp-scan -l  (Linux)
    # Example:
    # {
    #     "ip": "192.168.1.45",
    #     "label": "My Phone",
    #     "snmp": False,
    # },
]

# ── Polling intervals ────────────────────────────────────────────────────────
SNMP_INTERVAL  = 60   # seconds between SNMP polls
ICMP_INTERVAL  = 30   # seconds between ICMP probe rounds
ICMP_COUNT     = 4    # TCP probes per host per round
ICMP_TIMEOUT   = 2    # seconds before a probe is counted as lost

# ── Alert thresholds ─────────────────────────────────────────────────────────
THRESHOLDS = {
    "cpu_warning":    70.0,
    "cpu_critical":   90.0,
    "mem_warning":    75.0,
    "mem_critical":   90.0,
    "rtt_warning":   100.0,   # ms
    "rtt_critical":  500.0,   # ms
    "loss_warning":   10.0,   # %
    "loss_critical":  50.0,   # %
    "errors_warning":  5,
    "errors_critical": 20,
}

# ── Dashboard settings ───────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECS = 30
MAX_CHART_POINTS       = 200

# ── Simulation mode ──────────────────────────────────────────────────────────
# True  → generates realistic synthetic data (no real devices needed, great for demos)
# False → queries real devices using pysnmp and TCP probes
SIMULATE = False

# ── Database path ────────────────────────────────────────────────────────────
DB_PATH = "network_monitor.db"
