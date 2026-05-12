# Hybrid Network Monitoring Agent — SNMP + ICMP
### Undergraduate Project | Computer Science

---

## What This System Does

This agent monitors network devices using **two complementary protocols**:

| Protocol | What it measures |
|----------|-----------------|
| **SNMP** | CPU %, Memory %, Interface traffic (Mbps), Interface errors |
| **ICMP** | Host availability (Up/Down/Degraded), Latency (RTT), Packet loss, Jitter |

Collected data is stored in a local SQLite database and displayed on a
real-time Streamlit web dashboard that auto-refreshes every 30 seconds.

---

## Project File Structure

```
network_monitor/
├── main.py          ← Run this first  (starts SNMP + ICMP threads)
├── dashboard.py     ← Run this second (opens the web dashboard)
├── snmp_monitor.py  ← SNMP polling module
├── icmp_monitor.py  ← ICMP probe module
├── database.py      ← SQLite database helper functions
├── config.py        ← ALL settings: hosts, intervals, thresholds
├── requirements.txt ← Python package dependencies
└── README.md        ← This file
```

---

## Step-by-Step Setup Instructions

### Step 1 — Install Python
Download and install Python 3.10 or newer from https://python.org
During installation on Windows, tick **"Add Python to PATH"**.

### Step 2 — Open a terminal (Command Prompt / PowerShell)
Navigate to the project folder:
```
cd path\to\network_monitor
```

### Step 3 — Install dependencies
```
pip install -r requirements.txt
```

### Step 4 — Configure your hosts (optional)
Open `config.py` in any text editor and edit the `HOSTS` list.
By default the system runs in **SIMULATE = True** mode, which generates
realistic fake data — no real network devices or SNMP agents needed.

### Step 5 — Start the monitoring agent
In Terminal 1:
```
python main.py
```
You will see SNMP and ICMP output printed every 30–60 seconds.

### Step 6 — Open the dashboard
In Terminal 2 (keep Terminal 1 running):
```
streamlit run dashboard.py
```
Your browser will open automatically at http://localhost:8501

---

## Dashboard Tabs

| Tab | Contents |
|-----|----------|
| 🏠 Overview | Host status cards, active alert banners |
| 📊 SNMP Metrics | CPU, Memory, Traffic, Error charts with threshold lines |
| 🌐 ICMP Metrics | RTT, Packet Loss, Jitter, Status over time charts |
| 🚨 Alerts | Alert log with severity, type breakdown chart |

---

## Alert Thresholds (editable in config.py)

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU Utilization | > 70% | > 90% |
| Memory Utilization | > 75% | > 90% |
| Round Trip Time | > 100 ms | > 500 ms |
| Packet Loss | > 10% | > 50% |
| Interface Errors | > 5 | > 20 |

---

## Switching to Real Network Monitoring

1. Open `config.py`
2. Set `SIMULATE = False`
3. Add real device IPs to the `HOSTS` list with correct community strings
4. Ensure SNMP is enabled on your target devices (UDP port 161)
5. Restart `main.py`

---

## Technologies Used

- **Python 3.10+** — Core programming language
- **pysnmp** — SNMP v1/v2c/v3 implementation for Python
- **Streamlit** — Real-time web dashboard framework
- **Plotly** — Interactive charting library
- **SQLite3** — Embedded time-series database (built into Python)
- **pandas** — Data manipulation for dashboard queries
