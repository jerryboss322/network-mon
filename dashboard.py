"""
dashboard.py — Real-time Streamlit Dashboard
Hybrid Network Monitoring Agent (SNMP + ICMP)
"""

import time
import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from config import DB_PATH, MAX_CHART_POINTS, DASHBOARD_REFRESH_SECS, HOSTS
import icmp_monitor
import snmp_monitor

# Page config
st.set_page_config(page_title="Hybrid Network Monitor", page_icon="📡", layout="wide")

# Start monitoring threads
if "monitoring_started" not in st.session_state:
    icmp_monitor.start()
    snmp_monitor.start()
    st.session_state.monitoring_started = True
    st.success("✅ Monitoring threads started successfully!")

# Database helpers
def load_table(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def get_snmp():
    return load_table(f"SELECT * FROM snmp_metrics ORDER BY timestamp DESC LIMIT {MAX_CHART_POINTS * len(HOSTS)}")

def get_icmp():
    return load_table(f"SELECT * FROM icmp_metrics ORDER BY timestamp DESC LIMIT {MAX_CHART_POINTS * len(HOSTS)}")

def get_alerts():
    return load_table("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")

# Helpers
def severity_colour(sev):
    return {"CRITICAL": "🔴", "WARNING": "🟡"}.get(sev, "🟢")

def status_badge(status):
    return {"Up": "🟢 Up", "Degraded": "🟡 Degraded", "Down": "🔴 Down"}.get(status, "⚪ Unknown")

# Main UI
st.title("📡 Hybrid Network Monitoring Agent")
st.caption(f"Real-time monitoring using SNMP + ICMP | Auto-refreshes every {DASHBOARD_REFRESH_SECS} seconds")

placeholder = st.empty()

while True:
    snmp_df = get_snmp()
    icmp_df = get_icmp()
    alert_df = get_alerts()

    if not snmp_df.empty:
        snmp_df = snmp_df.iloc[::-1].reset_index(drop=True)
    if not icmp_df.empty:
        icmp_df = icmp_df.iloc[::-1].reset_index(drop=True)

    with placeholder.container():
        tab1, tab2, tab3, tab4 = st.tabs(["🏠 Overview", "📊 SNMP Metrics", "🌐 ICMP Metrics", "🚨 Alerts"])

        # === OVERVIEW ===
        with tab1:
            st.subheader("Host Status Summary")
            cols = st.columns(len(HOSTS))
            for idx, host in enumerate(HOSTS):
                ip = host["ip"]
                label = host["label"]

                # ICMP
                if not icmp_df.empty:
                    row = icmp_df[icmp_df["host_ip"] == ip].tail(1)
                    if not row.empty:
                        status = row["status"].values[0]
                        rtt = row["avg_rtt_ms"].values[0]
                        loss = row["packet_loss_pct"].values[0]
                    else:
                        status, rtt, loss = "Unknown", None, None
                else:
                    status, rtt, loss = "Waiting…", None, None

                # SNMP
                cpu = mem = None
                if not snmp_df.empty and host.get("snmp"):
                    srow = snmp_df[snmp_df["host_ip"] == ip].tail(1)
                    if not srow.empty:
                        cpu = srow["cpu_pct"].values[0]
                        mem = srow["mem_pct"].values[0]

                with cols[idx]:
                    st.markdown(f"### {label}")
                    st.markdown(f"**Status:** {status_badge(status)}")
                    st.metric("RTT (ms)", f"{rtt:.1f}" if rtt is not None else "—")
                    st.metric("Packet Loss", f"{loss:.0f}%" if loss is not None else "—")
                    if cpu is not None: st.metric("CPU", f"{cpu:.1f}%")
                    if mem is not None: st.metric("Memory", f"{mem:.1f}%")

            st.divider()
            if not alert_df.empty:
                active = alert_df[alert_df["resolved"] == 0]
                crit = len(active[active["severity"] == "CRITICAL"])
                warn = len(active[active["severity"] == "WARNING"])
                if crit > 0:
                    st.error(f"🔴 {crit} CRITICAL alert(s)")
                elif warn > 0:
                    st.warning(f"🟡 {warn} WARNING alert(s)")
                else:
                    st.success("✅ All systems normal")
            else:
                st.info("Monitoring is starting up...")

        # === SNMP TAB ===
        with tab2:
            st.subheader("SNMP Device Performance Metrics")
            if snmp_df.empty:
                st.info("Waiting for SNMP data… (first poll in ~60 seconds)")
            else:
                snmp_hosts = snmp_df["host_ip"].unique()

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("#### CPU Utilization (%)")
                    fig = px.line(snmp_df, x="timestamp", y="cpu_pct", color="host_ip")
                    fig.add_hline(y=90, line_dash="dash", line_color="red", annotation_text="Critical")
                    fig.add_hline(y=70, line_dash="dot", line_color="orange", annotation_text="Warning")
                    st.plotly_chart(fig, use_container_width=True)

                with col_b:
                    st.markdown("#### Memory Utilization (%)")
                    fig2 = px.line(snmp_df, x="timestamp", y="mem_pct", color="host_ip")
                    fig2.add_hline(y=90, line_dash="dash", line_color="red")
                    fig2.add_hline(y=75, line_dash="dot", line_color="orange")
                    st.plotly_chart(fig2, use_container_width=True)

                # More charts...
                st.info("✅ SNMP simulation is running — charts will populate shortly")

        # === ICMP TAB ===
        with tab3:
            st.subheader("ICMP Availability & Latency Metrics")
            if icmp_df.empty:
                st.info("Waiting for ICMP data… (first probe soon)")
            else:
                col_e, col_f = st.columns(2)
                with col_e:
                    st.markdown("#### Round Trip Time (ms)")
                    fig5 = px.line(icmp_df, x="timestamp", y="avg_rtt_ms", color="host_ip")
                    st.plotly_chart(fig5, use_container_width=True)
                with col_f:
                    st.markdown("#### Packet Loss (%)")
                    fig6 = px.line(icmp_df, x="timestamp", y="packet_loss_pct", color="host_ip")
                    st.plotly_chart(fig6, use_container_width=True)

                st.success("✅ Live ICMP data is being collected!")

        # === ALERTS TAB ===
        with tab4:
            st.subheader("Alert Log")
            if alert_df.empty:
                st.success("No alerts yet")
            else:
                st.dataframe(alert_df.head(30), use_container_width=True)

    time.sleep(DASHBOARD_REFRESH_SECS)
