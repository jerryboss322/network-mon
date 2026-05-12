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
import database   # ← Important

# Page config
st.set_page_config(page_title="Hybrid Network Monitor", page_icon="📡", layout="wide")

# Initialize database + start threads
if "monitoring_started" not in st.session_state:
    database.init_db()                    # ← This was missing!
    icmp_monitor.start()
    snmp_monitor.start()
    st.session_state.monitoring_started = True
    st.success("✅ Monitoring threads & database started!")

# Database helpers
def load_table(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"DB Error: {e}")
        return pd.DataFrame()

def get_snmp():
    return load_table(f"""
        SELECT * FROM snmp_metrics 
        ORDER BY timestamp DESC 
        LIMIT {MAX_CHART_POINTS * len(HOSTS)}
    """)

def get_icmp():
    return load_table(f"""
        SELECT * FROM icmp_metrics 
        ORDER BY timestamp DESC 
        LIMIT {MAX_CHART_POINTS * len(HOSTS)}
    """)

def get_alerts():
    return load_table("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")

# UI Helpers
def status_badge(status):
    return {"Up": "🟢 Up", "Degraded": "🟡 Degraded", "Down": "🔴 Down"}.get(status, "⚪ Unknown")

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

        # Overview
        with tab1:
            st.subheader("Host Status Summary")
            cols = st.columns(len(HOSTS))
            for idx, host in enumerate(HOSTS):
                ip = host["ip"]
                label = host["label"]

                # Get latest ICMP
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

        # SNMP Tab
        with tab2:
            st.subheader("SNMP Device Performance Metrics")
            if snmp_df.empty:
                st.info("⏳ Waiting for SNMP data… (first poll in ~60 seconds)")
            else:
                # CPU Chart
                fig_cpu = px.line(snmp_df, x="timestamp", y="cpu_pct", color="host_ip", title="CPU Utilization (%)")
                fig_cpu.add_hline(y=90, line_dash="dash", line_color="red")
                st.plotly_chart(fig_cpu, use_container_width=True)

                # Memory Chart
                fig_mem = px.line(snmp_df, x="timestamp", y="mem_pct", color="host_ip", title="Memory Utilization (%)")
                fig_mem.add_hline(y=90, line_dash="dash", line_color="red")
                st.plotly_chart(fig_mem, use_container_width=True)

        # ICMP Tab
        with tab3:
            st.subheader("ICMP Availability & Latency Metrics")
            if icmp_df.empty:
                st.info("⏳ Waiting for ICMP data… (first probe soon)")
            else:
                col1, col2 = st.columns(2)
                with col1:
                    fig_rtt = px.line(icmp_df, x="timestamp", y="avg_rtt_ms", color="host_ip", title="Round Trip Time (ms)")
                    st.plotly_chart(fig_rtt, use_container_width=True)
                with col2:
                    fig_loss = px.line(icmp_df, x="timestamp", y="packet_loss_pct", color="host_ip", title="Packet Loss (%)")
                    st.plotly_chart(fig_loss, use_container_width=True)

        # Alerts Tab
        with tab4:
            st.subheader("Alert Log")
            if alert_df.empty:
                st.success("✅ No alerts yet")
            else:
                st.dataframe(alert_df[["timestamp", "host_ip", "alert_type", "severity", "message"]].head(30), use_container_width=True)

    time.sleep(DASHBOARD_REFRESH_SECS)
