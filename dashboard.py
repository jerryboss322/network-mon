"""
dashboard.py — Hybrid Network Monitoring Agent
"""

import time
import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px

from config import DB_PATH, MAX_CHART_POINTS, DASHBOARD_REFRESH_SECS, HOSTS
import icmp_monitor
import snmp_monitor
import database

st.set_page_config(page_title="Hybrid Network Monitor", page_icon="📡", layout="wide")

# Initialize once
if "monitoring_started" not in st.session_state:
    database.init_db()
    icmp_monitor.start()
    snmp_monitor.start()
    st.session_state.monitoring_started = True
    st.success("✅ Monitoring started successfully!")

def load_table(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

snmp_df = load_table(f"SELECT * FROM snmp_metrics ORDER BY timestamp DESC LIMIT {MAX_CHART_POINTS * len(HOSTS)}")
icmp_df = load_table(f"SELECT * FROM icmp_metrics ORDER BY timestamp DESC LIMIT {MAX_CHART_POINTS * len(HOSTS)}")
alert_df = load_table("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")

if not snmp_df.empty: snmp_df = snmp_df.iloc[::-1].reset_index(drop=True)
if not icmp_df.empty: icmp_df = icmp_df.iloc[::-1].reset_index(drop=True)

st.title("📡 Hybrid Network Monitoring Agent")
st.caption(f"Real-time monitoring using SNMP + ICMP | Auto-refreshes every {DASHBOARD_REFRESH_SECS} seconds")

tab1, tab2, tab3, tab4 = st.tabs(["🏠 Overview", "📊 SNMP Metrics", "🌐 ICMP Metrics", "🚨 Alerts"])

with tab1:
    st.subheader("Host Status Summary")
    cols = st.columns(len(HOSTS))
    for idx, host in enumerate(HOSTS):
        ip = host["ip"]
        label = host["label"]

        if not icmp_df.empty:
            row = icmp_df[icmp_df["host_ip"] == ip].tail(1)
            if not row.empty:
                status = row["status"].values[0]
                rtt = row["avg_rtt_ms"].values[0]
                loss = row["packet_loss_pct"].values[0]
            else:
                status = rtt = loss = None
        else:
            status = rtt = loss = None

        cpu = mem = None
        if not snmp_df.empty and host.get("snmp"):
            srow = snmp_df[snmp_df["host_ip"] == ip].tail(1)
            if not srow.empty:
                cpu = srow["cpu_pct"].values[0]
                mem = srow["mem_pct"].values[0]

        with cols[idx]:
            st.markdown(f"### {label}")
            st.metric("Status", "🟢 Up" if status == "Up" else "⚪ Unknown")
            st.metric("RTT (ms)", f"{rtt:.1f}" if rtt else "—")
            st.metric("Packet Loss", f"{loss:.0f}%" if loss is not None else "—")
            if cpu: st.metric("CPU", f"{cpu:.1f}%")
            if mem: st.metric("Memory", f"{mem:.1f}%")

with tab2:
    st.subheader("SNMP Metrics")
    if snmp_df.empty:
        st.info("⏳ Waiting for SNMP data...")
    else:
        st.plotly_chart(px.line(snmp_df, x="timestamp", y="cpu_pct", color="host_ip", title="CPU %"), use_container_width=True)
        st.plotly_chart(px.line(snmp_df, x="timestamp", y="mem_pct", color="host_ip", title="Memory %"), use_container_width=True)

with tab3:
    st.subheader("ICMP Metrics")
    if icmp_df.empty:
        st.info("⏳ Waiting for ICMP data...")
    else:
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(px.line(icmp_df, x="timestamp", y="avg_rtt_ms", color="host_ip", title="RTT (ms)"), use_container_width=True)
        with col2:
            st.plotly_chart(px.line(icmp_df, x="timestamp", y="packet_loss_pct", color="host_ip", title="Packet Loss %"), use_container_width=True)

with tab4:
    st.subheader("Alerts")
    if alert_df.empty:
        st.success("No alerts yet")
    else:
        st.dataframe(alert_df.head(20), use_container_width=True)

time.sleep(DASHBOARD_REFRESH_SECS)
st.rerun()
