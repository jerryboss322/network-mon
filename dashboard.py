"""
dashboard.py — Real-time Streamlit Dashboard
Hybrid Network Monitoring Agent (SNMP + ICMP)

Run with:
    streamlit run dashboard.py
"""

import time
import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from config import DB_PATH, MAX_CHART_POINTS, DASHBOARD_REFRESH_SECS, HOSTS
import database
import icmp_monitor
import snmp_monitor

# ── Start monitoring threads (Streamlit Cloud compatible) ─────────────────────
# On Streamlit Cloud there is no separate terminal to run main.py, so we start
# the monitoring threads here instead. st.session_state ensures they only launch
# once per session, not on every rerun of the dashboard script.
if "monitoring_started" not in st.session_state:
    database.init_db()
    icmp_monitor.start()
    snmp_monitor.start()
    st.session_state.monitoring_started = True

# ── Page configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Hybrid Network Monitor",
    page_icon="📡",
    layout="wide",
)

# ── Helper: load data from SQLite ─────────────────────────────────────────────
def load_table(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
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
    return load_table("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT 100
    """)


# ── Severity colour helper ────────────────────────────────────────────────────
def severity_colour(sev):
    return {"CRITICAL": "🔴", "WARNING": "🟡"}.get(sev, "🟢")


# ── Status colour helper ──────────────────────────────────────────────────────
def status_badge(status):
    return {"Up": "🟢 Up", "Degraded": "🟡 Degraded", "Down": "🔴 Down"}.get(
        status, "⚪ Unknown"
    )


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN DASHBOARD RENDER (runs every DASHBOARD_REFRESH_SECS seconds)
# ═════════════════════════════════════════════════════════════════════════════
st.title("📡 Hybrid Network Monitoring Agent")
st.caption("Real-time monitoring using SNMP + ICMP  |  Auto-refreshes every "
           f"{DASHBOARD_REFRESH_SECS} seconds")

placeholder = st.empty()

while True:
    snmp_df  = get_snmp()
    icmp_df  = get_icmp()
    alert_df = get_alerts()

    # Reverse so charts plot oldest → newest left to right
    if not snmp_df.empty:
        snmp_df = snmp_df.iloc[::-1].reset_index(drop=True)
    if not icmp_df.empty:
        icmp_df = icmp_df.iloc[::-1].reset_index(drop=True)

    with placeholder.container():

        # ── TAB NAVIGATION ────────────────────────────────────────────────────
        tab1, tab2, tab3, tab4 = st.tabs([
            "🏠 Overview", "📊 SNMP Metrics", "🌐 ICMP Metrics", "🚨 Alerts"
        ])

        # ════════════════════════════════════════════════════════════════════
        # TAB 1 — OVERVIEW
        # ════════════════════════════════════════════════════════════════════
        with tab1:
            st.subheader("Host Status Summary")

            cols = st.columns(len(HOSTS))
            for idx, host in enumerate(HOSTS):
                ip = host["ip"]
                label = host["label"]

                # Latest ICMP status
                if not icmp_df.empty:
                    row = icmp_df[icmp_df["host_ip"] == ip].tail(1)
                    if not row.empty:
                        status    = row["status"].values[0]
                        rtt       = row["avg_rtt_ms"].values[0]
                        loss      = row["packet_loss_pct"].values[0]
                    else:
                        status, rtt, loss = "Unknown", None, None
                else:
                    status, rtt, loss = "Waiting…", None, None

                # Latest SNMP metrics
                if not snmp_df.empty and host["snmp"]:
                    srow = snmp_df[snmp_df["host_ip"] == ip].tail(1)
                    cpu = srow["cpu_pct"].values[0]  if not srow.empty else None
                    mem = srow["mem_pct"].values[0]  if not srow.empty else None
                else:
                    cpu, mem = None, None

                with cols[idx]:
                    st.markdown(f"### {label}")
                    st.markdown(f"**Status:** {status_badge(status)}")
                    st.metric("RTT (ms)",     f"{rtt:.1f}" if rtt is not None else "—")
                    st.metric("Packet Loss",  f"{loss:.0f}%" if loss is not None else "—")
                    if cpu is not None:
                        st.metric("CPU",      f"{cpu:.1f}%")
                    if mem is not None:
                        st.metric("Memory",   f"{mem:.1f}%")

            # Active alerts banner
            st.divider()
            if not alert_df.empty:
                active = alert_df[alert_df["resolved"] == 0]
                criticals = active[active["severity"] == "CRITICAL"]
                warnings  = active[active["severity"] == "WARNING"]
                if not criticals.empty:
                    st.error(f"🔴 {len(criticals)} CRITICAL alert(s) active — see Alerts tab")
                if not warnings.empty:
                    st.warning(f"🟡 {len(warnings)} WARNING alert(s) active — see Alerts tab")
                if criticals.empty and warnings.empty:
                    st.success("✅ No active alerts — all systems normal")
            else:
                st.info("ℹ️ No alert data yet. Monitoring is starting up…")

        # ════════════════════════════════════════════════════════════════════
        # TAB 2 — SNMP METRICS
        # ════════════════════════════════════════════════════════════════════
        with tab2:
            st.subheader("SNMP Device Performance Metrics")

            if snmp_df.empty:
                st.info("Waiting for SNMP data… (first poll in up to 60 seconds)")
            else:
                snmp_hosts = snmp_df["host_ip"].unique()

                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown("#### CPU Utilization (%)")
                    fig = px.line(
                        snmp_df[snmp_df["host_ip"].isin(snmp_hosts)],
                        x="timestamp", y="cpu_pct", color="host_ip",
                        labels={"cpu_pct": "CPU %", "timestamp": "Time",
                                "host_ip": "Host"},
                    )
                    fig.add_hline(y=90, line_dash="dash", line_color="red",
                                  annotation_text="Critical 90%")
                    fig.add_hline(y=70, line_dash="dot",  line_color="orange",
                                  annotation_text="Warning 70%")
                    st.plotly_chart(fig, use_container_width=True)

                with col_b:
                    st.markdown("#### Memory Utilization (%)")
                    fig2 = px.line(
                        snmp_df,
                        x="timestamp", y="mem_pct", color="host_ip",
                        labels={"mem_pct": "Memory %", "timestamp": "Time",
                                "host_ip": "Host"},
                    )
                    fig2.add_hline(y=90, line_dash="dash", line_color="red",
                                   annotation_text="Critical 90%")
                    fig2.add_hline(y=75, line_dash="dot",  line_color="orange",
                                   annotation_text="Warning 75%")
                    st.plotly_chart(fig2, use_container_width=True)

                col_c, col_d = st.columns(2)

                with col_c:
                    st.markdown("#### Interface Traffic (Mbps)")
                    fig3 = go.Figure()
                    for h in snmp_hosts:
                        sub = snmp_df[snmp_df["host_ip"] == h]
                        fig3.add_trace(go.Scatter(
                            x=sub["timestamp"], y=sub["if_in_mbps"],
                            name=f"{h} IN", mode="lines"))
                        fig3.add_trace(go.Scatter(
                            x=sub["timestamp"], y=sub["if_out_mbps"],
                            name=f"{h} OUT", mode="lines", line=dict(dash="dot")))
                    fig3.update_layout(
                        xaxis_title="Time", yaxis_title="Mbps",
                        legend_title="Host / Direction")
                    st.plotly_chart(fig3, use_container_width=True)

                with col_d:
                    st.markdown("#### Interface Errors")
                    fig4 = px.bar(
                        snmp_df.tail(30),
                        x="timestamp", y="if_errors", color="host_ip",
                        labels={"if_errors": "Error Count", "timestamp": "Time"},
                        barmode="group",
                    )
                    st.plotly_chart(fig4, use_container_width=True)

                # Raw data table
                with st.expander("📋 Raw SNMP Data"):
                    st.dataframe(
                        snmp_df[["timestamp","host_ip","cpu_pct","mem_pct",
                                 "if_in_mbps","if_out_mbps","if_errors",
                                 "sys_uptime","reachable"]].tail(50),
                        use_container_width=True,
                    )

        # ════════════════════════════════════════════════════════════════════
        # TAB 3 — ICMP METRICS
        # ════════════════════════════════════════════════════════════════════
        with tab3:
            st.subheader("ICMP Availability & Latency Metrics")

            if icmp_df.empty:
                st.info("Waiting for ICMP data… (first probe in up to 30 seconds)")
            else:
                col_e, col_f = st.columns(2)

                with col_e:
                    st.markdown("#### Round Trip Time — RTT (ms)")
                    fig5 = px.line(
                        icmp_df,
                        x="timestamp", y="avg_rtt_ms", color="host_ip",
                        labels={"avg_rtt_ms": "RTT (ms)", "timestamp": "Time",
                                "host_ip": "Host"},
                    )
                    fig5.add_hline(y=500, line_dash="dash", line_color="red",
                                   annotation_text="Critical 500ms")
                    fig5.add_hline(y=100, line_dash="dot",  line_color="orange",
                                   annotation_text="Warning 100ms")
                    st.plotly_chart(fig5, use_container_width=True)

                with col_f:
                    st.markdown("#### Packet Loss (%)")
                    fig6 = px.line(
                        icmp_df,
                        x="timestamp", y="packet_loss_pct", color="host_ip",
                        labels={"packet_loss_pct": "Loss %", "timestamp": "Time",
                                "host_ip": "Host"},
                    )
                    fig6.add_hline(y=50, line_dash="dash", line_color="red",
                                   annotation_text="Critical 50%")
                    fig6.add_hline(y=10, line_dash="dot",  line_color="orange",
                                   annotation_text="Warning 10%")
                    st.plotly_chart(fig6, use_container_width=True)

                col_g, col_h = st.columns(2)

                with col_g:
                    st.markdown("#### Jitter (ms)")
                    fig7 = px.line(
                        icmp_df,
                        x="timestamp", y="jitter_ms", color="host_ip",
                        labels={"jitter_ms": "Jitter (ms)", "timestamp": "Time"},
                    )
                    st.plotly_chart(fig7, use_container_width=True)

                with col_h:
                    st.markdown("#### Host Status Over Time")
                    status_map = {"Up": 1, "Degraded": 0.5, "Down": 0}
                    icmp_df["status_num"] = icmp_df["status"].map(status_map)
                    fig8 = px.line(
                        icmp_df,
                        x="timestamp", y="status_num", color="host_ip",
                        labels={"status_num": "Status (1=Up, 0=Down)",
                                "timestamp": "Time"},
                    )
                    fig8.update_yaxes(range=[-0.1, 1.1],
                                      tickvals=[0, 0.5, 1],
                                      ticktext=["Down", "Degraded", "Up"])
                    st.plotly_chart(fig8, use_container_width=True)

                with st.expander("📋 Raw ICMP Data"):
                    st.dataframe(
                        icmp_df[["timestamp","host_ip","avg_rtt_ms","min_rtt_ms",
                                 "max_rtt_ms","packet_loss_pct",
                                 "jitter_ms","status"]].tail(50),
                        use_container_width=True,
                    )

        # ════════════════════════════════════════════════════════════════════
        # TAB 4 — ALERTS
        # ════════════════════════════════════════════════════════════════════
        with tab4:
            st.subheader("Alert Log")

            if alert_df.empty:
                st.success("✅ No alerts have been generated yet.")
            else:
                # Summary metrics
                total     = len(alert_df)
                criticals = len(alert_df[alert_df["severity"] == "CRITICAL"])
                warnings  = len(alert_df[alert_df["severity"] == "WARNING"])

                m1, m2, m3 = st.columns(3)
                m1.metric("Total Alerts", total)
                m2.metric("🔴 Critical",  criticals)
                m3.metric("🟡 Warning",   warnings)

                st.divider()

                # Alert type breakdown chart
                if len(alert_df) > 1:
                    type_counts = (
                        alert_df.groupby(["alert_type", "severity"])
                        .size()
                        .reset_index(name="count")
                    )
                    fig9 = px.bar(
                        type_counts,
                        x="alert_type", y="count", color="severity",
                        color_discrete_map={"CRITICAL": "#d9534f",
                                            "WARNING":  "#f0ad4e"},
                        labels={"alert_type": "Alert Type",
                                "count": "Occurrences"},
                        title="Alert Frequency by Type",
                    )
                    st.plotly_chart(fig9, use_container_width=True)

                # Full alert table with coloured severity
                st.markdown("#### Alert History (most recent first)")
                display_df = alert_df.copy()
                display_df["severity"] = display_df["severity"].apply(
                    lambda s: f"{severity_colour(s)} {s}"
                )
                st.dataframe(
                    display_df[["timestamp","host_ip","alert_type",
                                "severity","metric_value",
                                "threshold_value","message"]],
                    use_container_width=True,
                )

    # Wait before refreshing
    time.sleep(DASHBOARD_REFRESH_SECS)
