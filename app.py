"""
SOC dashboard (Streamlit).

All data comes from the backend REST API (backend/api.py) - nothing is read
from CSV files here any more. Start the backend first:

    python -m backend.api
    streamlit run app.py
"""

import os
import time

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

API_URL = os.environ.get("SIEM_API_URL", "http://127.0.0.1:8000").rstrip("/")
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d", "HIGH": "#ff8c42", "MEDIUM": "#f7c948", "LOW": "#2ec27e",
}


# ------------------------------------------------------------ API helpers
def api_get(path, **params):
    """GET <API_URL>/api/<path> -> parsed JSON. Raises on any failure."""
    response = requests.get(f"{API_URL}/api/{path}", params=params, timeout=10)
    response.raise_for_status()
    return response.json()


def api_send(method, path, payload=None):
    response = requests.request(method, f"{API_URL}/api/{path}", json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


# App page setup

st.set_page_config(
    page_title="Smart SIEM Alert Prioritization",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Styling tweaks for the dashboard look and feel

st.markdown(
    """
    <style>

    /* Main page */
    .stApp {
        background-color: #0e1117;
    }

    [data-testid="stAppViewContainer"] .main .block-container {
        padding-top: 0.35rem !important;
    }

    .main-header {
        padding: 0 0 4px 0;
    }

    /* Header */
    .main-title {
        font-size: 38px;
        font-weight: 700;
        letter-spacing: -0.5px;
        margin-bottom: 4px;
    }

    .main-subtitle {
        color: #9ca3af;
        font-size: 15px;
        margin-bottom: 20px;
    }

    /* KPI Cards */
    .metric-card {
        background: #171b24;
        border: 1px solid #262c38;
        border-radius: 10px;
        padding: 16px 18px;
        min-height: 105px;
    }

    .metric-label {
        color: #9ca3af;
        font-size: 13px;
        margin-bottom: 8px;
    }

    .metric-value {
        font-size: 28px;
        font-weight: 650;
    }

    .critical-value {
        color: #ff5c5c;
    }

    .high-value {
        color: #ff9f43;
    }

    .medium-value {
        color: #f6c85f;
    }

    .low-value {
        color: #55d68a;
    }

    /* Section headers */
    .section-title {
        font-size: 20px;
        font-weight: 650;
        margin-top: 8px;
        margin-bottom: 12px;
    }

    /* Top alert card */
    .top-alert {
        background: #151922;
        border: 1px solid #292f3b;
        border-radius: 9px;
        padding: 13px 16px;
        margin-bottom: 8px;
    }

    .alert-id {
        font-weight: 650;
        font-size: 15px;
    }

    .alert-type {
        color: #d1d5db;
        font-size: 14px;
    }

    .alert-asset {
        color: #9ca3af;
        font-size: 13px;
    }

    /* Risk badge */
    .risk-badge {
        display: inline-block;
        padding: 4px 9px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: 650;
    }

    .critical-badge {
        background: #3a171b;
        color: #ff6b6b;
    }

    .high-badge {
        background: #3a2816;
        color: #ffad5c;
    }

    .medium-badge {
        background: #393117;
        color: #f6ce67;
    }

    .low-badge {
        background: #143022;
        color: #61d995;
    }

    /* Info box */
    .methodology-box {
        background: #151922;
        border: 1px solid #292f3b;
        border-radius: 10px;
        padding: 18px 20px;
        margin-top: 10px;
    }

    .methodology-item {
        margin-bottom: 7px;
        color: #d1d5db;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #11151d;
        border-right: 1px solid #252b35;
        padding-top: 14px;
    }

    section[data-testid="stSidebar"] > div:first-child {
        padding-left: 8px;
        padding-right: 8px;
    }

    section[data-testid="stSidebar"] .stMarkdown h2 {
        font-size: 25px;
        font-weight: 700;
        letter-spacing: -0.2px;
        margin-bottom: 10px;
        color: #f2f4f7;
    }

    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stCaption {
        color: #98a4b7;
        font-size: 13px;
    }

    section[data-testid="stSidebar"] label {
        font-weight: 600;
        color: #e6ebf2;
    }

    section[data-testid="stSidebar"] .stTextInput > div,
    section[data-testid="stSidebar"] .stSelectbox > div,
    section[data-testid="stSidebar"] .stMultiSelect > div {
        background: #141b27;
        border: 1px solid #2b3545;
        border-radius: 12px;
        box-shadow: none;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    section[data-testid="stSidebar"] .stTextInput > div:focus-within,
    section[data-testid="stSidebar"] .stSelectbox > div:focus-within,
    section[data-testid="stSidebar"] .stMultiSelect > div:focus-within {
        border-color: #4e617d;
        box-shadow: 0 0 0 1px rgba(78, 97, 125, 0.35);
    }

    section[data-testid="stSidebar"] .stTextInput input,
    section[data-testid="stSidebar"] .stSelectbox div[role="button"],
    section[data-testid="stSidebar"] .stMultiSelect div[role="button"] {
        color: #f3f5f8;
        background: transparent;
        border: none;
    }

    section[data-testid="stSidebar"] .stMultiSelect [data-baseweb="tag"] {
        background: #2a3344;
        border: 1px solid #3a465a;
        border-radius: 8px;
        padding: 4px 9px;
        margin: 2px;
    }

    section[data-testid="stSidebar"] .stMultiSelect [data-baseweb="tag"] span {
        color: #dde5f1;
        font-weight: 550;
    }

    section[data-testid="stSidebar"] .stMultiSelect [data-baseweb="tag"] svg {
        color: #aeb9c8;
    }

    section[data-testid="stSidebar"] .stSlider {
        margin-top: 10px;
    }

    section[data-testid="stSidebar"] .stSlider .MuiSlider-thumb {
        color: #ff6b6b;
        box-shadow: 0 0 0 4px rgba(255, 107, 107, 0.18);
    }

    section[data-testid="stSidebar"] .stSlider .MuiSlider-rail {
        background: #374151;
    }

    section[data-testid="stSidebar"] .stSlider .MuiSlider-track {
        background: linear-gradient(90deg, #44d19d, #ff6b6b);
    }

    /* Dividers */
    hr {
        border-color: #272d38;
    }

    </style>
    """,
    unsafe_allow_html=True
)

# ---------------------------------------------------------------- sidebar
with st.sidebar:

    st.markdown("## 🔎 Alert Filters")

    st.caption("Narrow down alerts for investigation.")

    search_text = st.text_input(
        "Search",
        placeholder="Alert ID, asset, IP, user..."
    )

    selected_severity = st.multiselect(
        "Severity", options=SEVERITIES, default=SEVERITIES
    )

    selected_status = st.multiselect(
        "Status", options=STATUSES, default=STATUSES
    )

    minimum_score = st.slider("Minimum Risk Score", 0, 100, 0)

    st.divider()
    st.markdown("## ⚙️ Pipeline")

    refresh_seconds = st.select_slider(
        "Auto-refresh (seconds, 0 = off)",
        options=[0, 5, 10, 30, 60],
        value=10
    )

    if st.button("▶ Process logs now"):
        try:
            result = api_send("POST", "process")
            st.success(
                f"{result['events_parsed']} events read, "
                f"{result['alerts_generated']} alerts generated"
            )
        except requests.RequestException as exc:
            st.error(f"Processing failed: {exc}")

    if st.button("📥 Load sample alerts (CSV)"):
        try:
            loaded = api_send("POST", "sample/load")["loaded"]
            st.success(f"Loaded {loaded} sample alerts")
        except requests.RequestException as exc:
            st.error(f"Could not load sample alerts: {exc}")

    st.caption(f"API: {API_URL}")


# ------------------------------------------------------- load backend data
try:
    summary = api_get("dashboard/summary")
    alerts_json = api_get("alerts", limit=2000)["alerts"]
    trend_json = api_get("trend")["trend"]
    distribution = api_get("distribution")
    events_json = api_get("events", limit=25)["events"]
except requests.RequestException as exc:
    st.error(
        f"Cannot reach the SIEM backend at {API_URL}.\n\n"
        f"Start it with `python -m backend.api` (details: {exc})"
    )
    st.stop()

# The API already returns alerts in SOC priority order
# (severity > risk score > frequency > asset criticality > correlation).
df = pd.DataFrame(alerts_json)


# Main heading

st.markdown(
    """
    <div class="main-header">
        <div class="main-title">🛡️ Smart SIEM Alert Prioritization</div>
        <div class="main-subtitle">
            Log-driven, rule-based alert triage: severity, asset importance
            and event context combine into a 0-100 risk score.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# Top summary cards

cards = [
    ("TOTAL ALERTS", summary["total_alerts"], ""),
    ("🔴 CRITICAL", summary["critical"], "critical-value"),
    ("🟠 HIGH", summary["high"], "high-value"),
    ("🟡 MEDIUM", summary["medium"], "medium-value"),
    ("🟢 LOW", summary["low"], "low-value"),
]

for column, (label, value, css_class) in zip(st.columns(5), cards):
    with column:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value {css_class}">{value}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

st.caption(
    f"Open alerts: {summary['open_alerts']} (critical: {summary['open_critical']}) · "
    f"Security events stored: {summary['total_events']} · "
    f"Last pipeline run: {summary['pipeline'].get('last_run') or 'not yet'}"
)

if summary["pipeline"].get("last_error"):
    st.warning(f"Last pipeline run failed: {summary['pipeline']['last_error']}")

if df.empty:
    st.info(
        "No alerts yet. Generate logs with `python tools/generate_logs.py "
        "--scenario all`, or use the sidebar to process logs / load sample alerts."
    )
    if refresh_seconds:
        time.sleep(refresh_seconds)
        st.rerun()
    st.stop()


# ---------------------------------------------------------------- filters
filtered_df = df[
    df["severity"].isin(selected_severity)
    & df["status"].isin(selected_status)
    & (df["risk_score"] >= minimum_score)
]

if search_text:
    needle = search_text.lower()
    haystack = (
        df[["alert_id", "alert_type", "asset", "source_ip", "username"]]
        .fillna("").astype(str).apply(lambda col: col.str.lower())
    )
    mask = haystack.apply(lambda col: col.str.contains(needle, regex=False)).any(axis=1)
    filtered_df = filtered_df[mask.loc[filtered_df.index]]

open_df = df[~df["status"].isin(["RESOLVED", "FALSE_POSITIVE"])]


# ------------------------------------------------------ critical alerts
st.markdown(
    '<div class="section-title">🔥 Critical Alerts (open)</div>',
    unsafe_allow_html=True
)

critical_open = open_df[open_df["severity"] == "CRITICAL"]

if critical_open.empty:
    st.success("No open critical alerts.")
else:
    for _, alert in critical_open.head(5).iterrows():
        st.markdown(
            f"""
            <div class="top-alert" style="border-left: 4px solid #ff4d4d;">
                <div class="alert-id">{alert['alert_id']} · {alert['alert_type']}
                    <span class="risk-badge critical-badge">{alert['risk_score']:.1f}</span>
                </div>
                <div class="alert-asset">
                    {alert['source_ip']} → {alert['asset']} · user: {alert['username'] or '-'}
                    · status: {alert['status']}
                </div>
                <div class="alert-type">{alert['description']}</div>
                <div class="alert-asset">➡ {alert['recommended_action']}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


# Highlight the top five highest-priority open alerts

st.markdown(
    '<div class="section-title">🚨 Top Priority Alerts</div>',
    unsafe_allow_html=True
)

for _, alert in open_df.head(5).iterrows():
    badge_color = SEVERITY_COLORS.get(alert["severity"], "#a8b1c1")

    st.markdown(
        f"""
        <div style="
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.75);
            padding: 18px 16px;
            margin-bottom: 12px;
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
                <div>
                    <div style="font-size: 0.9rem; color: #dfe4ee; font-weight: 600; margin-bottom: 4px;">
                        {alert['alert_id']} · {alert['priority']}
                    </div>
                    <div style="font-size: 1rem; color: #f8f9fb; font-weight: 600; margin-bottom: 4px;">
                        {alert['alert_type']}
                    </div>
                    <div style="font-size: 0.8rem; color: #a7b0c2;">
                        Affected asset: {alert['asset']} · Source IP: {alert['source_ip']}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="
                        display: inline-block;
                        background: {badge_color};
                        color: white;
                        border-radius: 999px;
                        padding: 6px 10px;
                        font-size: 0.7rem;
                        font-weight: 700;
                        letter-spacing: 0.04em;
                        margin-bottom: 8px;
                    ">{alert['severity']}</div>
                    <div style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">
                        {alert['risk_score']:.1f}
                    </div>
                    <div style="font-size: 0.7rem; color: #8f96a3;">/100</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# PRIORITIZED ALERT TABLE

st.markdown(
    '<div class="section-title">📋 Prioritized Security Alerts</div>',
    unsafe_allow_html=True
)

if len(filtered_df) > 0:

    display_df = filtered_df[[
        "priority", "severity", "risk_score", "alert_id", "alert_type", "source_ip",
        "username", "asset", "failed_attempts", "status", "timestamp"
    ]].copy()
    display_df["risk_score"] = display_df["risk_score"].round(1)

    st.dataframe(display_df, hide_index=True)

else:

    st.info("No alerts match the selected filters.")


# ------------------------------------------------ analyst: update status
st.markdown(
    '<div class="section-title">🛠️ Update Alert Status</div>',
    unsafe_allow_html=True
)

if len(filtered_df) > 0:

    col_a, col_b, col_c = st.columns([2, 2, 3])

    with col_a:
        status_alert_id = st.selectbox("Alert", filtered_df["alert_id"].tolist(), key="status_alert")

    current_status = df.loc[df["alert_id"] == status_alert_id, "status"].iloc[0]

    with col_b:
        new_status = st.selectbox(
            "New status", STATUSES, index=STATUSES.index(current_status), key="status_new"
        )

    with col_c:
        note = st.text_input("Analyst note (optional)", key="status_note")

    if st.button("Save status"):
        try:
            api_send("PATCH", f"alerts/{status_alert_id}/status",
                     {"status": new_status, "note": note or None})
            st.success(f"{status_alert_id} → {new_status}")
            time.sleep(0.6)
            st.rerun()
        except requests.RequestException as exc:
            st.error(f"Could not update status: {exc}")


# Analytics section

st.divider()

st.markdown(
    '<div class="section-title">📊 Alert Analytics</div>',
    unsafe_allow_html=True
)

col1, col2 = st.columns(2)

with col1:

    severity_counts = (
        df["severity"].value_counts().reindex(SEVERITIES, fill_value=0).reset_index()
    )
    severity_counts.columns = ["severity", "count"]

    fig_severity = px.pie(
        severity_counts[severity_counts["count"] > 0],
        names="severity", values="count", hole=0.55,
        color="severity", color_discrete_map=SEVERITY_COLORS,
    )
    fig_severity.update_traces(
        textinfo="percent",
        texttemplate="%{percent:.0%}",
        textfont=dict(color="#111111", size=18),
    )
    fig_severity.update_layout(
        title="Severity Distribution", template="plotly_dark",
        margin=dict(l=10, r=10, t=50, b=10), legend_title=""
    )
    st.plotly_chart(fig_severity)

with col2:

    trend_df = pd.DataFrame(trend_json)

    if trend_df.empty:
        st.info("No trend data yet.")
    else:
        trend_long = trend_df.melt(
            id_vars="bucket", value_vars=SEVERITIES,
            var_name="severity", value_name="alerts"
        )
        fig_trend = px.bar(
            trend_long, x="bucket", y="alerts", color="severity",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"severity": SEVERITIES},
        )
        fig_trend.update_layout(
            title="Alert Trend (per hour)", template="plotly_dark",
            xaxis_title="", yaxis_title="Alerts", xaxis_tickangle=-35,
            margin=dict(l=10, r=10, t=50, b=10), legend_title=""
        )
        st.plotly_chart(fig_trend)

col3, col4 = st.columns(2)

with col3:

    hist_df = pd.DataFrame(
        {"risk_score_range": list(distribution["risk_score"].keys()),
         "alerts": list(distribution["risk_score"].values())}
    )
    fig_hist = px.bar(hist_df, x="risk_score_range", y="alerts")
    fig_hist.update_traces(marker_color="#62d0ff")
    fig_hist.update_layout(
        title="Risk Score Distribution", template="plotly_dark",
        xaxis_title="Risk score", yaxis_title="Alerts",
        margin=dict(l=10, r=10, t=50, b=10)
    )
    st.plotly_chart(fig_hist)

with col4:

    alert_type_counts = df["alert_type"].value_counts().reset_index()
    alert_type_counts.columns = ["alert_type", "count"]

    fig_alerts = px.bar(
        alert_type_counts, x="alert_type", y="count", color="alert_type",
        color_discrete_sequence=px.colors.qualitative.Set2,
    )
    fig_alerts.update_layout(
        title="Alerts by Type", template="plotly_dark", xaxis_tickangle=-35,
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis_title="", yaxis_title="Alerts", showlegend=False,
    )
    st.plotly_chart(fig_alerts)


# Risk score breakdown for one selected alert

st.divider()

st.markdown(
    '<div class="section-title">📐 Risk Score Breakdown</div>',
    unsafe_allow_html=True
)

if len(filtered_df) > 0:

    selected_alert_id = st.selectbox(
        "Select an alert to inspect",
        filtered_df["alert_id"].tolist(),
        key="breakdown_alert",
    )

    # The breakdown is computed by the backend scoring engine and stored
    # with the alert, so the dashboard never re-implements the formula.
    selected_alert = api_get(f"alerts/{selected_alert_id}")
    breakdown = selected_alert["score_breakdown"] or {}

    st.markdown(
        f"""
        <div style="font-size: 1.05rem; color: #e5e7eb; margin: 12px 0 6px 0; font-weight: 600;">
            {selected_alert['alert_type']} • {selected_alert['asset']}
        </div>
        <div style="color:#9ca3af; margin-bottom: 14px;">{selected_alert['description']}</div>
        """,
        unsafe_allow_html=True,
    )

    def breakdown_card(title, score, color, weight_note):
        return f"""
        <div style="background: #151b26; border: 1px solid #2a3441; border-radius: 12px; padding: 16px; min-height: 150px;">
            <div style="font-size: 0.9rem; color: #b1bac7; margin-bottom: 10px;">{title}</div>
            <div style="font-size: 2.2rem; font-weight: 700; color: {color}; line-height: 1.1;">{score}/100</div>
            <div style="font-size: 0.82rem; color: #9aa4b2; margin-top: 16px;">{weight_note}</div>
        </div>
        """

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(breakdown_card(
            "Severity", breakdown.get("severity_score", "-"), "#ff6b6b",
            f"Weight: 40% • +{breakdown.get('severity_contribution', '-')}"
        ), unsafe_allow_html=True)

    with col2:
        st.markdown(breakdown_card(
            "Asset Importance", breakdown.get("asset_score", "-"), "#62d0ff",
            f"Weight: 30% • +{breakdown.get('asset_contribution', '-')}"
        ), unsafe_allow_html=True)

    with col3:
        st.markdown(breakdown_card(
            "Event Context", breakdown.get("context_score", "-"), "#ffd166",
            f"Weight: 30% • +{breakdown.get('context_contribution', '-')}"
        ), unsafe_allow_html=True)

    with col4:
        color = SEVERITY_COLORS.get(selected_alert["severity"], "#ff8fab")
        st.markdown(breakdown_card(
            "Final Risk", selected_alert["risk_score"], color,
            f"Severity: {selected_alert['severity']} • {selected_alert['priority']}"
        ), unsafe_allow_html=True)

    st.write("")
    st.markdown("**Why this score:** " + " · ".join(selected_alert["reasons"] or []))
    st.markdown(f"**Recommended action:** {selected_alert['recommended_action']}")


# Recent security events (raw log events stored by the pipeline)

st.divider()

st.markdown(
    '<div class="section-title">🧾 Recent Security Events</div>',
    unsafe_allow_html=True
)

if events_json:
    events_df = pd.DataFrame(events_json)[[
        "timestamp", "event_type", "status", "username", "source_ip",
        "resource", "failed_attempts", "frequency_per_min", "attack_type"
    ]]
    st.dataframe(events_df, hide_index=True)
else:
    st.info("No security events stored yet.")


# Scoring methodology notes

st.divider()

st.markdown(
    '<div class="section-title">⚙️ Risk Scoring Methodology</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="methodology-box">

    <div class="methodology-item">
    <b>Severity — 40%</b><br>
    Base seriousness of the detected event (e.g. brute force 90,
    ransomware 100, failed login 30).
    </div>

    <div class="methodology-item">
    <b>Asset Importance — 30%</b><br>
    Business importance of the affected asset.
    </div>

    <div class="methodology-item">
    <b>Event Context — 30%</b><br>
    Failed attempts, known-malicious IP, after-hours activity, affected
    users, privileged account, event frequency and correlation with other
    detections from the same source.
    </div>

    <br>

    <div class="methodology-item">
    <b>Severity thresholds</b><br>
    🔴 Critical: 90–100 &nbsp; | &nbsp;
    🟠 High: 70–89 &nbsp; | &nbsp;
    🟡 Medium: 40–69 &nbsp; | &nbsp;
    🟢 Low: 0–39
    </div>

    </div>
    """,
    unsafe_allow_html=True
)

# Footer

st.divider()

st.markdown(
    "<div style='text-align: center; color: #8c8c8c; font-size: 0.9rem;'>"
    "Security Alert Prioritization — Project by Harsha Patel (SOC Intern)"
    "</div>",
    unsafe_allow_html=True,
)


# Periodic refresh: re-run the script so new alerts appear automatically
if refresh_seconds:
    time.sleep(refresh_seconds)
    st.rerun()
