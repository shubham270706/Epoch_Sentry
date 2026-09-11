import streamlit as st
import pandas as pd
import sqlite3
import joblib
import altair as alt
import os
from datetime import datetime, timedelta

import capture_controller

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentry_logs.db")
MODEL_PATH = os.path.join(BASE_DIR, "data", "epoch_sentry_model.pkl")

STALE_AFTER_SEC = 15  # if no new flow in this long, flag the feed as stale

st.set_page_config(page_title="Epoch Sentry", page_icon="◆", layout="wide")

# ---------------------------------------------------------------------------
# Look & feel: deliberately NOT the default Streamlit light-theme-plus-emoji
# look. NOC/SOC glass walls run dark with a limited, high-contrast signal
# palette because analysts stare at these for hours — that's a real
# operational constraint, not decoration.
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"]  { font-family: 'IBM Plex Sans', sans-serif; }
code, .mono { font-family: 'IBM Plex Mono', monospace; }

.stApp {
    background-color: #0B1220;
    color: #E6EDF3;
}
section[data-testid="stSidebar"] {
    background-color: #0E1729;
    border-right: 1px solid #1E2A3F;
}

.sentry-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    border-bottom: 1px solid #1E2A3F;
    padding-bottom: 14px;
    margin-bottom: 18px;
}
.sentry-title { font-size: 1.6rem; font-weight: 600; letter-spacing: 0.5px; color: #E6EDF3; }
.sentry-sub { font-size: 0.85rem; color: #7C8B9C; margin-top: 2px; }

.status-pill {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    padding: 4px 10px;
    border-radius: 3px;
    border: 1px solid;
}
.status-live { color: #4FD1C5; border-color: #205A54; background: rgba(79,209,197,0.08); }
.status-stale { color: #F5A623; border-color: #6B4E14; background: rgba(245,166,35,0.08); }
.status-down { color: #E5484D; border-color: #6B2226; background: rgba(229,72,77,0.08); }

.kpi-card {
    background: #101B2D;
    border: 1px solid #1E2A3F;
    border-radius: 4px;
    padding: 14px 16px;
}
.kpi-label { font-size: 0.75rem; color: #7C8B9C; text-transform: uppercase; letter-spacing: 0.6px; }
.kpi-value { font-family: 'IBM Plex Mono', monospace; font-size: 1.7rem; color: #E6EDF3; margin-top: 2px; }
.kpi-value.warn { color: #F5A623; }
.kpi-value.crit { color: #E5484D; }
.kpi-value.ok { color: #4FD1C5; }

.section-label {
    font-size: 0.8rem;
    color: #7C8B9C;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin: 22px 0 8px 0;
    border-left: 2px solid #4FD1C5;
    padding-left: 8px;
}

.disclosure {
    font-size: 0.78rem;
    color: #7C8B9C;
    border-top: 1px solid #1E2A3F;
    margin-top: 30px;
    padding-top: 12px;
    line-height: 1.5;
}

div[data-testid="stDataFrame"] { border: 1px solid #1E2A3F; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------
@st.cache_resource
def load_ml_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)


@st.cache_data(ttl=2)
def fetch_sqlite_logs(limit=500):
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql(f"SELECT * FROM live_conn ORDER BY id DESC LIMIT {int(limit)}", conn)
    conn.close()
    return df


model = load_ml_model()

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Epoch Sentry")
    st.caption("Unidirectional IP traffic — anomaly triage")

    # -----------------------------------------------------------------
    # Capture control — single start/stop button.
    #
    # This launches/stops Zeek (reading local_capture.zeek, which loads
    # the DNS-entropy enrichment and disables every log stream except
    # conn.log) plus zeek_daemon.py as tracked background processes.
    # Once started, capture runs indefinitely against the chosen
    # interface — there's no packet count or time limit — until this
    # button is used to stop it.
    # -----------------------------------------------------------------
    st.markdown('<div class="section-label">Capture control</div>', unsafe_allow_html=True)

    cap_status = capture_controller.status()

    if cap_status["running"]:
        elapsed = ""
        if cap_status.get("started_at"):
            started = datetime.strptime(cap_status["started_at"], "%Y-%m-%dT%H:%M:%S")
            mins = int((datetime.now() - started).total_seconds() // 60)
            elapsed = f" · running {mins}m"
        st.markdown(
            f'<span class="status-pill status-live">● CAPTURING on '
            f'{cap_status["interface"]}{elapsed}</span>',
            unsafe_allow_html=True,
        )
        st.caption(f"zeek pid {cap_status['zeek_pid']} · daemon pid {cap_status['daemon_pid']}")
        if st.button("■ Stop capture", use_container_width=True, type="primary"):
            capture_controller.stop()
            st.rerun()
    else:
        if cap_status.get("note"):
            st.caption(f"⚠ {cap_status['note']}")
        capture_iface = st.selectbox(
            "Interface",
            options=capture_controller.list_interfaces(),
            help="'any' captures on all interfaces (libpcap pseudo-interface) "
                 "and is the safest default if you're unsure.",
            key="capture_iface",
        )
        if st.button("▶ Start capture", use_container_width=True, type="primary"):
            try:
                with st.spinner("Starting Zeek + ingestion daemon..."):
                    capture_controller.start(capture_iface)
                st.rerun()
            except capture_controller.CaptureError as e:
                st.error(str(e))

    st.markdown("---")

    threshold = st.slider(
        "Threat probability threshold",
        min_value=0.05, max_value=0.95, value=0.85, step=0.05,
        help="Flows with predicted threat probability above this line are flagged as threats.",
        key="threshold",
    )
    row_limit = st.select_slider(
        "Flows to pull from DB", options=[100, 250, 500, 1000], value=500,
        key="row_limit",
    )
    auto_refresh = st.checkbox("Auto-refresh page", value=True, key="auto_refresh")
    refresh_sec = st.slider(
        "Refresh interval (s)", 3, 30, 5, disabled=not auto_refresh, key="refresh_sec",
    )
    if auto_refresh and not HAS_AUTOREFRESH:
        st.caption(
            "⚠ Auto-refresh needs the `streamlit-autorefresh` package: "
            "`pip install streamlit-autorefresh`."
        )

    st.markdown("---")
    st.caption(f"DB: `{os.path.relpath(DB_PATH, BASE_DIR)}`")
    st.caption(f"Model: {'loaded' if model is not None else 'NOT FOUND'}")

# Real Streamlit rerun on a timer (over the existing websocket connection),
# NOT a browser page reload — a page reload would drop session_state and
# reset every slider/checkbox above on each tick, which is what was
# happening before.
if auto_refresh and HAS_AUTOREFRESH:
    st_autorefresh(interval=refresh_sec * 1000, key="sentry_autorefresh_tick")

# ---------------------------------------------------------------------------
# Header + status
# ---------------------------------------------------------------------------
df_conn = fetch_sqlite_logs(row_limit)

status_html = '<span class="status-pill status-down">NO DATA</span>'
if not df_conn.empty and 'timestamp' in df_conn.columns:
    # sqlite's CURRENT_TIMESTAMP (used as the default for this column in
    # zeek_daemon.py) is always UTC. Comparing it against local time here
    # would inflate "age" by the server's UTC offset and falsely show
    # FEED DOWN even while flows are actively arriving.
    latest_ts = pd.to_datetime(df_conn['timestamp']).max()
    age_sec = (datetime.utcnow() - latest_ts).total_seconds()
    if age_sec <= STALE_AFTER_SEC:
        status_html = '<span class="status-pill status-live">● LIVE</span>'
    elif age_sec <= STALE_AFTER_SEC * 6:
        status_html = f'<span class="status-pill status-stale">STALE · last flow {int(age_sec)}s ago</span>'
    else:
        status_html = f'<span class="status-pill status-down">FEED DOWN · last flow {int(age_sec)}s ago</span>'

st.markdown(f"""
<div class="sentry-header">
  <div>
    <div class="sentry-title">EPOCH SENTRY</div>
    <div class="sentry-sub">SIH26145 — AI-based detection of cyber threats in unidirectional IP traffic</div>
  </div>
  <div>{status_html}</div>
</div>
""", unsafe_allow_html=True)

if model is None:
    st.error(f"Model file not found at `{MODEL_PATH}`. Inference is disabled until it's present.")
    st.stop()

if df_conn.empty:
    st.warning("`live_conn` is empty. Start `zeek_daemon.py` (and Zeek itself) to begin streaming flows.")
    st.stop()

# ---------------------------------------------------------------------------
# Feature engineering
#
# NOTE on the two engineered features below: sni_entropy and cipher_encoded
# come from TLS/SSL metadata (Zeek's ssl.log), which this pipeline does not
# currently ingest — only conn.log (+ a DNS entropy enrichment) is wired up.
# They are filled with neutral placeholder values so the model's expected
# input shape is satisfied, but this means those two signals contribute
# nothing to the live predictions right now. This is disclosed to the
# analyst below rather than hidden.
# ---------------------------------------------------------------------------
df = df_conn.copy()
df['byte_ratio'] = df['orig_bytes'] / (df['resp_bytes'] + 1)
state_mapping = {'SF': 0, 'S0': 1, 'REJ': 1, 'RSTR': 1, 'RSTO': 1, 'SH': 1}
df['failed_state_flag'] = df['conn_state'].map(state_mapping).fillna(0)
df['sni_entropy'] = 0.0
df['cipher_encoded'] = -1

FEATURES = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
            'byte_ratio', 'failed_state_flag', 'dns_query_entropy',
            'sni_entropy', 'cipher_encoded']

X = df[FEATURES].fillna(0)
try:
    df['threat_prob'] = model.predict_proba(X)[:, 1]
except Exception as e:
    st.error(f"Model inference failed on current feature set: {e}")
    st.stop()

df['is_threat'] = df['threat_prob'] > threshold
df['timestamp'] = pd.to_datetime(df['timestamp'])

# All-return-traffic-is-near-zero is expected on a unidirectional link, so
# flag that context rather than let byte_ratio look like a bug.
unidirectional_hint = (df['resp_bytes'].fillna(0) == 0).mean() > 0.9

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
threats = df[df['is_threat']]
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f'<div class="kpi-card"><div class="kpi-label">Flows in window</div>'
                f'<div class="kpi-value">{len(df):,}</div></div>', unsafe_allow_html=True)
with c2:
    cls = "crit" if len(threats) > 0 else "ok"
    st.markdown(f'<div class="kpi-card"><div class="kpi-label">Flagged threats</div>'
                f'<div class="kpi-value {cls}">{len(threats)}</div></div>', unsafe_allow_html=True)
with c3:
    st.markdown(f'<div class="kpi-card"><div class="kpi-label">Distinct sources</div>'
                f'<div class="kpi-value">{df["orig_h"].nunique()}</div></div>', unsafe_allow_html=True)
with c4:
    avg_p = df['threat_prob'].mean()
    cls = "warn" if avg_p > threshold * 0.6 else "ok"
    st.markdown(f'<div class="kpi-card"><div class="kpi-label">Mean threat prob.</div>'
                f'<div class="kpi-value {cls}">{avg_p:.2f}</div></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_threats, tab_telemetry, tab_analytics = st.tabs(["Threat Feed", "Telemetry", "Analytics"])

with tab_threats:
    st.markdown('<div class="section-label">Flagged flows, ranked by probability</div>', unsafe_allow_html=True)
    if threats.empty:
        st.success(f"No flows above the {threshold:.2f} threshold in the current window.")
    else:
        show = threats.sort_values('threat_prob', ascending=False)[
            ['timestamp', 'uid', 'orig_h', 'resp_h', 'resp_p', 'conn_state', 'threat_prob']
        ]
        st.dataframe(
            show,
            use_container_width=True,
            hide_index=True,
            column_config={
                "threat_prob": st.column_config.ProgressColumn(
                    "Threat probability", min_value=0.0, max_value=1.0, format="%.2f",
                ),
                "timestamp": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"),
                "orig_h": "Source",
                "resp_h": "Destination",
                "resp_p": "Port",
                "conn_state": "State",
            },
        )
        st.download_button(
            "Export flagged flows (CSV)",
            data=show.to_csv(index=False).encode(),
            file_name=f"epoch_sentry_threats_{datetime.now():%Y%m%d_%H%M%S}.csv",
            mime="text/csv",
        )

with tab_telemetry:
    st.markdown('<div class="section-label">Recent flows</div>', unsafe_allow_html=True)
    st.dataframe(
        df.sort_values('timestamp', ascending=False)[
            ['timestamp', 'uid', 'orig_h', 'resp_h', 'resp_p', 'conn_state', 'threat_prob']
        ],
        use_container_width=True,
        hide_index=True,
        column_config={
            "threat_prob": st.column_config.ProgressColumn(
                "Threat probability", min_value=0.0, max_value=1.0, format="%.2f",
            ),
            "timestamp": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"),
        },
    )

with tab_analytics:
    left, right = st.columns(2)

    with left:
        st.markdown('<div class="section-label">Threat probability over time</div>', unsafe_allow_html=True)
        timeline = alt.Chart(df).mark_circle(size=45, opacity=0.75).encode(
            x=alt.X('timestamp:T', title=None),
            y=alt.Y('threat_prob:Q', title='Threat probability', scale=alt.Scale(domain=[0, 1])),
            color=alt.condition(
                alt.datum.threat_prob > threshold,
                alt.value('#E5484D'),
                alt.value('#4FD1C5'),
            ),
            tooltip=['uid', 'orig_h', 'resp_h', alt.Tooltip('threat_prob:Q', format='.2f')],
        ).properties(height=240)
        rule = alt.Chart(pd.DataFrame({'y': [threshold]})).mark_rule(
            color='#F5A623', strokeDash=[4, 4]
        ).encode(y='y:Q')
        combined = (timeline + rule).configure_view(strokeWidth=0)
        st.altair_chart(combined, use_container_width=True)

    with right:
        st.markdown('<div class="section-label">Top destination ports</div>', unsafe_allow_html=True)
        port_counts = df['resp_p'].value_counts().head(10).reset_index()
        port_counts.columns = ['port', 'count']
        port_chart = alt.Chart(port_counts).mark_bar(color='#4FD1C5').encode(
            x=alt.X('count:Q', title=None),
            y=alt.Y('port:N', sort='-x', title=None),
            tooltip=['port', 'count'],
        ).properties(height=240)
        st.altair_chart(port_chart, use_container_width=True)

    st.markdown('<div class="section-label">Top talkers (by source IP)</div>', unsafe_allow_html=True)
    talkers = df.groupby('orig_h').agg(
        flows=('uid', 'count'),
        mean_threat_prob=('threat_prob', 'mean'),
    ).sort_values('flows', ascending=False).head(10).reset_index()
    st.dataframe(
        talkers, use_container_width=True, hide_index=True,
        column_config={
            "orig_h": "Source IP",
            "mean_threat_prob": st.column_config.ProgressColumn(
                "Avg. threat prob.", min_value=0.0, max_value=1.0, format="%.2f",
            ),
        },
    )

# ---------------------------------------------------------------------------
# Honest disclosure footer
# ---------------------------------------------------------------------------
notes = [
    "`sni_entropy` and `cipher_encoded` are placeholder-valued (no ssl.log ingestion wired up yet) — "
    "TLS-derived signal is not currently contributing to predictions.",
]
if unidirectional_hint:
    notes.append(
        "Over 90% of flows in this window have ~0 response bytes, consistent with a unidirectional link. "
        "`byte_ratio` and `conn_state` were designed assuming bidirectional TCP handshakes and carry weaker "
        "signal here — worth revisiting the feature set against one-way traffic specifically."
    )

st.markdown(
    '<div class="disclosure"><b>Known limitations</b><br>' + "<br>".join(f"— {n}" for n in notes) + "</div>",
    unsafe_allow_html=True,
)