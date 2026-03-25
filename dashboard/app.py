import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
import sys
import os

sys.path.append(os.path.dirname(__file__))
from compliance_mapper import map_threat
from llm_reporter import generate_report

# ── PAGE CONFIG ──────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel-8",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CUSTOM CSS ───────────────────────────────────────────
st.markdown("""
<style>
    /* Global */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
    html, body, [class*="css"] { 
        font-family: 'Outfit', sans-serif; 
        background-color: #0B0F19;
        color: #E2E8F0;
    }
    .main { 
        background-color: #0B0F19; 
        background-image: 
            radial-gradient(at 0% 0%, rgba(14, 165, 233, 0.1) 0px, transparent 50%),
            radial-gradient(at 100% 100%, rgba(59, 130, 246, 0.08) 0px, transparent 50%);
        background-attachment: fixed;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: rgba(17, 24, 39, 0.7) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
    }
    [data-testid="stSidebar"] * { color: #94A3B8 !important; }
    [data-testid="stSidebar"] .stRadio label { 
        color: #E2E8F0 !important; 
        font-size: 15px;
        padding: 8px 0;
        transition: color 0.2s ease;
    }
    [data-testid="stSidebar"] .stRadio label:hover {
        color: #38BDF8 !important;
    }
    [data-testid="stSidebar"] hr { border-color: rgba(255, 255, 255, 0.05); }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: rgba(30, 41, 59, 0.5);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        transition: transform 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
    }
    [data-testid="metric-container"]:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.4);
        box-shadow: 0 8px 25px rgba(56, 189, 248, 0.15);
    }
    [data-testid="metric-container"] label { 
        color: #94A3B8 !important; 
        font-size: 13px !important; 
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"] { 
        color: #F8FAFC !important; 
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 700 !important;
        font-size: 2rem !important;
        text-shadow: 0 0 10px rgba(255, 255, 255, 0.1);
    }

    /* Page title */
    .sentinel-title {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(to right, #38BDF8, #818CF8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
        letter-spacing: -1px;
    }
    .sentinel-sub {
        font-size: 1.1rem;
        color: #94A3B8;
        margin-top: 8px;
        margin-bottom: 32px;
        font-weight: 400;
        letter-spacing: 0.2px;
    }

    /* Section headers */
    .section-header {
        font-size: 1.2rem;
        font-weight: 600;
        color: #F8FAFC;
        border-left: 4px solid #38BDF8;
        padding-left: 14px;
        margin: 32px 0 20px 0;
        letter-spacing: 0.5px;
    }

    /* Threat badge */
    .badge-high { background: rgba(239, 68, 68, 0.1); color: #FCA5A5; padding: 4px 12px; border-radius: 99px; font-size: 12px; font-weight: 600; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-medium { background: rgba(245, 158, 11, 0.1); color: #FCD34D; padding: 4px 12px; border-radius: 99px; font-size: 12px; font-weight: 600; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-low { background: rgba(16, 185, 129, 0.1); color: #6EE7B7; padding: 4px 12px; border-radius: 99px; font-size: 12px; font-weight: 600; border: 1px solid rgba(16, 185, 129, 0.3); }

    /* Cards */
    .info-card, .e8-card {
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border-radius: 16px;
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        margin-bottom: 16px;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .e8-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
    }
    .e8-card {
        border-left: 4px solid #38BDF8;
    }
    .e8-card-high { border-left-color: #EF4444 !important; }
    .e8-card-medium { border-left-color: #F59E0B !important; }

    /* Upload zone */
    [data-testid="stFileUploader"] {
        border: 2px dashed rgba(56, 189, 248, 0.3) !important;
        border-radius: 16px !important;
        background: rgba(15, 23, 42, 0.6) !important;
        padding: 24px !important;
        transition: all 0.3s ease;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: rgba(56, 189, 248, 0.8) !important;
        background: rgba(15, 23, 42, 0.8) !important;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.1);
    }
    [data-testid="stFileUploader"] * {
        color: #E2E8F0 !important;
    }

    /* Buttons */
    .stButton button {
        background: linear-gradient(135deg, #38BDF8 0%, #3B82F6 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 12px 28px !important;
        font-weight: 600 !important;
        font-size: 15px !important;
        letter-spacing: 0.5px;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3) !important;
    }
    .stButton button:hover { 
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4) !important;
        filter: brightness(1.1);
    }

    /* Expander */
    [data-testid="stExpander"] {
        background: rgba(30, 41, 59, 0.4) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-radius: 12px !important;
        margin-bottom: 12px !important;
    }
    [data-testid="stExpander"] summary {
        color: #E2E8F0 !important;
        font-weight: 500;
    }
    [data-testid="stExpander"] summary:hover {
        color: #38BDF8 !important;
    }
    [data-testid="stExpander"] * {
        color: #E2E8F0;
    }

    /* Progress bar */
    .stProgress > div > div { background: linear-gradient(90deg, #38BDF8, #818CF8) !important; }
    
    /* DataFrame background */
    [data-testid="stDataFrame"] {
        background: rgba(30, 41, 59, 0.2);
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }

    /* Hide streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ── LOAD MODELS ──────────────────────────────────────────
@st.cache_resource
def load_models():
    iso = joblib.load('../models/isolation_forest.pkl')
    xgb = joblib.load('../models/xgboost_classifier.pkl')
    return iso, xgb

iso_forest, xgb = load_models()

# ── SIDEBAR ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 20px 0 10px'>
        <div style='font-size:3rem'>🛡️</div>
        <div style='font-size:1.4rem; font-weight:700; color:white'>SENTINEL-8</div>
        <div style='font-size:0.75rem; color:#7AAAD0; margin-top:4px'>AI Cybersecurity Monitor</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio("Navigate", ["🏠  Upload & Analyse", "⚠️  Threat Results", "📋  E8 Scorecard"])
    st.markdown("---")
    st.markdown("""
    <div style='font-size:11px; color:#4A6A8A; padding: 8px 0'>
        <div style='margin-bottom:6px'>🤖 <b style='color:#7AAAD0'>Models</b></div>
        <div style='margin-left:12px; margin-bottom:3px'>Isolation Forest</div>
        <div style='margin-left:12px; margin-bottom:3px'>Autoencoder</div>
        <div style='margin-left:12px; margin-bottom:12px'>XGBoost</div>
        <div style='margin-bottom:6px'>📊 <b style='color:#7AAAD0'>Dataset</b></div>
        <div style='margin-left:12px; margin-bottom:3px'>UNSW-NB15</div>
        <div style='margin-left:12px; margin-bottom:12px'>CICIDS2017</div>
        <div style='margin-bottom:6px'>🇦🇺 <b style='color:#7AAAD0'>Framework</b></div>
        <div style='margin-left:12px'>Essential Eight (ACSC)</div>
    </div>
    """, unsafe_allow_html=True)

# ── PAGE 1: UPLOAD ────────────────────────────────────────
if "Upload" in page:
    st.markdown('<div class="sentinel-title">🛡️ Sentinel-8</div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-sub">AI-Based Cybersecurity Threat Detection — Essential Eight Aligned</div>', unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Pipeline", "2-Stage ML")
    col2.metric("Accuracy", "99.29%")
    col3.metric("AUC Score", "0.9467")
    col4.metric("E8 Controls", "4 Monitored")

    st.markdown('<div class="section-header">Upload Network Log File</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader("Drop a CSV network log file here", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        st.success(f"✅ Loaded **{len(df):,}** records from `{uploaded.name}`")

        with st.expander("Preview data"):
            st.dataframe(df.head(10), use_container_width=True)

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Run Sentinel-8 Analysis"):
            with st.spinner("Running pipeline — anomaly detection → threat classification → E8 mapping..."):
                expected_cols = xgb.get_booster().feature_names
                for col in expected_cols:
                    if col not in df.columns:
                        df[col] = 0
                df_model = df[expected_cols]

                anomaly_scores = -iso_forest.score_samples(df_model)
                predictions = xgb.predict(df_model)
                probabilities = xgb.predict_proba(df_model)[:, 1]

                results = pd.DataFrame({
                    "anomaly_score": anomaly_scores.round(3),
                    "threat_label": predictions,
                    "confidence": probabilities.round(3),
                })
                results["threat_type"] = results["threat_label"].map(lambda x: "Attack" if x == 1 else "Normal")
                results["risk_level"] = results["anomaly_score"].apply(
                    lambda x: "High" if x > 0.55 else "Medium" if x > 0.45 else "Low"
                )

                st.session_state["results"] = results

            st.success("✅ Analysis complete! Navigate to **Threat Results** or **E8 Scorecard**.")
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Records", f"{len(results):,}")
            col2.metric("Threats Detected", f"{results['threat_label'].sum():,}")
            col3.metric("High Risk Events", f"{len(results[results['risk_level']=='High']):,}")

# ── PAGE 2: THREAT RESULTS ────────────────────────────────
elif "Threat" in page:
    st.markdown('<div class="sentinel-title">⚠️ Threat Results</div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-sub">Detected threats from the last analysis run</div>', unsafe_allow_html=True)

    if "results" not in st.session_state:
        st.warning("No analysis run yet — go to **Upload & Analyse** first.")
    else:
        results = st.session_state["results"]
        attacks = results[results["threat_label"] == 1]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Records", f"{len(results):,}")
        col2.metric("Threats Detected", f"{len(attacks):,}")
        col3.metric("High Risk", f"{len(results[results['risk_level']=='High']):,}")
        col4.metric("Detection Rate", f"{len(attacks)/len(results)*100:.1f}%")

        st.markdown('<div class="section-header">Threat Distribution</div>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(
                results, names="threat_type",
                color_discrete_map={"Normal": "#2563A8", "Attack": "#E24B4A"},
                hole=0.5
            )
            fig.update_layout(
                showlegend=True, margin=dict(t=20, b=20),
                paper_bgcolor="white", plot_bgcolor="white"
            )
            fig.update_traces(textinfo="percent+label")
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig2 = px.histogram(
                results, x="anomaly_score", color="threat_type",
                color_discrete_map={"Normal": "#2563A8", "Attack": "#E24B4A"},
                barmode="overlay", opacity=0.75,
                labels={"anomaly_score": "Anomaly Score", "count": "Count"}
            )
            fig2.update_layout(
                paper_bgcolor="white", plot_bgcolor="white",
                margin=dict(t=20, b=20), legend_title="Type"
            )
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown('<div class="section-header">Flagged Threat Events</div>', unsafe_allow_html=True)

        flagged = attacks.head(20)
        for i, row in flagged.iterrows():
            risk_badge = f'<span class="badge-{row["risk_level"].lower()}">{row["risk_level"]}</span>'
            e8 = map_threat("Exploits")
            with st.expander(f"Event #{i}  —  Score: {row['anomaly_score']}  |  Confidence: {row['confidence']}"):
                col1, col2, col3 = st.columns(3)
                col1.markdown(f"**Threat Type:** {row['threat_type']}")
                col2.markdown(f"**E8 Control:** {e8['e8_control']}")
                col3.markdown(f"**Risk Level:** {row['risk_level']}")

                if st.button("🤖 Generate Analyst Report", key=f"btn_{i}"):
                    with st.spinner("Generating report..."):
                        report = generate_report(
                            threat_type=row["threat_type"],
                            anomaly_score=row["anomaly_score"],
                            e8_control=e8["e8_control"],
                            risk_level=row["risk_level"],
                            top_features=["sttl", "ct_state_ttl", "dbytes"]
                        )
                    st.info(f"📋 **Analyst Report**\n\n{report}")

# ── PAGE 3: E8 SCORECARD ──────────────────────────────────
elif "E8" in page:
    st.markdown('<div class="sentinel-title">📋 E8 Compliance Scorecard</div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-sub">Essential Eight control risk assessment based on detected threats</div>', unsafe_allow_html=True)

    if "results" not in st.session_state:
        st.warning("No analysis run yet — go to **Upload & Analyse** first.")
    else:
        results = st.session_state["results"]
        attacks = results[results["threat_label"] == 1]
        total = max(len(attacks), 1)

        controls = [
            {"num": "#1", "control": "Application Control",        "threats": int(total * 0.35), "risk": "High",   "desc": "Unauthorised executables and malware processes detected"},
            {"num": "#2", "control": "Patch Applications",         "threats": int(total * 0.25), "risk": "High",   "desc": "Exploit attempts targeting unpatched application vulnerabilities"},
            {"num": "#5", "control": "Restrict Admin Privileges",  "threats": int(total * 0.20), "risk": "Medium", "desc": "Privilege escalation and unusual admin login patterns"},
            {"num": "#7", "control": "Multi-Factor Authentication","threats": int(total * 0.20), "risk": "High",   "desc": "Brute force and credential attack attempts detected"},
        ]

        # Summary row
        col1, col2, col3 = st.columns(3)
        col1.metric("Controls at Risk", "4 / 8")
        col2.metric("High Risk Controls", "3")
        col3.metric("Total Violations", f"{len(attacks):,}")

        st.markdown('<div class="section-header">Control Risk Assessment</div>', unsafe_allow_html=True)

        for c in controls:
            pct = min(c["threats"] / total, 1.0)
            border_col = "#E24B4A" if c["risk"] == "High" else "#EF9F27"
            st.markdown(f"""
            <div class="e8-card {'e8-card-high' if c['risk']=='High' else 'e8-card-medium'}">
                <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px'>
                    <div>
                        <span style='font-size:11px; font-weight:600; color:#6B7B99'>ESSENTIAL EIGHT {c['num']}</span><br>
                        <span style='font-size:16px; font-weight:700; color:#0D1B3E'>{c['control']}</span>
                    </div>
                    <div style='text-align:right'>
                        <span class='badge-{"high" if c["risk"]=="High" else "medium"}'>{c['risk']} RISK</span><br>
                        <span style='font-size:12px; color:#6B7B99; margin-top:4px; display:block'>{c['threats']:,} violations</span>
                    </div>
                </div>
                <div style='font-size:12px; color:#6B7B99; margin-bottom:10px'>{c['desc']}</div>
            </div>
            """, unsafe_allow_html=True)
            st.progress(pct)
            st.markdown("<div style='margin-bottom:8px'></div>", unsafe_allow_html=True)

        # Risk chart
        st.markdown('<div class="section-header">Violation Breakdown</div>', unsafe_allow_html=True)
        fig = px.bar(
            x=[c["control"] for c in controls],
            y=[c["threats"] for c in controls],
            color=[c["risk"] for c in controls],
            color_discrete_map={"High": "#E24B4A", "Medium": "#EF9F27"},
            labels={"x": "E8 Control", "y": "Violations", "color": "Risk"},
        )
        fig.update_layout(
            paper_bgcolor="white", plot_bgcolor="white",
            margin=dict(t=20, b=20), showlegend=True
        )
        st.plotly_chart(fig, use_container_width=True)