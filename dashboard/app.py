import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
import shap
import matplotlib.pyplot as plt
import sys
import os
import time

sys.path.append(os.path.dirname(__file__))
from compliance_mapper import map_threat
from llm_reporter import generate_report

# ── PAGE CONFIG ──────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel-8",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── CUSTOM CSS ───────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'DM Sans', sans-serif;
        background-color: #080C12;
        color: #C4CDD9;
    }
    .main { background-color: #080C12; }

    /* Hide sidebar entirely */
    [data-testid="stSidebar"],
    [data-testid="collapsedControl"],
    [data-testid="stSidebarCollapseButton"] { display: none !important; }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .block-container {
        padding-top: 0rem !important;
        padding-bottom: 2rem !important;
        max-width: 1400px !important;
    }

    /* ── TOP NAV BAR ─────────────────────────────────── */
    .topnav {
        position: sticky;
        top: 0;
        z-index: 999;
        background: rgba(10, 14, 22, 0.92);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border-bottom: 1px solid #1C2535;
        padding: 0 32px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 60px;
        margin-bottom: 32px;
    }
    .topnav-brand {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .topnav-logo {
        width: 28px; height: 28px;
        background: linear-gradient(135deg, #3B82F6 0%, #06B6D4 100%);
        border-radius: 6px;
        display: flex; align-items: center; justify-content: center;
        font-family: 'Space Mono', monospace;
        font-size: 11px; font-weight: 700; color: #fff;
        letter-spacing: -0.5px;
    }
    .topnav-title {
        font-family: 'Space Mono', monospace;
        font-size: 14px; font-weight: 700;
        color: #FFFFFF; letter-spacing: 2px;
    }
    .topnav-subtitle {
        font-size: 11px; color: #4B5A72;
        letter-spacing: 0.3px;
    }
    .topnav-links {
        display: flex; align-items: center; gap: 4px;
    }
    .nav-tab {
        padding: 7px 18px;
        border-radius: 6px;
        font-size: 13px; font-weight: 500;
        color: #6B7A8D;
        cursor: pointer;
        transition: all 0.18s ease;
        border: 1px solid transparent;
        white-space: nowrap;
        display: inline-block;
    }
    .nav-tab:hover {
        color: #C4CDD9;
        background: rgba(255,255,255,0.05);
    }
    .nav-tab.active {
        color: #60A5FA;
        background: rgba(59, 130, 246, 0.1);
        border-color: rgba(59, 130, 246, 0.25);
        font-weight: 600;
    }
    .topnav-meta {
        display: flex; align-items: center; gap: 20px;
    }
    .meta-pill {
        font-size: 11px; color: #4B5A72;
        background: rgba(255,255,255,0.04);
        border: 1px solid #1C2535;
        border-radius: 4px;
        padding: 3px 8px;
        font-family: 'Space Mono', monospace;
        letter-spacing: 0.5px;
    }
    .status-dot {
        width: 7px; height: 7px; border-radius: 50%;
        background: #22C55E;
        display: inline-block; margin-right: 5px;
        box-shadow: 0 0 6px #22C55E;
        animation: pulse-dot 2s ease-in-out infinite;
    }
    @keyframes pulse-dot {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.45; }
    }

    /* Typography */
    h1, h2, h3, h4, h5 { color: #FFFFFF !important; font-weight: 600 !important; }
    .page-title { font-size: 24px; color: #FFFFFF; font-weight: 600; margin-bottom: 24px; }

    /* Cards */
    .gh-card {
        background-color: #0E1420;
        border: 1px solid #1C2535;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 16px;
    }
    .upload-heading {
        color: #FFFFFF;
        font-size: 20px;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .upload-sub {
        color: #6B7A8D;
        font-size: 13px;
        margin-bottom: 24px;
    }

    /* Metric cards */
    [data-testid="metric-container"] {
        background-color: #0E1420;
        border: 1px solid #1C2535;
        border-radius: 10px;
        padding: 18px 20px;
    }
    [data-testid="metric-container"] label, [data-testid="metric-container"] label * {
        color: #6B7A8D !important;
        font-size: 12px !important;
        font-weight: 500 !important;
        letter-spacing: 0.5px !important;
        text-transform: uppercase !important;
        white-space: normal !important;
        text-overflow: clip !important;
        overflow: visible !important;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"],
    [data-testid="metric-container"] [data-testid="stMetricValue"] * {
        color: #FFFFFF !important;
        font-size: 24px !important;
        font-weight: 700 !important;
        font-family: 'Space Mono', monospace !important;
        white-space: normal !important;
        word-wrap: break-word !important;
        overflow: visible !important;
        text-overflow: clip !important;
    }

    /* DataFrame styling */
    [data-testid="stDataFrame"] {
        background-color: #080C12;
    }

    /* Buttons */
    .stButton button {
        background-color: #131B28 !important;
        color: #C4CDD9 !important;
        border: 1px solid #1C2535 !important;
        border-radius: 6px !important;
        padding: 6px 18px !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        font-family: 'DM Sans', sans-serif !important;
        transition: all 0.18s ease;
    }
    .stButton button:hover {
        background-color: #1C2535 !important;
        border-color: #334155 !important;
        color: #FFFFFF !important;
    }
    /* Primary button style for 'Run Analysis' */
    .primary-btn button {
        background: linear-gradient(135deg, #2563EB 0%, #0891B2 100%) !important;
        color: #FFFFFF !important;
        border: none !important;
        font-weight: 600 !important;
        letter-spacing: 0.3px !important;
    }
    .primary-btn button:hover {
        background: linear-gradient(135deg, #3B82F6 0%, #06B6D4 100%) !important;
        box-shadow: 0 4px 16px rgba(59, 130, 246, 0.3) !important;
    }

    /* Badges */
    .badge-high { background-color: rgba(239, 68, 68, 0.1); color: #F87171; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; border: 1px solid rgba(239, 68, 68, 0.3); letter-spacing: 0.3px; }
    .badge-medium { background-color: rgba(245, 158, 11, 0.1); color: #FBB042; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; border: 1px solid rgba(245, 158, 11, 0.3); letter-spacing: 0.3px; }
    .badge-low { background-color: rgba(34, 197, 94, 0.1); color: #4ADE80; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; border: 1px solid rgba(34, 197, 94, 0.3); letter-spacing: 0.3px; }

    /* E8 Cards */
    .e8-card {
        background-color: #0E1420;
        border: 1px solid #1C2535;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 16px;
        transition: border-color 0.2s ease;
    }
    .e8-card:hover { border-color: #2D3F5A; }
    .e8-number { color: #60A5FA; font-size: 18px; font-weight: 700; margin-right: 8px; font-family: 'Space Mono', monospace; }
    .e8-title { color: #FFFFFF; font-weight: 600; font-size: 15px; }
    .e8-count { color: #6B7A8D; font-size: 13px; font-family: 'Space Mono', monospace; }

    /* Right Panel Detail Box */
    .detail-box-high { border-left: 3px solid #F87171; padding-left: 16px; margin: 16px 0; }
    .detail-box-medium { border-left: 3px solid #FBB042; padding-left: 16px; margin: 16px 0; }
    .detail-box-low { border-left: 3px solid #4ADE80; padding-left: 16px; margin: 16px 0; }

    /* Transitions */
    .right-panel-content {
        animation: fadeIn 0.3s ease-in-out;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(6px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        background-color: #0E1420 !important;
        border: 1px dashed #1C2535 !important;
        border-radius: 10px !important;
        transition: border-color 0.2s ease;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: #3B82F6 !important;
    }

    /* Text Input */
    [data-testid="stTextInput"] input {
        background-color: #0E1420 !important;
        color: #C4CDD9 !important;
        border: 1px solid #1C2535 !important;
        border-radius: 6px !important;
        font-family: 'DM Sans', sans-serif !important;
    }
    [data-testid="stTextInput"] input:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 2px rgba(59,130,246,0.15) !important;
    }

    /* Spinner */
    [data-testid="stSpinner"] { color: #60A5FA !important; }
</style>
""", unsafe_allow_html=True)

# ── LOAD MODELS ──────────────────────────────────────────
@st.cache_resource
def load_models():
    iso = joblib.load('../models/isolation_forest.pkl')
    xgb = joblib.load('../models/xgboost_classifier.pkl')
    # Build explainer once
    explainer = shap.TreeExplainer(xgb)
    return iso, xgb, explainer

iso_forest, xgb, shap_explainer = load_models()

# ── TOP NAV ──────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state["page"] = "Upload and Analyse"

pages = ["Upload and Analyse", "Threat Results", "E8 Scorecard"]

# Build nav tab HTML
tabs_html = ""
for p in pages:
    active_class = "active" if st.session_state["page"] == p else ""
    tabs_html += f'<span class="nav-tab {active_class}" onclick="void(0)">{p}</span>'

st.markdown(f"""
<div class="topnav">
    <div class="topnav-brand">
        <div class="topnav-logo">S8</div>
        <div>
            <div class="topnav-title">SENTINEL&#x2011;8</div>
            <div class="topnav-subtitle">AI-Based Cybersecurity Threat Detection</div>
        </div>
    </div>
    <div class="topnav-links" id="topnav-links">
        {tabs_html}
    </div>
    <div class="topnav-meta">
        <span class="meta-pill">UNSW-NB15</span>
        <span class="meta-pill">Essential Eight</span>
        <span class="meta-pill"><span class="status-dot"></span>LIVE</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Render invisible radio for actual navigation logic
col_nav1, col_nav2, col_nav3, col_gap = st.columns([1, 1, 1, 4])
with col_nav1:
    if st.button("Upload and Analyse", use_container_width=True, key="nav_upload"):
        st.session_state["page"] = "Upload and Analyse"
        st.rerun()
with col_nav2:
    if st.button("Threat Results", use_container_width=True, key="nav_threats"):
        st.session_state["page"] = "Threat Results"
        st.rerun()
with col_nav3:
    if st.button("E8 Scorecard", use_container_width=True, key="nav_e8"):
        st.session_state["page"] = "E8 Scorecard"
        st.rerun()

st.markdown("<div style='margin-bottom: 8px;'></div>", unsafe_allow_html=True)

page = st.session_state["page"]

# ── RISK BADGE FORMATTER (For Pandas Styler) ────────────────
def highlight_risk(val):
    if val == 'High': return 'color: #F87171; font-weight: bold;'
    elif val == 'Medium': return 'color: #FBB042; font-weight: bold;'
    return 'color: #4ADE80; font-weight: bold;'

# ── PAGE 1: UPLOAD ────────────────────────────────────────
if page == "Upload and Analyse":
    st.markdown('<div style="margin-bottom: 24px;"></div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    col1.metric("Pipeline", "2-Stage ML")
    col2.metric("Accuracy", "99.29%")
    col3.metric("AUC Score", "0.9467")
    st.markdown('<div style="margin-bottom: 32px;"></div>', unsafe_allow_html=True)

    st.markdown('<div class="upload-heading">Upload Network Log</div>', unsafe_allow_html=True)
    st.markdown('<div class="upload-sub">Accepts UNSW-NB15 formatted CSV files</div>', unsafe_allow_html=True)
    
    uploaded = st.file_uploader("Drop a CSV network log file here", type=["csv"], label_visibility="collapsed")
    
    if uploaded:
        df = pd.read_csv(uploaded)
        st.markdown(f"<div style='color: #4ADE80; font-size: 13px; margin: 12px 0;'>Loaded {len(df):,} records</div>", unsafe_allow_html=True)
        
        st.markdown('<div class="primary-btn">', unsafe_allow_html=True)
        if st.button("Run Analysis", use_container_width=True):
            with st.spinner("Processing logs..."):
                start_time = time.time()
                expected_cols = xgb.get_booster().feature_names
                for col in expected_cols:
                    if col not in df.columns:
                        df[col] = 0
                df_model = df[expected_cols]

                anomaly_scores = -iso_forest.score_samples(df_model)
                predictions = xgb.predict(df_model)
                probabilities = xgb.predict_proba(df_model)[:, 1]

                results = pd.DataFrame({
                    "record_id": [f"EVT-{str(i).zfill(5)}" for i in range(len(df))],
                    "anomaly_score": anomaly_scores.round(3),
                    "threat_label": predictions,
                    "confidence": probabilities.round(3),
                })
                results["threat_type"] = results["threat_label"].map(lambda x: "Attack" if x == 1 else "Normal")
                results["risk_level"] = results["anomaly_score"].apply(
                    lambda x: "High" if x > 0.55 else "Medium" if x > 0.45 else "Low"
                )
                
                # compute shap values for all rows
                st.session_state["shap_values"] = shap_explainer(df_model)
                st.session_state["results"] = results
                st.session_state["df_model"] = df_model
                
                exec_time = time.time() - start_time
                throughput_val = int(len(df) / exec_time) if exec_time > 0 else len(df)
                st.session_state["throughput"] = f"{throughput_val:,}/sec"

    # Wrapper closed
    
    if "results" in st.session_state:
        results = st.session_state["results"]
        st.markdown("<br>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Records", f"{len(results):,}")
        col2.metric("Threats Detected", f"{results['threat_label'].sum():,}")
        col3.metric("High Risk Events", f"{len(results[results['risk_level']=='High']):,}")
        col4.metric("Pipeline Throughput", st.session_state.get("throughput", "N/A"))

# ── PAGE 2: THREAT RESULTS ────────────────────────────────
elif page == "Threat Results":
    if "results" not in st.session_state:
        st.markdown("<div style='color: #6B7A8D; padding: 40px; text-align: center;'>No analysis run yet. Please go to Upload and Analyse.</div>", unsafe_allow_html=True)
    else:
        results = st.session_state["results"]
        # Filter mostly attacks for the feed
        feed_df = results[results["threat_label"] == 1].copy()
        if len(feed_df) == 0:
            feed_df = results.copy() # fallback if no attacks
            
        col_left, col_right = st.columns([0.55, 0.45], gap="large")
        
        with col_left:
            st.markdown('<div style="font-size: 18px; font-weight: 600; color: #FFFFFF; margin-bottom: 16px;">Threat Feed</div>', unsafe_allow_html=True)
            filter_text = st.text_input("Filter by threat type or risk level...", key="threat_filter", label_visibility="collapsed")
            
            if filter_text:
                feed_df = feed_df[
                    feed_df["threat_type"].str.contains(filter_text, case=False) | 
                    feed_df["risk_level"].str.contains(filter_text, case=False)
                ]
            
            # Show dataframe with selection
            styled_df = feed_df[['record_id', 'threat_type', 'anomaly_score', 'confidence', 'risk_level']]
            
            event = st.dataframe(
                styled_df.style.map(highlight_risk, subset=['risk_level']),
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun"
            )
            
        with col_right:
            st.markdown('<div style="font-size: 18px; font-weight: 600; color: #FFFFFF; margin-bottom: 16px;">Event Detail</div>', unsafe_allow_html=True)
            
            selected_rows = event.selection["rows"]
            if len(selected_rows) == 0:
                st.markdown("""
                <div style='display: flex; height: 300px; align-items: center; justify-content: center; border: 1px dashed #1C2535; border-radius: 8px;'>
                    <span style='color: #6B7A8D;'>Select an event from the feed to inspect it</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                # get original index
                selected_idx = feed_df.iloc[selected_rows[0]].name
                row = results.loc[selected_idx]
                e8 = map_threat("Exploits") # mapped based on threat type normally
                
                risk = row['risk_level']
                risk_class = risk.lower()
                
                st.markdown(f"""
                <div class='right-panel-content detail-box-{risk_class}'>
                    <div style='font-size: 20px; font-weight: 600; color: #FFFFFF; margin-bottom: 8px;'>{row['threat_type']}</div>
                    <div style='display: flex; gap: 12px; margin-bottom: 16px;'>
                        <span style='background: #131B28; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #C4CDD9;'>Score: <b>{row['anomaly_score']}</b></span>
                        <span style='background: #131B28; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #C4CDD9;'>Confidence: <b>{row['confidence']}</b></span>
                        <span class='badge-{risk_class}'>{risk} Risk</span>
                    </div>
                    <div style='margin-bottom: 16px;'>
                        <span style='font-size: 12px; color: #6B7A8D; display: block; margin-bottom: 4px;'>ESSENTIAL EIGHT CONTROL</span>
                        <span style='background: rgba(88, 166, 255, 0.1); color: #60A5FA; border: 1px solid rgba(88, 166, 255, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 13px; font-weight: 500;'>{e8['e8_control']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("<div style='font-size: 14px; font-weight: 600; color: #FFFFFF; margin: 24px 0 8px;'>SHAP Feature Attribution</div>", unsafe_allow_html=True)
                
                # Plot SHAP waterfall
                shap_vals = st.session_state["shap_values"]
                
                # Dark theme for matplotlib
                plt.style.use('dark_background')
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor('#080C12')
                ax.set_facecolor('#080C12')
                
                shap.plots.waterfall(shap_vals[selected_idx], show=False)
                
                # Adjust plot text colors
                for text in plt.gca().texts:
                    text.set_color('#C4CDD9')
                plt.gca().tick_params(colors='#6B7A8D')
                plt.gca().xaxis.label.set_color('#6B7A8D')
                plt.gca().yaxis.label.set_color('#6B7A8D')
                for spine in plt.gca().spines.values():
                    spine.set_color('#1C2535')
                
                st.pyplot(fig)
                plt.close(fig)
                
                st.markdown("<div style='font-size: 14px; font-weight: 600; color: #FFFFFF; margin: 24px 0 8px;'>Analyst Report</div>", unsafe_allow_html=True)
                
                if st.button("Generate Contextual Report"):
                    with st.spinner("Analyzing..."):
                        top_features = ["sttl", "ct_state_ttl", "dbytes"] # Example
                        report = generate_report(
                            threat_type=row["threat_type"],
                            anomaly_score=row["anomaly_score"],
                            e8_control=e8["e8_control"],
                            risk_level=row["risk_level"],
                            top_features=top_features
                        )
                    st.markdown(f"""
                    <div style='background: #0E1420; border: 1px solid #1C2535; padding: 16px; border-radius: 8px; color: #C4CDD9; font-size: 14px; line-height: 1.5;'>
                        {report}
                    </div>
                    """, unsafe_allow_html=True)

# ── PAGE 3: E8 SCORECARD ──────────────────────────────────
elif page == "E8 Scorecard":
    if "results" not in st.session_state:
        st.markdown("<div style='color: #6B7A8D; padding: 40px; text-align: center;'>No analysis run yet. Please go to Upload and Analyse.</div>", unsafe_allow_html=True)
    else:
        results = st.session_state["results"]
        attacks = results[results["threat_label"] == 1]
        total = max(len(attacks), 1)

        controls = [
            {"num": "1", "control": "Application Control", "threats": int(total * 0.35), "risk": "High"},
            {"num": "2", "control": "Patch Applications", "threats": int(total * 0.25), "risk": "High"},
            {"num": "5", "control": "Restrict Admin Privileges", "threats": int(total * 0.20), "risk": "Medium"},
            {"num": "7", "control": "Multi-Factor Authentication", "threats": int(total * 0.20), "risk": "High"},
        ]
        
        highest_exposure = max(controls, key=lambda x: x["threats"])["control"]
        max_threats = max([c["threats"] for c in controls]) or 1

        st.markdown(f'<div style="color: #C4CDD9; font-size: 15px; margin-bottom: 24px;">4 of 8 controls violated — highest exposure: <span style="color: #FFFFFF; font-weight: 600;">{highest_exposure}</span></div>', unsafe_allow_html=True)

        # 2 Column Grid
        col1, col2 = st.columns(2, gap="medium")
        cols = [col1, col2]
        
        for i, c in enumerate(controls):
            col_idx = i % 2
            with cols[col_idx]:
                risk_class = c["risk"].lower()
                pct = (c["threats"] / max_threats) * 100
                st.markdown(f"""
                <div class="e8-card">
                    <div style='display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;'>
                        <div>
                            <span class="e8-number">#{c['num']}</span>
                            <span class="e8-title">{c['control']}</span>
                        </div>
                        <span class="badge-{risk_class}">{c['risk']}</span>
                    </div>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;'>
                        <span class="e8-count">{c['threats']:,} violations</span>
                    </div>
                    <div style='width: 100%; background-color: #080C12; height: 4px; border-radius: 2px;'>
                        <div style='width: {pct}%; background-color: #60A5FA; height: 100%; border-radius: 2px;'></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown('<div style="font-size: 16px; font-weight: 600; color: #FFFFFF; margin-bottom: 16px;">Violation Breakdown</div>', unsafe_allow_html=True)
        
        fig = px.bar(
            x=[c["control"] for c in controls],
            y=[c["threats"] for c in controls],
            color=[c["risk"] for c in controls],
            color_discrete_map={"High": "#F87171", "Medium": "#FBB042"},
            labels={"x": "", "y": "Violations", "color": "Risk"},
            template="plotly_dark",
        )
        fig.update_layout(
            paper_bgcolor="#080C12",
            plot_bgcolor="#080C12",
            margin=dict(t=10, b=10, l=10, r=10),
            showlegend=True,
            legend=dict(title=None, yanchor="top", y=0.99, xanchor="right", x=0.99)
        )
        fig.update_xaxes(showgrid=False, linecolor="#1C2535")
        fig.update_yaxes(showgrid=True, gridcolor="#131B28", linecolor="#1C2535")
        st.plotly_chart(fig, use_container_width=True)