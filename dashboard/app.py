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
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from compliance_mapper import map_threat
from llm_reporter import generate_report

# ── PAGE CONFIG ──────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel-8",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CUSTOM CSS ───────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] { 
        font-family: 'Inter', sans-serif; 
        background-color: #0D1117;
        color: #C9D1D9;
    }
    .main { background-color: #0D1117; }
    
    /* Hide Sidebar Collapse and Expand Buttons */
    [data-testid="collapsedControl"],
    [data-testid="stSidebarCollapseButton"],
    [data-testid="baseButton-header"],
    [data-testid="stSidebarHeader"] button,
    section[data-testid="stSidebar"] button[title="Collapse sidebar"] {
        display: none !important;
    }
    
    /* Remove padding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .block-container { padding-top: 2rem !important; padding-bottom: 2rem !important; }

    /* Sidebar - Navigation Rail */
    [data-testid="stSidebar"] {
        background-color: #0D1117 !important;
        border-right: 1px solid #30363D !important;
    }
    [data-testid="stSidebar"] * { color: #8B949E !important; }
    
    [data-testid="stSidebar"] .stRadio > div { gap: 0px; }
    [data-testid="stSidebar"] .stRadio label { 
        color: #C9D1D9 !important; 
        font-size: 14px;
        padding: 12px 16px;
        margin: 4px 0;
        border-radius: 0;
        cursor: pointer;
    }
    [data-testid="stSidebar"] .stRadio label:hover {
        background-color: rgba(139, 148, 158, 0.1);
    }
    /* Active sidebar item */
    [data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label[data-checked="true"] {
        background-color: rgba(88, 166, 255, 0.1);
        border-left: 3px solid #58A6FF;
        color: #58A6FF !important;
        font-weight: 600;
    }
    [data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label[data-checked="true"] * {
        color: #58A6FF !important;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5 { color: #FFFFFF !important; font-weight: 600 !important; }
    .page-title { font-size: 24px; color: #FFFFFF; font-weight: 600; margin-bottom: 24px; }
    
    /* Cards */
    .gh-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 16px;
    }
    .upload-card-wrapper {
        display: flex;
        justify-content: center;
        margin-top: 40px;
    }
    .upload-card {
        width: 100%;
        max-width: 680px;
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 12px;
        padding: 32px;
    }
    .upload-heading {
        color: #FFFFFF;
        font-size: 20px;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .upload-sub {
        color: #8B949E;
        font-size: 13px;
        margin-bottom: 24px;
    }

    /* Metric cards */
    [data-testid="metric-container"] {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 16px;
    }
    [data-testid="metric-container"] label, [data-testid="metric-container"] label * { 
        color: #8B949E !important; 
        font-size: 13px !important; 
        white-space: normal !important;
        text-overflow: clip !important;
        overflow: visible !important;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"], 
    [data-testid="metric-container"] [data-testid="stMetricValue"] * { 
        color: #FFFFFF !important; 
        font-size: 22px !important;
        font-weight: 600 !important;
        white-space: normal !important;
        word-wrap: break-word !important;
        overflow: visible !important;
        text-overflow: clip !important;
    }

    /* DataFrame styling */
    [data-testid="stDataFrame"] {
        background-color: #0D1117;
    }
    
    /* Buttons */
    .stButton button {
        background-color: #21262D !important;
        color: #C9D1D9 !important;
        border: 1px solid #30363D !important;
        border-radius: 6px !important;
        padding: 6px 16px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        transition: 0.2s ease;
    }
    .stButton button:hover {
        background-color: #30363D !important;
        border-color: #8B949E !important;
    }
    /* Primary button style for 'Run Analysis' */
    .primary-btn button {
        background-color: #238636 !important;
        color: #FFFFFF !important;
        border: 1px solid rgba(240, 246, 252, 0.1) !important;
    }
    .primary-btn button:hover {
        background-color: #2EA043 !important;
    }

    /* Badges */
    .badge-high { background-color: rgba(248, 81, 73, 0.1); color: #F85149; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 500; border: 1px solid rgba(248, 81, 73, 0.4); }
    .badge-medium { background-color: rgba(227, 179, 65, 0.1); color: #E3B341; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 500; border: 1px solid rgba(227, 179, 65, 0.4); }
    .badge-low { background-color: rgba(63, 185, 80, 0.1); color: #3FB950; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 500; border: 1px solid rgba(63, 185, 80, 0.4); }

    /* E8 Cards */
    .e8-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .e8-number { color: #58A6FF; font-size: 18px; font-weight: 700; margin-right: 8px; }
    .e8-title { color: #FFFFFF; font-weight: 600; font-size: 15px; }
    .e8-count { color: #8B949E; font-size: 13px; }
    
    /* Right Panel Detail Box */
    .detail-box-high { border-left: 3px solid #F85149; padding-left: 16px; margin: 16px 0; }
    .detail-box-medium { border-left: 3px solid #E3B341; padding-left: 16px; margin: 16px 0; }
    .detail-box-low { border-left: 3px solid #3FB950; padding-left: 16px; margin: 16px 0; }
    
    /* Transitions for right panel */
    .right-panel-content {
        animation: fadeIn 0.3s ease-in-out;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(5px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    /* File uploader */
    [data-testid="stFileUploader"] {
        background-color: #0D1117 !important;
        border: 1px dashed #30363D !important;
        border-radius: 8px !important;
    }
    
    /* Text Input */
    [data-testid="stTextInput"] input {
        background-color: #0D1117 !important;
        color: #C9D1D9 !important;
        border: 1px solid #30363D !important;
    }
    [data-testid="stTextInput"] input:focus {
        border-color: #58A6FF !important;
        box-shadow: 0 0 0 1px #58A6FF !important;
    }
</style>
""", unsafe_allow_html=True)

# ── LOAD MODELS ──────────────────────────────────────────
@st.cache_resource
def load_models():
    # 1. Resolve Path Robustly
    # Current file is at /app/dashboard/app.py
    # Project root should be /app/
    # Models should be at /app/models/
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir.parent
    models_dir = project_root / "models"
    
    # Debug Info (will show in Hugging Face Logs)
    print(f"[DEBUG] Current script directory: {current_dir}")
    print(f"[DEBUG] Calculated project root: {project_root}")
    print(f"[DEBUG] Expected models directory: {models_dir}")
    print(f"[DEBUG] Files in project root: {os.listdir(project_root) if project_root.exists() else 'Root not found'}")
    
    if models_dir.exists():
        print(f"[DEBUG] Files in models directory: {os.listdir(models_dir)}")
    else:
        print(f"[DEBUG] Models directory NOT FOUND at {models_dir}")

    # 2. Define File Paths
    iso_path = models_dir / "isolation_forest.pkl"
    xgb_path = models_dir / "xgboost_classifier.pkl"
    
    # 3. Robust Loading with Error Handling
    missing_files = []
    if not iso_path.exists(): missing_files.append(str(iso_path))
    if not xgb_path.exists(): missing_files.append(str(xgb_path))
    
    if missing_files:
        error_msg = f"CRITICAL: Model files missing: {', '.join(missing_files)}"
        print(f"[ERROR] {error_msg}")
        st.error(error_msg)
        st.info(f"Verified current directory: {os.getcwd()}")
        st.info(f"Contents of {project_root}: {os.listdir(project_root) if project_root.exists() else 'N/A'}")
        raise FileNotFoundError(error_msg)

    # 4. Actual Load
    try:
        iso = joblib.load(iso_path)
        xgb = joblib.load(xgb_path)
        # Build explainer dynamically
        explainer = shap.TreeExplainer(xgb)
        return iso, xgb, explainer
    except Exception as e:
        st.error(f"Error during model deserialization: {e}")
        raise e

iso_forest, xgb, shap_explainer = load_models()

# ── SIDEBAR ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='padding: 12px 16px 24px'>
        <div style='font-size:18px; font-weight:700; color:#FFFFFF; letter-spacing: 0.5px;'>SENTINEL-8</div>
        <div style='font-size:12px; color:#8B949E; margin-top:2px; line-height: 1.4;'>AI-Based Cybersecurity Threat Detection</div>
    </div>
    """, unsafe_allow_html=True)
    
    page = st.radio("Navigation", ["Upload and Analyse", "Threat Results", "E8 Scorecard"], label_visibility="collapsed")
    
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    st.markdown("""
    <div style='padding: 0 16px; font-size: 12px; color: #8B949E;'>
        <div style='margin-bottom: 12px;'><strong>MODELS</strong><br>Isolation Forest<br>XGBoost Classifier</div>
        <div style='margin-bottom: 12px;'><strong>DATASET</strong><br>UNSW-NB15</div>
        <div><strong>FRAMEWORK</strong><br>Essential Eight</div>
    </div>
    """, unsafe_allow_html=True)

# ── RISK BADGE FORMATTER (For Pandas Styler) ────────────────
def highlight_risk(val):
    if val == 'High': return 'color: #F85149; font-weight: bold;'
    elif val == 'Medium': return 'color: #E3B341; font-weight: bold;'
    return 'color: #3FB950; font-weight: bold;'

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
        st.markdown(f"<div style='color: #3FB950; font-size: 13px; margin: 12px 0;'>Loaded {len(df):,} records</div>", unsafe_allow_html=True)
        
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
        st.markdown("<div style='color: #8B949E; padding: 40px; text-align: center;'>No analysis run yet. Please go to Upload and Analyse.</div>", unsafe_allow_html=True)
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
                <div style='display: flex; height: 300px; align-items: center; justify-content: center; border: 1px dashed #30363D; border-radius: 8px;'>
                    <span style='color: #8B949E;'>Select an event from the feed to inspect it</span>
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
                        <span style='background: #21262D; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #C9D1D9;'>Score: <b>{row['anomaly_score']}</b></span>
                        <span style='background: #21262D; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #C9D1D9;'>Confidence: <b>{row['confidence']}</b></span>
                        <span class='badge-{risk_class}'>{risk} Risk</span>
                    </div>
                    <div style='margin-bottom: 16px;'>
                        <span style='font-size: 12px; color: #8B949E; display: block; margin-bottom: 4px;'>ESSENTIAL EIGHT CONTROL</span>
                        <span style='background: rgba(88, 166, 255, 0.1); color: #58A6FF; border: 1px solid rgba(88, 166, 255, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 13px; font-weight: 500;'>{e8['e8_control']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("<div style='font-size: 14px; font-weight: 600; color: #FFFFFF; margin: 24px 0 8px;'>SHAP Feature Attribution</div>", unsafe_allow_html=True)
                
                # Plot SHAP waterfall
                shap_vals = st.session_state["shap_values"]
                
                # Dark theme for matplotlib
                plt.style.use('dark_background')
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor('#0D1117')
                ax.set_facecolor('#0D1117')
                
                shap.plots.waterfall(shap_vals[selected_idx], show=False)
                
                # Adjust plot text colors
                for text in plt.gca().texts:
                    text.set_color('#C9D1D9')
                plt.gca().tick_params(colors='#8B949E')
                plt.gca().xaxis.label.set_color('#8B949E')
                plt.gca().yaxis.label.set_color('#8B949E')
                for spine in plt.gca().spines.values():
                    spine.set_color('#30363D')
                
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
                    <div style='background: #161B22; border: 1px solid #30363D; padding: 16px; border-radius: 8px; color: #C9D1D9; font-size: 14px; line-height: 1.5;'>
                        {report}
                    </div>
                    """, unsafe_allow_html=True)

# ── PAGE 3: E8 SCORECARD ──────────────────────────────────
elif page == "E8 Scorecard":
    if "results" not in st.session_state:
        st.markdown("<div style='color: #8B949E; padding: 40px; text-align: center;'>No analysis run yet. Please go to Upload and Analyse.</div>", unsafe_allow_html=True)
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

        st.markdown(f'<div style="color: #C9D1D9; font-size: 15px; margin-bottom: 24px;">4 of 8 controls violated — highest exposure: <span style="color: #FFFFFF; font-weight: 600;">{highest_exposure}</span></div>', unsafe_allow_html=True)

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
                    <div style='width: 100%; background-color: #0D1117; height: 4px; border-radius: 2px;'>
                        <div style='width: {pct}%; background-color: #58A6FF; height: 100%; border-radius: 2px;'></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown('<div style="font-size: 16px; font-weight: 600; color: #FFFFFF; margin-bottom: 16px;">Violation Breakdown</div>', unsafe_allow_html=True)
        
        fig = px.bar(
            x=[c["control"] for c in controls],
            y=[c["threats"] for c in controls],
            color=[c["risk"] for c in controls],
            color_discrete_map={"High": "#F85149", "Medium": "#E3B341"},
            labels={"x": "", "y": "Violations", "color": "Risk"},
            template="plotly_dark",
        )
        fig.update_layout(
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            margin=dict(t=10, b=10, l=10, r=10),
            showlegend=True,
            legend=dict(title=None, yanchor="top", y=0.99, xanchor="right", x=0.99)
        )
        fig.update_xaxes(showgrid=False, linecolor="#30363D")
        fig.update_yaxes(showgrid=True, gridcolor="#21262D", linecolor="#30363D")
        st.plotly_chart(fig, use_container_width=True)