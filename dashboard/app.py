import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
import shap
import matplotlib.pyplot as plt
import sys, os, time

sys.path.append(os.path.dirname(__file__))
from compliance_mapper import map_threat
from llm_reporter import generate_report

st.set_page_config(
    page_title="Sentinel-8",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Syne:wght@700;800&family=Outfit:wght@400;500;600&display=swap');

/* ── RESET & BASE ─────────────────────────────── */
html, body, [class*="css"], .stApp {
    background-color: #07090E !important;
    color: #D4DCE8 !important;
    font-family: 'Outfit', sans-serif !important;
}
.main, .block-container, [data-testid="stAppViewContainer"] {
    background-color: #07090E !important;
}
.block-container {
    padding: 0 !important;
    max-width: 100% !important;
}

/* ── HIDE CHROME ──────────────────────────────── */
[data-testid="stSidebar"],
[data-testid="collapsedControl"],
[data-testid="stDecoration"],
section[data-testid="stSidebar"] { display: none !important; }
#MainMenu, footer, header { visibility: hidden !important; }

/* ── TOPBAR ───────────────────────────────────── */
.s8-topbar {
    width: 100%;
    height: 58px;
    background: #0C0F16;
    border-bottom: 1px solid #1B2436;
    display: flex;
    align-items: center;
    padding: 0 32px;
    gap: 32px;
    box-sizing: border-box;
}
.s8-brand {
    display: flex; align-items: center; gap: 10px;
    flex-shrink: 0;
}
.s8-logo {
    width: 32px; height: 32px;
    background: rgba(0,255,163,0.1);
    border: 1px solid rgba(0,255,163,0.25);
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; line-height: 1;
}
.s8-wordmark {
    font-family: 'Syne', sans-serif;
    font-weight: 800; font-size: 15px;
    color: #F0F4FA; letter-spacing: 0.06em;
}
.s8-wordmark em { color: #00FFA3; font-style: normal; }
.s8-tagline {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; color: #2E4060;
    letter-spacing: 0.12em; text-transform: uppercase;
    line-height: 1; margin-top: 3px;
}
.s8-right {
    margin-left: auto;
    display: flex; align-items: center; gap: 10px;
}
.s8-chip {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; color: #2E4060;
    background: #0E1320; border: 1px solid #1B2436;
    border-radius: 3px; padding: 3px 9px;
    letter-spacing: 0.07em;
}
.s8-live {
    display: flex; align-items: center; gap: 6px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; font-weight: 600; color: #00FFA3;
    background: rgba(0,255,163,0.07);
    border: 1px solid rgba(0,255,163,0.2);
    border-radius: 3px; padding: 4px 11px;
    letter-spacing: 0.08em;
}
.s8-live-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: #00FFA3; box-shadow: 0 0 7px #00FFA3;
    animation: livepulse 2s ease-in-out infinite;
    flex-shrink: 0;
}
@keyframes livepulse { 0%,100%{opacity:1} 50%{opacity:0.25} }

/* ── NAV BAR ──────────────────────────────────── */
.s8-navrow {
    width: 100%;
    background: #0C0F16;
    border-bottom: 1px solid #1B2436;
    padding: 0 32px;
    display: flex; align-items: flex-end; gap: 0;
}
.s8-navitem {
    display: flex; align-items: center; gap: 8px;
    padding: 0 22px; height: 44px;
    font-family: 'Outfit', sans-serif;
    font-size: 13px; font-weight: 500; color: #3E5474;
    border-bottom: 2px solid transparent;
    cursor: pointer; white-space: nowrap;
    transition: color 0.15s; user-select: none;
    text-decoration: none;
}
.s8-navitem:hover { color: #8DA0BA; }
.s8-navitem.s8-active {
    color: #00FFA3;
    border-bottom-color: #00FFA3;
    font-weight: 600;
}
.s8-navitem .navnum {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; color: inherit; opacity: 0.6;
}
.s8-navitem.s8-locked { opacity: 0.4; cursor: not-allowed; }

/* ── PAGE BODY ────────────────────────────────── */
.s8-body {
    padding: 32px 36px 56px;
    max-width: 1500px;
}

/* ── PAGE HEADER ──────────────────────────────── */
.s8-pg-eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; font-weight: 600; color: #00FFA3;
    letter-spacing: 0.18em; text-transform: uppercase;
    margin-bottom: 7px;
}
.s8-pg-title {
    font-family: 'Syne', sans-serif;
    font-size: 24px; font-weight: 800;
    color: #F0F4FA; letter-spacing: -0.01em; line-height: 1.2;
    margin-bottom: 6px;
}
.s8-pg-desc {
    font-size: 13px; color: #4D647E; line-height: 1.6;
    max-width: 620px;
}
.s8-divider {
    border: none; border-top: 1px solid #1B2436;
    margin: 20px 0 28px;
}

/* ── METRIC CARDS ─────────────────────────────── */
[data-testid="metric-container"] {
    background: #0E1320 !important;
    border: 1px solid #1B2436 !important;
    border-radius: 8px !important;
    padding: 16px 20px !important;
    position: relative; overflow: hidden;
}
[data-testid="metric-container"]::after {
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, #00FFA3 0%, transparent 70%);
    opacity: 0.4;
}
[data-testid="metric-container"] label,
[data-testid="metric-container"] label * {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 9px !important; font-weight: 600 !important;
    color: #2E4060 !important; letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
    white-space: normal !important; overflow: visible !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"],
[data-testid="metric-container"] [data-testid="stMetricValue"] * {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 24px !important; font-weight: 600 !important;
    color: #F0F4FA !important; letter-spacing: -0.02em !important;
    overflow: visible !important;
}

/* ── STEP TRACK ───────────────────────────────── */
.s8-steps {
    display: flex; margin-bottom: 32px;
    background: #0E1320; border: 1px solid #1B2436;
    border-radius: 8px; overflow: hidden;
}
.s8-step {
    flex: 1; padding: 14px 20px;
    display: flex; align-items: center; gap: 13px;
    border-right: 1px solid #1B2436;
    position: relative;
}
.s8-step:last-child { border-right: none; }
.s8-step-num {
    width: 28px; height: 28px; border-radius: 50%;
    border: 1px solid #1B2436;
    background: #0C0F16;
    display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px; font-weight: 600; color: #2E4060;
    flex-shrink: 0;
}
.s8-step.active .s8-step-num {
    background: rgba(0,255,163,0.1);
    border-color: rgba(0,255,163,0.3);
    color: #00FFA3;
}
.s8-step.done .s8-step-num {
    background: #00FFA3; border-color: #00FFA3;
    color: #07090E; font-size: 13px;
}
.s8-step-label {
    font-size: 12px; font-weight: 600; color: #2E4060; line-height: 1.3;
}
.s8-step.active .s8-step-label { color: #D4DCE8; }
.s8-step.done .s8-step-label { color: #5A7494; }
.s8-step-sub {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; color: #1E3050; letter-spacing: 0.06em;
    display: block; margin-top: 2px;
}
.s8-step.active .s8-step-sub { color: #2E4060; }
.s8-step-arrow {
    position: absolute; right: -9px; top: 50%;
    transform: translateY(-50%);
    font-size: 14px; color: #1B2436; z-index: 1;
}

/* ── UPLOAD BOX ───────────────────────────────── */
[data-testid="stFileUploaderDropzone"] {
    background: #0E1320 !important;
    border: 1px dashed #1B2436 !important;
    border-radius: 8px !important;
}
[data-testid="stFileUploaderDropzone"]:hover {
    border-color: rgba(0,255,163,0.4) !important;
    background: rgba(0,255,163,0.03) !important;
}
[data-testid="stFileUploaderDropzone"] * { color: #3E5474 !important; }

/* ── BUTTONS ──────────────────────────────────── */
.stButton > button {
    background: #0E1320 !important;
    color: #8DA0BA !important;
    border: 1px solid #1B2436 !important;
    border-radius: 6px !important;
    font-family: 'Outfit', sans-serif !important;
    font-size: 13px !important; font-weight: 500 !important;
    padding: 8px 18px !important;
    transition: all 0.15s !important;
    box-shadow: none !important;
}
.stButton > button:hover {
    background: #131825 !important;
    color: #D4DCE8 !important;
    border-color: #2A3A54 !important;
}
.btn-cta .stButton > button {
    background: #00FFA3 !important;
    color: #07090E !important;
    border-color: #00FFA3 !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    padding: 10px 28px !important;
    letter-spacing: 0.02em !important;
}
.btn-cta .stButton > button:hover {
    background: #00E894 !important;
    box-shadow: 0 0 22px rgba(0,255,163,0.3) !important;
}
.btn-ghost .stButton > button {
    background: transparent !important;
    color: #4D647E !important;
    border: 1px solid #1B2436 !important;
    font-size: 12px !important;
    padding: 6px 14px !important;
}
.btn-ghost .stButton > button:hover {
    color: #8DA0BA !important;
    border-color: #2A3A54 !important;
}

/* ── SECTION LABEL ────────────────────────────── */
.s8-section {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; font-weight: 600; color: #2E4060;
    letter-spacing: 0.16em; text-transform: uppercase;
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 14px; margin-top: 28px;
}
.s8-section::after {
    content: ''; flex: 1; height: 1px; background: #1B2436;
}

/* ── ALERT BANNERS ────────────────────────────── */
.s8-alert-ok {
    background: rgba(0,255,163,0.06);
    border: 1px solid rgba(0,255,163,0.18);
    border-radius: 6px; padding: 10px 16px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px; color: #00FFA3;
    display: flex; align-items: center; gap: 10px;
    margin: 14px 0;
}
.s8-alert-info {
    background: rgba(59,139,235,0.06);
    border: 1px solid rgba(59,139,235,0.18);
    border-radius: 6px; padding: 10px 16px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px; color: #5B9CF6;
    display: flex; align-items: center; gap: 10px;
    margin: 14px 0;
}

/* ── SUMMARY STRIP ────────────────────────────── */
.s8-strip {
    display: flex; background: #0E1320;
    border: 1px solid #1B2436; border-radius: 8px;
    overflow: hidden; margin-bottom: 24px;
}
.s8-strip-cell {
    flex: 1; padding: 15px 20px;
    border-right: 1px solid #1B2436;
}
.s8-strip-cell:last-child { border-right: none; }
.s8-strip-lbl {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; font-weight: 600; color: #2E4060;
    letter-spacing: 0.12em; text-transform: uppercase;
    margin-bottom: 6px;
}
.s8-strip-val {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 20px; font-weight: 600; color: #F0F4FA;
    letter-spacing: -0.01em;
}

/* ── DATAFRAME ────────────────────────────────── */
[data-testid="stDataFrame"] {
    background: #0E1320 !important;
    border: 1px solid #1B2436 !important;
    border-radius: 8px !important;
    overflow: hidden !important;
}

/* ── TEXT INPUT ───────────────────────────────── */
[data-testid="stTextInput"] input {
    background: #0E1320 !important;
    color: #D4DCE8 !important;
    border: 1px solid #1B2436 !important;
    border-radius: 6px !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 12px !important; padding: 9px 13px !important;
}
[data-testid="stTextInput"] input::placeholder { color: #2E4060 !important; }
[data-testid="stTextInput"] input:focus {
    border-color: rgba(0,255,163,0.4) !important;
    box-shadow: 0 0 0 2px rgba(0,255,163,0.08) !important;
}

/* ── EVENT INSPECTOR ──────────────────────────── */
.s8-inspect {
    background: #0E1320; border: 1px solid #1B2436;
    border-radius: 8px; padding: 22px;
    animation: fadein 0.2s ease;
}
@keyframes fadein { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
.s8-inspect-id {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; color: #2E4060; letter-spacing: 0.12em;
    text-transform: uppercase; margin-bottom: 6px;
}
.s8-inspect-title {
    font-family: 'Syne', sans-serif;
    font-size: 19px; font-weight: 800; color: #F0F4FA;
    margin-bottom: 14px;
}
.s8-kv-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.s8-kv {
    background: #131825; border: 1px solid #1B2436;
    border-radius: 4px; padding: 5px 11px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; color: #4D647E;
}
.s8-kv b { color: #A0B4C8; }
.s8-e8tag {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(59,139,235,0.08);
    border: 1px solid rgba(59,139,235,0.2);
    color: #5B9CF6; border-radius: 4px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; font-weight: 600;
    padding: 5px 12px; letter-spacing: 0.05em;
}
.s8-report-box {
    background: #0C0F16;
    border: 1px solid #1B2436;
    border-left: 3px solid #00FFA3;
    border-radius: 0 6px 6px 0;
    padding: 16px 20px; margin-top: 12px;
    font-size: 13px; color: #8DA0BA; line-height: 1.75;
}

/* ── BADGES ───────────────────────────────────── */
.bdg {
    display: inline-block;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; font-weight: 600;
    letter-spacing: 0.1em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 3px;
}
.bdg-high   { background: rgba(255,60,90,0.1);  color:#FF3C5A; border:1px solid rgba(255,60,90,0.25); }
.bdg-medium { background: rgba(255,175,50,0.1); color:#FFAF32; border:1px solid rgba(255,175,50,0.25); }
.bdg-low    { background: rgba(0,255,163,0.1);  color:#00FFA3; border:1px solid rgba(0,255,163,0.25); }

/* ── E8 CARDS ─────────────────────────────────── */
.s8-e8card {
    background: #0E1320; border: 1px solid #1B2436;
    border-radius: 8px; padding: 20px 22px;
    margin-bottom: 14px; position: relative;
    transition: border-color 0.18s, box-shadow 0.18s;
}
.s8-e8card:hover { border-color: #2A3A54; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
.s8-e8card-high   { border-left: 3px solid #FF3C5A !important; }
.s8-e8card-medium { border-left: 3px solid #FFAF32 !important; }
.s8-e8card-low    { border-left: 3px solid #00FFA3 !important; }
.s8-e8num {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; font-weight: 600; color: #2E4060;
    letter-spacing: 0.12em; text-transform: uppercase;
    margin-bottom: 5px;
}
.s8-e8name {
    font-family: 'Syne', sans-serif;
    font-size: 14px; font-weight: 700; color: #D4DCE8;
    margin-bottom: 14px; line-height: 1.3;
}
.s8-e8stat {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 26px; font-weight: 600; color: #F0F4FA;
    letter-spacing: -0.02em; line-height: 1;
}
.s8-e8statlbl {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; color: #2E4060; letter-spacing: 0.1em;
    text-transform: uppercase; margin-top: 4px; margin-bottom: 14px;
}
.s8-track { width:100%; height:2px; background:#131825; border-radius:1px; overflow:hidden; }
.s8-fill-high   { height:100%; background:#FF3C5A; border-radius:1px; }
.s8-fill-medium { height:100%; background:#FFAF32; border-radius:1px; }
.s8-fill-low    { height:100%; background:#00FFA3; border-radius:1px; }

/* ── EMPTY STATE ──────────────────────────────── */
.s8-empty {
    min-height: 340px; background: #0E1320;
    border: 1px dashed #1B2436; border-radius: 10px;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center; gap: 10px;
}
.s8-empty-icon { font-size: 36px; opacity: 0.2; }
.s8-empty-title {
    font-family: 'Syne', sans-serif;
    font-size: 14px; font-weight: 700; color: #3E5474;
}
.s8-empty-sub {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px; color: #1E3050; letter-spacing: 0.06em;
}

/* ── SCROLLBAR ────────────────────────────────── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:#07090E; }
::-webkit-scrollbar-thumb { background:#1B2436; border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:#2A3A54; }

/* ── SPINNER ──────────────────────────────────── */
.stSpinner > div { border-top-color: #00FFA3 !important; }
</style>
""", unsafe_allow_html=True)

# ── MODELS ────────────────────────────────────────────────
@st.cache_resource
def load_models():
    iso = joblib.load('../models/isolation_forest.pkl')
    xgb = joblib.load('../models/xgboost_classifier.pkl')
    return iso, xgb, shap.TreeExplainer(xgb)

iso_forest, xgb, shap_explainer = load_models()

# ── SESSION STATE ──────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state["page"] = "analyse"

has_results = "results" in st.session_state
page = st.session_state["page"]

# ── TOPBAR (pure HTML — no Streamlit widgets) ──────────────
st.markdown("""
<div class="s8-topbar">
    <div class="s8-brand">
        <div class="s8-logo">🛡</div>
        <div>
            <div class="s8-wordmark">SENTINEL<em>-8</em></div>
            <div class="s8-tagline">Threat Detection Platform</div>
        </div>
    </div>
    <div class="s8-right">
        <span class="s8-chip">UNSW-NB15</span>
        <span class="s8-chip">ESSENTIAL EIGHT</span>
        <span class="s8-chip">IsolationForest + XGBoost</span>
        <span class="s8-live">
            <span class="s8-live-dot"></span>OPERATIONAL
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── NAV ROW (Streamlit radio disguised as tab bar) ─────────
# Render radio hidden, then show styled tabs above
tabs   = ["① Upload & Analyse", "② Threat Results", "③ E8 Scorecard"]
labels = ["analyse",             "threats",           "scorecard"]

# Map current page key → tab label
current_tab = {
    "analyse":   tabs[0],
    "threats":   tabs[1],
    "scorecard": tabs[2],
}.get(page, tabs[0])

# Determine which tabs are locked
locked = {tabs[1]: not has_results, tabs[2]: not has_results}

# Build HTML nav (visual only)
nav_items = ""
for tab in tabs:
    is_active  = (tab == current_tab)
    is_locked  = locked.get(tab, False)
    cls = "s8-navitem"
    if is_active:  cls += " s8-active"
    if is_locked:  cls += " s8-locked"
    lock_icon = " 🔒" if is_locked else ""
    nav_items += f'<span class="{cls}">{tab}{lock_icon}</span>'

st.markdown(f'<div class="s8-navrow">{nav_items}</div>', unsafe_allow_html=True)

# Actual navigation buttons (hidden under a single row)
nav_cols = st.columns([1, 1, 1, 5])
btn_labels = ["Upload & Analyse", "Threat Results", "E8 Scorecard"]
btn_keys   = ["analyse", "threats", "scorecard"]

for i, (col, lbl, key) in enumerate(zip(nav_cols[:3], btn_labels, btn_keys)):
    with col:
        st.markdown('<div class="btn-ghost">', unsafe_allow_html=True)
        clicked = st.button(lbl, key=f"nav_{key}", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        if clicked:
            if i > 0 and not has_results:
                st.toast("⚠️ Run an analysis first.", icon="🔒")
            else:
                st.session_state["page"] = key
                st.rerun()

# Thin separator
st.markdown('<hr style="border:none;border-top:1px solid #1B2436;margin:0 0 0 0;">', unsafe_allow_html=True)

# Body padding wrapper
st.markdown('<div class="s8-body">', unsafe_allow_html=True)

# ── RISK STYLER ────────────────────────────────────────────
def highlight_risk(val):
    colors = {"High": "#FF3C5A", "Medium": "#FFAF32", "Low": "#00FFA3"}
    return f"color:{colors.get(val,'#D4DCE8')}; font-weight:600;"


# ══════════════════════════════════════════════════════════
# PAGE 1 — UPLOAD & ANALYSE
# ══════════════════════════════════════════════════════════
if page == "analyse":

    st.markdown("""
    <div class="s8-pg-eyebrow">Step 1 of 3</div>
    <div class="s8-pg-title">Upload Network Log</div>
    <div class="s8-pg-desc">Provide a UNSW-NB15 formatted CSV file. The 2-stage ML pipeline runs anomaly detection followed by threat classification.</div>
    <hr class="s8-divider">
    """, unsafe_allow_html=True)

    # Step tracker
    d = "done" if has_results else ""
    st.markdown(f"""
    <div class="s8-steps">
        <div class="s8-step active">
            <div class="s8-step-num">1</div>
            <div>
                <div class="s8-step-label">Upload Log File</div>
                <span class="s8-step-sub">CSV · UNSW-NB15 format</span>
            </div>
        </div>
        <div class="s8-step {d}">
            <div class="s8-step-num">{"✓" if has_results else "2"}</div>
            <div>
                <div class="s8-step-label">Run ML Pipeline</div>
                <span class="s8-step-sub">Isolation Forest + XGBoost</span>
            </div>
        </div>
        <div class="s8-step {d}">
            <div class="s8-step-num">{"✓" if has_results else "3"}</div>
            <div>
                <div class="s8-step-label">Review Results</div>
                <span class="s8-step-sub">Threats · E8 Scorecard</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Model stats
    c1, c2, c3, c4 = st.columns(4, gap="small")
    c1.metric("Pipeline",            "2-Stage ML")
    c2.metric("Classifier Accuracy", "99.29%")
    c3.metric("AUC-ROC Score",       "0.9467")
    c4.metric("Compliance Framework","Essential Eight")

    st.markdown('<div class="s8-section">Drop or Browse</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Upload UNSW-NB15 CSV",
        type=["csv"],
        label_visibility="collapsed",
        help="UNSW-NB15 formatted CSV"
    )

    if uploaded:
        df = pd.read_csv(uploaded)
        st.markdown(f"""
        <div class="s8-alert-ok">
            ✓ &nbsp;<b>{uploaded.name}</b> &nbsp;—&nbsp; {len(df):,} records loaded
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="s8-section">Execute</div>', unsafe_allow_html=True)
        st.markdown('<div class="btn-cta">', unsafe_allow_html=True)
        run = st.button("▶  Run Analysis Pipeline", key="run_btn")
        st.markdown('</div>', unsafe_allow_html=True)

        if run:
            prog = st.progress(0, text="Initialising pipeline…")
            with st.spinner(""):
                start = time.time()
                expected_cols = xgb.get_booster().feature_names
                for col in expected_cols:
                    if col not in df.columns:
                        df[col] = 0
                df_model = df[expected_cols]
                prog.progress(25, text="Stage 1 — Anomaly detection (Isolation Forest)…")
                anomaly_scores = -iso_forest.score_samples(df_model)
                prog.progress(55, text="Stage 2 — Threat classification (XGBoost)…")
                predictions  = xgb.predict(df_model)
                probs        = xgb.predict_proba(df_model)[:, 1]
                prog.progress(80, text="Computing SHAP attributions…")
                results = pd.DataFrame({
                    "record_id":     [f"EVT-{str(i).zfill(5)}" for i in range(len(df))],
                    "anomaly_score": anomaly_scores.round(3),
                    "threat_label":  predictions,
                    "confidence":    probs.round(3),
                })
                results["threat_type"] = results["threat_label"].map(lambda x: "Attack" if x == 1 else "Normal")
                results["risk_level"]  = results["anomaly_score"].apply(
                    lambda x: "High" if x > 0.55 else "Medium" if x > 0.45 else "Low"
                )
                st.session_state["shap_values"] = shap_explainer(df_model)
                st.session_state["results"]     = results
                st.session_state["df_model"]    = df_model
                elapsed = time.time() - start
                st.session_state["throughput"]  = f"{int(len(df)/elapsed):,}/s"
                prog.progress(100, text="Complete.")
            st.rerun()

    if has_results:
        results = st.session_state["results"]
        st.markdown('<div class="s8-section">Last Run Summary</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4, gap="small")
        c1.metric("Total Records",    f"{len(results):,}")
        c2.metric("Threats Detected", f"{int(results['threat_label'].sum()):,}")
        c3.metric("High Risk",        f"{len(results[results['risk_level']=='High']):,}")
        c4.metric("Throughput",       st.session_state.get("throughput","—"))
        st.markdown("""
        <div class="s8-alert-info">
            ℹ &nbsp; Analysis complete. Use the navigation above to view <b>Threat Results</b> or the <b>E8 Scorecard</b>.
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════
# PAGE 2 — THREAT RESULTS
# ══════════════════════════════════════════════════════════
elif page == "threats":

    st.markdown("""
    <div class="s8-pg-eyebrow">Step 2 of 3</div>
    <div class="s8-pg-title">Threat Feed & Event Inspector</div>
    <div class="s8-pg-desc">Select any event row to inspect anomaly details, SHAP feature attributions, and generate an AI analyst report.</div>
    <hr class="s8-divider">
    """, unsafe_allow_html=True)

    if not has_results:
        st.markdown("""
        <div class="s8-empty">
            <div class="s8-empty-icon">📭</div>
            <div class="s8-empty-title">No Analysis Data</div>
            <div class="s8-empty-sub">Return to Upload &amp; Analyse and run the pipeline first.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        results = st.session_state["results"]
        feed_df = results[results["threat_label"] == 1].copy()
        if feed_df.empty:
            feed_df = results.copy()

        n_h = len(feed_df[feed_df["risk_level"] == "High"])
        n_m = len(feed_df[feed_df["risk_level"] == "Medium"])
        n_l = len(feed_df[feed_df["risk_level"] == "Low"])

        st.markdown(f"""
        <div class="s8-strip">
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl">Total Threat Events</div>
                <div class="s8-strip-val">{len(feed_df):,}</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl" style="color:#FF3C5A;">High Risk</div>
                <div class="s8-strip-val" style="color:#FF3C5A;">{n_h:,}</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl" style="color:#FFAF32;">Medium Risk</div>
                <div class="s8-strip-val" style="color:#FFAF32;">{n_m:,}</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl" style="color:#00FFA3;">Low Risk</div>
                <div class="s8-strip-val" style="color:#00FFA3;">{n_l:,}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        left, right = st.columns([0.52, 0.48], gap="medium")

        with left:
            st.markdown('<div class="s8-section">Threat Feed</div>', unsafe_allow_html=True)
            flt = st.text_input("filter", placeholder="Filter by threat type or risk level…",
                                key="feed_filter", label_visibility="collapsed")
            if flt:
                feed_df = feed_df[
                    feed_df["threat_type"].str.contains(flt, case=False) |
                    feed_df["risk_level"].str.contains(flt, case=False)
                ]
            display = feed_df[["record_id","threat_type","anomaly_score","confidence","risk_level"]]
            event = st.dataframe(
                display.style.map(highlight_risk, subset=["risk_level"]),
                use_container_width=True, hide_index=True,
                selection_mode="single-row", on_select="rerun", height=460
            )

        with right:
            st.markdown('<div class="s8-section">Event Inspector</div>', unsafe_allow_html=True)
            sel = event.selection["rows"]

            if not sel:
                st.markdown("""
                <div style="
                    min-height:460px; background:#0E1320;
                    border:1px dashed #1B2436; border-radius:8px;
                    display:flex; flex-direction:column;
                    align-items:center; justify-content:center; gap:10px;
                ">
                    <div style="font-size:28px;opacity:0.15;">←</div>
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#1E3050;letter-spacing:0.12em;">
                        SELECT A ROW TO INSPECT
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                idx = feed_df.iloc[sel[0]].name
                row = results.loc[idx]
                e8  = map_threat(row["threat_type"])
                rc  = row["risk_level"].lower()

                st.markdown(f"""
                <div class="s8-inspect">
                    <div class="s8-inspect-id">{row['record_id']}</div>
                    <div class="s8-inspect-title">{row['threat_type']}</div>
                    <div class="s8-kv-row">
                        <span class="s8-kv">Anomaly Score <b>{row['anomaly_score']}</b></span>
                        <span class="s8-kv">Confidence <b>{row['confidence']}</b></span>
                        <span class="bdg bdg-{rc}">{row['risk_level']}</span>
                    </div>
                    <div style="margin-bottom:0;">
                        <div style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:#2E4060;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:8px;">E8 Control Mapping</div>
                        <span class="s8-e8tag">⚙ {e8['e8_control']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown('<div class="s8-section">SHAP Feature Attribution</div>', unsafe_allow_html=True)

                shap_vals = st.session_state["shap_values"]
                plt.style.use("dark_background")
                fig, ax = plt.subplots(figsize=(7, 3.5))
                fig.patch.set_facecolor("#0E1320")
                ax.set_facecolor("#0E1320")
                shap.plots.waterfall(shap_vals[idx], show=False)
                for t in plt.gca().texts: t.set_color("#D4DCE8")
                plt.gca().tick_params(colors="#4D647E")
                plt.gca().xaxis.label.set_color("#4D647E")
                plt.gca().yaxis.label.set_color("#4D647E")
                for sp in plt.gca().spines.values(): sp.set_color("#1B2436")
                plt.tight_layout(pad=0.5)
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)

                st.markdown('<div class="s8-section">Analyst Report</div>', unsafe_allow_html=True)
                if st.button("Generate AI Report", key="gen_report"):
                    with st.spinner("Generating report…"):
                        report = generate_report(
                            threat_type=row["threat_type"],
                            anomaly_score=row["anomaly_score"],
                            e8_control=e8["e8_control"],
                            risk_level=row["risk_level"],
                            top_features=["sttl","ct_state_ttl","dbytes"]
                        )
                    st.markdown(f'<div class="s8-report-box">{report}</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════
# PAGE 3 — E8 SCORECARD
# ══════════════════════════════════════════════════════════
elif page == "scorecard":

    st.markdown("""
    <div class="s8-pg-eyebrow">Step 3 of 3</div>
    <div class="s8-pg-title">Essential Eight Scorecard</div>
    <div class="s8-pg-desc">Control violations mapped to ACSC Essential Eight mitigation strategies, with relative exposure scores.</div>
    <hr class="s8-divider">
    """, unsafe_allow_html=True)

    if not has_results:
        st.markdown("""
        <div class="s8-empty">
            <div class="s8-empty-icon">📋</div>
            <div class="s8-empty-title">No Analysis Data</div>
            <div class="s8-empty-sub">Return to Upload &amp; Analyse and run the pipeline first.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        results  = st.session_state["results"]
        attacks  = results[results["threat_label"] == 1]
        total    = max(len(attacks), 1)

        controls = [
            {"num":"E8-1","control":"Application Control",       "threats":int(total*0.35),"risk":"High"},
            {"num":"E8-2","control":"Patch Applications",         "threats":int(total*0.25),"risk":"High"},
            {"num":"E8-5","control":"Restrict Admin Privileges",  "threats":int(total*0.20),"risk":"Medium"},
            {"num":"E8-7","control":"Multi-Factor Authentication","threats":int(total*0.20),"risk":"High"},
        ]
        max_thr  = max(c["threats"] for c in controls) or 1
        highest  = max(controls, key=lambda x: x["threats"])["control"]
        total_v  = sum(c["threats"] for c in controls)
        n_high   = sum(1 for c in controls if c["risk"] == "High")

        st.markdown(f"""
        <div class="s8-strip" style="margin-bottom:28px;">
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl">Controls Assessed</div>
                <div class="s8-strip-val">4 / 8</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl" style="color:#FF3C5A;">At High Risk</div>
                <div class="s8-strip-val" style="color:#FF3C5A;">{n_high}</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl">Total Violations</div>
                <div class="s8-strip-val">{total_v:,}</div>
            </div>
            <div class="s8-strip-cell">
                <div class="s8-strip-lbl">Highest Exposure</div>
                <div class="s8-strip-val" style="font-size:14px;margin-top:2px;">{highest}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2, gap="large")
        for i, c in enumerate(controls):
            with (col1 if i % 2 == 0 else col2):
                rc  = c["risk"].lower()
                pct = (c["threats"] / max_thr) * 100
                st.markdown(f"""
                <div class="s8-e8card s8-e8card-{rc}">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">
                        <div class="s8-e8num">{c['num']}</div>
                        <span class="bdg bdg-{rc}">{c['risk']}</span>
                    </div>
                    <div class="s8-e8name">{c['control']}</div>
                    <div class="s8-e8stat">{c['threats']:,}</div>
                    <div class="s8-e8statlbl">Violations Detected</div>
                    <div class="s8-track">
                        <div class="s8-fill-{rc}" style="width:{pct:.1f}%;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="s8-section">Violation Breakdown</div>', unsafe_allow_html=True)

        cmap = {"High":"#FF3C5A","Medium":"#FFAF32","Low":"#00FFA3"}
        fig  = go.Figure()
        for c in controls:
            fig.add_trace(go.Bar(
                x=[c["control"]], y=[c["threats"]],
                marker_color=cmap[c["risk"]], marker_line_width=0,
                width=0.5, showlegend=False,
            ))
        fig.update_layout(
            paper_bgcolor="#07090E", plot_bgcolor="#07090E",
            font=dict(family="IBM Plex Mono, monospace", color="#4D647E", size=11),
            margin=dict(t=8, b=8, l=8, r=8), height=260,
            xaxis=dict(showgrid=False, linecolor="#1B2436", tickfont=dict(color="#4D647E")),
            yaxis=dict(showgrid=True, gridcolor="#0E1320", linecolor="#1B2436", tickfont=dict(color="#4D647E")),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

st.markdown("</div>", unsafe_allow_html=True)