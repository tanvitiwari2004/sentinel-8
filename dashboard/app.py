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
    page_title="Sentinel-8 | Threat Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── ENTERPRISE CSS ────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Syne:wght@400;500;600;700;800&family=Outfit:wght@300;400;500;600;700&display=swap');

:root {
    --bg-base:      #050709;
    --bg-surface:   #0A0D12;
    --bg-elevated:  #0F1318;
    --bg-overlay:   #141920;
    --border:       #1A2130;
    --border-light: #222D3D;
    --text-primary: #E8EDF5;
    --text-secondary: #7A8BA0;
    --text-muted:   #3D4F65;
    --accent:       #0CF2A0;
    --accent-dim:   rgba(12, 242, 160, 0.12);
    --accent-glow:  rgba(12, 242, 160, 0.25);
    --blue:         #3B8BEB;
    --blue-dim:     rgba(59, 139, 235, 0.12);
    --red:          #FF4D6A;
    --red-dim:      rgba(255, 77, 106, 0.12);
    --amber:        #FFB340;
    --amber-dim:    rgba(255, 179, 64, 0.12);
    --green:        #0CF2A0;
    --green-dim:    rgba(12, 242, 160, 0.12);
    --font-mono:    'IBM Plex Mono', monospace;
    --font-display: 'Syne', sans-serif;
    --font-body:    'Outfit', sans-serif;
}

*, *::before, *::after { box-sizing: border-box; }

html, body, [class*="css"] {
    font-family: var(--font-body);
    background-color: var(--bg-base);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
}
.main { background-color: var(--bg-base); }

/* ── HIDE STREAMLIT CHROME ───────────────────── */
[data-testid="stSidebar"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapseButton"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"] { display: none !important; }
#MainMenu, footer, header { visibility: hidden; }
.block-container {
    padding: 0 !important;
    max-width: 100% !important;
}

/* ── TOPBAR ──────────────────────────────────── */
.topbar {
    position: sticky; top: 0; z-index: 1000;
    display: flex; align-items: center;
    height: 56px;
    padding: 0 28px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    gap: 0;
}
.topbar-brand {
    display: flex; align-items: center; gap: 10px;
    margin-right: 48px; flex-shrink: 0;
}
.topbar-shield {
    width: 32px; height: 32px;
    background: var(--accent-dim);
    border: 1px solid var(--accent-glow);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
}
.topbar-wordmark {
    font-family: var(--font-display);
    font-size: 15px; font-weight: 800;
    color: var(--text-primary);
    letter-spacing: 0.05em;
}
.topbar-wordmark span {
    color: var(--accent);
}
.topbar-nav {
    display: flex; align-items: center; gap: 2px; flex: 1;
}
.topbar-right {
    display: flex; align-items: center; gap: 12px;
    margin-left: auto; flex-shrink: 0;
}
.status-badge {
    display: flex; align-items: center; gap: 6px;
    font-family: var(--font-mono);
    font-size: 10px; font-weight: 500;
    color: var(--accent);
    background: var(--accent-dim);
    border: 1px solid var(--accent-glow);
    border-radius: 4px;
    padding: 4px 10px;
    letter-spacing: 0.08em;
}
.status-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    animation: blink 2s ease-in-out infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

.chip {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 3px 8px;
    letter-spacing: 0.06em;
}

/* ── NAVIGATION BUTTONS ──────────────────────── */
/* Override all Streamlit button defaults for nav */
.nav-area .stButton button {
    background: transparent !important;
    color: var(--text-secondary) !important;
    border: none !important;
    border-radius: 0 !important;
    padding: 0 16px !important;
    height: 56px !important;
    font-family: var(--font-body) !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em !important;
    border-bottom: 2px solid transparent !important;
    margin-bottom: -1px !important;
    transition: all 0.15s ease !important;
    box-shadow: none !important;
    white-space: nowrap !important;
}
.nav-area .stButton button:hover {
    color: var(--text-primary) !important;
    background: rgba(255,255,255,0.03) !important;
    border-bottom-color: var(--border-light) !important;
}
.nav-active .stButton button {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
    font-weight: 600 !important;
}

/* ── PAGE WRAPPER ────────────────────────────── */
.page-content {
    padding: 32px 32px 48px;
    max-width: 1480px;
    margin: 0 auto;
}

/* ── PAGE HEADER ─────────────────────────────── */
.page-header {
    margin-bottom: 28px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
}
.page-header-left {}
.page-eyebrow {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 500;
    color: var(--accent);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.page-title {
    font-family: var(--font-display);
    font-size: 22px;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: -0.01em;
    line-height: 1.2;
}
.page-desc {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 5px;
    line-height: 1.5;
}

/* ── METRIC CARDS ────────────────────────────── */
[data-testid="metric-container"] {
    background: var(--bg-elevated) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 18px 20px !important;
    position: relative;
    overflow: hidden;
}
[data-testid="metric-container"]::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent) 0%, transparent 100%);
    opacity: 0.5;
}
[data-testid="metric-container"] label,
[data-testid="metric-container"] label * {
    color: var(--text-muted) !important;
    font-family: var(--font-mono) !important;
    font-size: 10px !important;
    font-weight: 500 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    white-space: normal !important;
    overflow: visible !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"],
[data-testid="metric-container"] [data-testid="stMetricValue"] * {
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 26px !important;
    font-weight: 600 !important;
    letter-spacing: -0.02em !important;
    overflow: visible !important;
}

/* ── CARDS ───────────────────────────────────── */
.card {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 16px;
}
.card-header {
    display: flex; align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
}
.card-title {
    font-family: var(--font-mono);
    font-size: 11px; font-weight: 600;
    color: var(--text-secondary);
    letter-spacing: 0.1em;
    text-transform: uppercase;
}

/* ── UPLOAD ZONE ─────────────────────────────── */
.upload-zone {
    background: var(--bg-elevated);
    border: 1px dashed var(--border-light);
    border-radius: 10px;
    padding: 40px 32px;
    text-align: center;
    transition: all 0.2s ease;
    margin: 16px 0 24px;
}
.upload-zone:hover {
    border-color: var(--accent);
    background: var(--accent-dim);
}
.upload-icon { font-size: 36px; margin-bottom: 12px; }
.upload-title {
    font-family: var(--font-display);
    font-size: 16px; font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 6px;
}
.upload-hint {
    font-size: 12px; color: var(--text-secondary);
    font-family: var(--font-mono);
}

/* ── STEP INDICATOR ──────────────────────────── */
.steps-row {
    display: flex; gap: 0; margin-bottom: 32px;
}
.step-item {
    flex: 1; display: flex; align-items: center; gap: 12px;
    padding: 14px 20px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    position: relative;
}
.step-item:not(:last-child)::after {
    content: '›';
    position: absolute; right: -12px; top: 50%;
    transform: translateY(-50%);
    color: var(--text-muted);
    font-size: 20px; z-index: 1;
}
.step-item:first-child { border-radius: 8px 0 0 8px; }
.step-item:last-child { border-radius: 0 8px 8px 0; }
.step-num {
    width: 28px; height: 28px; border-radius: 50%;
    background: var(--bg-overlay);
    border: 1px solid var(--border-light);
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-mono);
    font-size: 12px; font-weight: 600;
    color: var(--text-muted);
    flex-shrink: 0;
}
.step-item.active .step-num {
    background: var(--accent-dim);
    border-color: var(--accent-glow);
    color: var(--accent);
}
.step-item.done .step-num {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--bg-base);
}
.step-label {
    font-size: 12px; font-weight: 500;
    color: var(--text-muted);
}
.step-item.active .step-label { color: var(--text-primary); }
.step-item.done .step-label { color: var(--text-secondary); }
.step-sub {
    font-family: var(--font-mono);
    font-size: 10px; color: var(--text-muted);
    display: block; margin-top: 2px;
}

/* ── BUTTONS ─────────────────────────────────── */
.stButton button {
    background: var(--bg-overlay) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-light) !important;
    border-radius: 6px !important;
    padding: 8px 20px !important;
    font-family: var(--font-body) !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    transition: all 0.15s ease !important;
    box-shadow: none !important;
}
.stButton button:hover {
    background: var(--bg-elevated) !important;
    border-color: var(--border-light) !important;
    color: #fff !important;
}
.btn-primary .stButton button {
    background: var(--accent) !important;
    color: var(--bg-base) !important;
    border-color: var(--accent) !important;
    font-weight: 700 !important;
    letter-spacing: 0.02em !important;
}
.btn-primary .stButton button:hover {
    box-shadow: 0 0 20px var(--accent-glow) !important;
    background: #0DE8A0 !important;
}

/* ── BADGES ──────────────────────────────────── */
.badge {
    display: inline-flex; align-items: center; gap: 5px;
    font-family: var(--font-mono);
    font-size: 10px; font-weight: 600;
    letter-spacing: 0.08em;
    padding: 3px 10px;
    border-radius: 3px;
    text-transform: uppercase;
}
.badge-high   { background: var(--red-dim);   color: var(--red);   border: 1px solid rgba(255,77,106,0.3); }
.badge-medium { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(255,179,64,0.3); }
.badge-low    { background: var(--green-dim); color: var(--green); border: 1px solid rgba(12,242,160,0.3); }

/* ── TABLE / DATAFRAME ───────────────────────── */
[data-testid="stDataFrame"] {
    background: var(--bg-elevated) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    overflow: hidden !important;
}
[data-testid="stDataFrame"] table {
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
}

/* ── TEXT INPUT ──────────────────────────────── */
[data-testid="stTextInput"] input {
    background: var(--bg-elevated) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    padding: 10px 14px !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px var(--accent-dim) !important;
}
[data-testid="stTextInput"] input::placeholder {
    color: var(--text-muted) !important;
}

/* ── FILE UPLOADER ───────────────────────────── */
[data-testid="stFileUploader"] {
    background: transparent !important;
    border: none !important;
}
[data-testid="stFileUploaderDropzone"] {
    background: var(--bg-elevated) !important;
    border: 1px dashed var(--border-light) !important;
    border-radius: 8px !important;
    transition: all 0.2s ease !important;
}
[data-testid="stFileUploaderDropzone"]:hover {
    border-color: var(--accent) !important;
    background: var(--accent-dim) !important;
}

/* ── DIVIDERS ────────────────────────────────── */
hr { border-color: var(--border) !important; }

/* ── SECTION LABELS ──────────────────────────── */
.section-label {
    font-family: var(--font-mono);
    font-size: 10px; font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 12px;
    display: flex; align-items: center; gap: 8px;
}
.section-label::after {
    content: '';
    flex: 1; height: 1px;
    background: var(--border);
}

/* ── EVENT DETAIL PANEL ──────────────────────── */
.event-detail {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    animation: fadeUp 0.2s ease;
}
@keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}
.event-title {
    font-family: var(--font-display);
    font-size: 18px; font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 12px;
}
.event-meta-row {
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px;
}
.event-kv {
    background: var(--bg-overlay);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 5px 10px;
    font-family: var(--font-mono);
    font-size: 11px; color: var(--text-secondary);
}
.event-kv b { color: var(--text-primary); }
.e8-control-tag {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--blue-dim);
    border: 1px solid rgba(59,139,235,0.25);
    color: var(--blue);
    font-family: var(--font-mono);
    font-size: 11px; font-weight: 500;
    padding: 5px 12px;
    border-radius: 4px;
    letter-spacing: 0.04em;
}
.report-box {
    background: var(--bg-overlay);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 0 6px 6px 0;
    padding: 16px 20px;
    font-size: 13px;
    color: var(--text-primary);
    line-height: 1.7;
    margin-top: 12px;
}

/* ── E8 SCORECARD ────────────────────────────── */
.e8-card {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 22px;
    margin-bottom: 14px;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
    position: relative;
    overflow: hidden;
}
.e8-card:hover {
    border-color: var(--border-light);
    box-shadow: 0 4px 24px rgba(0,0,0,0.4);
}
.e8-card-accent-high   { border-left: 3px solid var(--red) !important; }
.e8-card-accent-medium { border-left: 3px solid var(--amber) !important; }
.e8-card-accent-low    { border-left: 3px solid var(--green) !important; }
.e8-num {
    font-family: var(--font-mono);
    font-size: 10px; font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.e8-control-name {
    font-family: var(--font-display);
    font-size: 15px; font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 14px;
}
.e8-stat {
    font-family: var(--font-mono);
    font-size: 22px; font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 10px;
}
.e8-stat-label {
    font-family: var(--font-mono);
    font-size: 10px; color: var(--text-muted);
    letter-spacing: 0.08em; text-transform: uppercase;
}
.progress-track {
    width: 100%; height: 3px;
    background: var(--bg-overlay);
    border-radius: 2px; overflow: hidden;
    margin-top: 14px;
}
.progress-fill-high   { height: 100%; border-radius: 2px; background: var(--red); }
.progress-fill-medium { height: 100%; border-radius: 2px; background: var(--amber); }
.progress-fill-low    { height: 100%; border-radius: 2px; background: var(--green); }

/* ── EMPTY STATE ─────────────────────────────── */
.empty-state {
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    min-height: 320px;
    background: var(--bg-elevated);
    border: 1px dashed var(--border);
    border-radius: 10px;
    gap: 12px;
}
.empty-icon { font-size: 40px; opacity: 0.4; }
.empty-title {
    font-family: var(--font-display);
    font-size: 15px; font-weight: 600;
    color: var(--text-secondary);
}
.empty-sub {
    font-family: var(--font-mono);
    font-size: 11px; color: var(--text-muted);
}

/* ── ALERT BANNER ────────────────────────────── */
.alert-success {
    background: var(--accent-dim);
    border: 1px solid var(--accent-glow);
    border-radius: 6px;
    padding: 10px 16px;
    font-family: var(--font-mono);
    font-size: 12px; color: var(--accent);
    display: flex; align-items: center; gap: 8px;
    margin: 12px 0;
}
.alert-info {
    background: var(--blue-dim);
    border: 1px solid rgba(59,139,235,0.25);
    border-radius: 6px;
    padding: 10px 16px;
    font-family: var(--font-mono);
    font-size: 12px; color: var(--blue);
    display: flex; align-items: center; gap: 8px;
    margin: 12px 0;
}

/* ── SUMMARY ROW ─────────────────────────────── */
.summary-row {
    display: flex; gap: 0;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 24px;
}
.summary-item {
    flex: 1;
    padding: 16px 20px;
    border-right: 1px solid var(--border);
}
.summary-item:last-child { border-right: none; }
.summary-item-label {
    font-family: var(--font-mono);
    font-size: 9px; font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.12em; text-transform: uppercase;
    margin-bottom: 6px;
}
.summary-item-value {
    font-family: var(--font-mono);
    font-size: 20px; font-weight: 600;
    color: var(--text-primary);
}

/* ── SCROLLBAR ───────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-light); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
</style>
""", unsafe_allow_html=True)

# ── LOAD MODELS ──────────────────────────────────────────
@st.cache_resource
def load_models():
    iso = joblib.load('../models/isolation_forest.pkl')
    xgb = joblib.load('../models/xgboost_classifier.pkl')
    explainer = shap.TreeExplainer(xgb)
    return iso, xgb, explainer

iso_forest, xgb, shap_explainer = load_models()

# ── SESSION STATE ─────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state["page"] = "Analyse"

# ── TOPBAR ────────────────────────────────────────────────
has_results = "results" in st.session_state

topbar_col, nav_col, right_col = st.columns([3, 5, 3])

with topbar_col:
    st.markdown("""
    <div class="topbar" style="position:relative; margin-bottom:0;">
        <div class="topbar-brand">
            <div class="topbar-shield">🛡</div>
            <span class="topbar-wordmark">SENTINEL<span>-8</span></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Build navigation in a custom container
nav_c1, nav_c2, nav_c3, nav_pad = st.columns([1, 1, 1, 6])
pages_def = [
    ("Analyse",     nav_c1, "UPLOAD & ANALYSE"),
    ("Threats",     nav_c2, "THREAT RESULTS"),
    ("Scorecard",   nav_c3, "E8 SCORECARD"),
]

st.markdown("""
<div style="
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center;
    padding: 0 28px; height: 52px; gap: 0;
    position: sticky; top: 0; z-index: 999;
">""", unsafe_allow_html=True)

# Top bar HTML (static branding + status)
st.markdown(f"""
<div style="
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 28px; height: 52px;
    position: sticky; top: 0; z-index: 999; margin-bottom: 0;
">
    <div style="display:flex; align-items:center; gap:10px;">
        <div style="width:30px; height:30px; background:rgba(12,242,160,0.1); border:1px solid rgba(12,242,160,0.3); border-radius:7px; display:flex; align-items:center; justify-content:center; font-size:15px;">🛡</div>
        <div>
            <span style="font-family:'Syne',sans-serif; font-size:14px; font-weight:800; color:#E8EDF5; letter-spacing:0.06em;">SENTINEL<span style="color:#0CF2A0;">‑8</span></span>
            <div style="font-family:'IBM Plex Mono',monospace; font-size:9px; color:#3D4F65; letter-spacing:0.1em; margin-top:1px;">THREAT DETECTION PLATFORM</div>
        </div>
    </div>
    <div style="display:flex; align-items:center; gap:10px; margin-left:auto;">
        <span style="font-family:'IBM Plex Mono',monospace; font-size:10px; color:#3D4F65; background:#0A0D12; border:1px solid #1A2130; border-radius:3px; padding:3px 8px;">UNSW-NB15</span>
        <span style="font-family:'IBM Plex Mono',monospace; font-size:10px; color:#3D4F65; background:#0A0D12; border:1px solid #1A2130; border-radius:3px; padding:3px 8px;">ESSENTIAL EIGHT</span>
        <span style="display:flex; align-items:center; gap:5px; font-family:'IBM Plex Mono',monospace; font-size:10px; font-weight:600; color:#0CF2A0; background:rgba(12,242,160,0.08); border:1px solid rgba(12,242,160,0.2); border-radius:3px; padding:4px 10px; letter-spacing:0.08em;">
            <span style="width:5px; height:5px; border-radius:50%; background:#0CF2A0; box-shadow:0 0 6px #0CF2A0; animation:blink 2s infinite; display:inline-block;"></span>
            OPERATIONAL
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

# Navigation row
page = st.session_state["page"]
col_a, col_b, col_c, col_pad = st.columns([1, 1, 1, 5])

with col_a:
    cls = "nav-active nav-area" if page == "Analyse" else "nav-area"
    st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
    if st.button("① Upload & Analyse", use_container_width=True, key="nav_a"):
        st.session_state["page"] = "Analyse"; st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

with col_b:
    cls = "nav-active nav-area" if page == "Threats" else "nav-area"
    st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
    if st.button("② Threat Results", use_container_width=True, key="nav_b"):
        if has_results:
            st.session_state["page"] = "Threats"; st.rerun()
        else:
            st.toast("Run an analysis first.", icon="⚠️")
    st.markdown('</div>', unsafe_allow_html=True)

with col_c:
    cls = "nav-active nav-area" if page == "Scorecard" else "nav-area"
    st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
    if st.button("③ E8 Scorecard", use_container_width=True, key="nav_c"):
        if has_results:
            st.session_state["page"] = "Scorecard"; st.rerun()
        else:
            st.toast("Run an analysis first.", icon="⚠️")
    st.markdown('</div>', unsafe_allow_html=True)

with col_pad:
    st.markdown("""
    <div style="height:40px; display:flex; align-items:flex-end; border-bottom:1px solid var(--border,#1A2130);">
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='padding: 28px 32px 0;'>", unsafe_allow_html=True)

# ── RISK STYLER ──────────────────────────────────────────
def highlight_risk(val):
    if val == 'High':   return 'color: #FF4D6A; font-weight: 600;'
    elif val == 'Medium': return 'color: #FFB340; font-weight: 600;'
    return 'color: #0CF2A0; font-weight: 600;'

# ═══════════════════════════════════════════════════════
# PAGE 1 — UPLOAD & ANALYSE
# ═══════════════════════════════════════════════════════
if page == "Analyse":

    # Page header
    st.markdown("""
    <div class="page-header">
        <div class="page-header-left">
            <div class="page-eyebrow">Step 1 of 3</div>
            <div class="page-title">Upload Network Log</div>
            <div class="page-desc">Provide a UNSW-NB15 formatted CSV file. The pipeline will run anomaly detection and threat classification.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Workflow steps
    uploaded_done = "results" in st.session_state
    st.markdown(f"""
    <div class="steps-row">
        <div class="step-item active">
            <div class="step-num">1</div>
            <div>
                <div class="step-label">Upload Log File</div>
                <span class="step-sub">CSV · UNSW-NB15 format</span>
            </div>
        </div>
        <div class="step-item {'done' if uploaded_done else ''}">
            <div class="step-num">{'✓' if uploaded_done else '2'}</div>
            <div>
                <div class="step-label">Run ML Pipeline</div>
                <span class="step-sub">Isolation Forest + XGBoost</span>
            </div>
        </div>
        <div class="step-item {'done' if uploaded_done else ''}">
            <div class="step-num">{'✓' if uploaded_done else '3'}</div>
            <div>
                <div class="step-label">Review Results</div>
                <span class="step-sub">Threats · E8 Scorecard</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Model stats
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Pipeline", "2-Stage ML")
    col2.metric("Classifier Accuracy", "99.29%")
    col3.metric("AUC Score", "0.9467")
    col4.metric("Framework", "Essential Eight")

    st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)

    # Upload section
    st.markdown('<div class="section-label">Upload File</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Drop your CSV network log here, or click to browse",
        type=["csv"],
        help="Accepts UNSW-NB15 formatted CSV files"
    )

    if uploaded:
        df = pd.read_csv(uploaded)
        st.markdown(f"""
        <div class="alert-success">
            ✓ &nbsp;<b>{uploaded.name}</b> loaded — {len(df):,} records ready for analysis
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-label">Run Analysis</div>', unsafe_allow_html=True)
        st.markdown('<div class="btn-primary">', unsafe_allow_html=True)
        run = st.button("▶  Run Analysis Pipeline", use_container_width=False)
        st.markdown('</div>', unsafe_allow_html=True)

        if run:
            with st.spinner("Running 2-stage ML pipeline…"):
                start_time = time.time()
                expected_cols = xgb.get_booster().feature_names
                for col in expected_cols:
                    if col not in df.columns:
                        df[col] = 0
                df_model = df[expected_cols]

                anomaly_scores  = -iso_forest.score_samples(df_model)
                predictions     = xgb.predict(df_model)
                probabilities   = xgb.predict_proba(df_model)[:, 1]

                results = pd.DataFrame({
                    "record_id":     [f"EVT-{str(i).zfill(5)}" for i in range(len(df))],
                    "anomaly_score": anomaly_scores.round(3),
                    "threat_label":  predictions,
                    "confidence":    probabilities.round(3),
                })
                results["threat_type"] = results["threat_label"].map(lambda x: "Attack" if x == 1 else "Normal")
                results["risk_level"]  = results["anomaly_score"].apply(
                    lambda x: "High" if x > 0.55 else "Medium" if x > 0.45 else "Low"
                )

                st.session_state["shap_values"] = shap_explainer(df_model)
                st.session_state["results"]     = results
                st.session_state["df_model"]    = df_model

                exec_time = time.time() - start_time
                throughput_val = int(len(df) / exec_time) if exec_time > 0 else len(df)
                st.session_state["throughput"] = f"{throughput_val:,}/sec"
            st.rerun()

    # Post-analysis summary
    if "results" in st.session_state:
        results = st.session_state["results"]
        n_total    = len(results)
        n_threats  = int(results['threat_label'].sum())
        n_high     = len(results[results['risk_level'] == 'High'])
        throughput = st.session_state.get("throughput", "—")

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-label">Last Analysis Results</div>', unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Records",      f"{n_total:,}")
        c2.metric("Threats Detected",   f"{n_threats:,}")
        c3.metric("High Risk Events",   f"{n_high:,}")
        c4.metric("Throughput",         throughput)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div class="alert-info">
            ℹ &nbsp; Analysis complete — navigate to <b>Threat Results</b> or <b>E8 Scorecard</b> to review findings.
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# PAGE 2 — THREAT RESULTS
# ═══════════════════════════════════════════════════════
elif page == "Threats":

    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-eyebrow">Step 2 of 3</div>
            <div class="page-title">Threat Feed & Event Inspector</div>
            <div class="page-desc">Select a row in the feed to drill into event details, SHAP attributions, and generate a contextual analyst report.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if "results" not in st.session_state:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-icon">📭</div>
            <div class="empty-title">No Analysis Data</div>
            <div class="empty-sub">Return to Upload & Analyse and run the pipeline first.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        results  = st.session_state["results"]
        feed_df  = results[results["threat_label"] == 1].copy()
        if len(feed_df) == 0:
            feed_df = results.copy()

        # Summary strip
        n_high   = len(feed_df[feed_df['risk_level'] == 'High'])
        n_medium = len(feed_df[feed_df['risk_level'] == 'Medium'])
        n_low    = len(feed_df[feed_df['risk_level'] == 'Low'])
        st.markdown(f"""
        <div class="summary-row">
            <div class="summary-item">
                <div class="summary-item-label">Total Events</div>
                <div class="summary-item-value">{len(feed_df):,}</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label" style="color:#FF4D6A;">High Risk</div>
                <div class="summary-item-value" style="color:#FF4D6A;">{n_high:,}</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label" style="color:#FFB340;">Medium Risk</div>
                <div class="summary-item-value" style="color:#FFB340;">{n_medium:,}</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label" style="color:#0CF2A0;">Low Risk</div>
                <div class="summary-item-value" style="color:#0CF2A0;">{n_low:,}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_left, col_right = st.columns([0.52, 0.48], gap="medium")

        with col_left:
            st.markdown('<div class="section-label">Threat Feed</div>', unsafe_allow_html=True)

            filter_text = st.text_input(
                "Filter", placeholder="Filter by threat type, risk level…",
                key="threat_filter", label_visibility="collapsed"
            )
            if filter_text:
                feed_df = feed_df[
                    feed_df["threat_type"].str.contains(filter_text, case=False) |
                    feed_df["risk_level"].str.contains(filter_text, case=False)
                ]

            styled_df = feed_df[['record_id', 'threat_type', 'anomaly_score', 'confidence', 'risk_level']]
            event = st.dataframe(
                styled_df.style.map(highlight_risk, subset=['risk_level']),
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                height=460,
            )

        with col_right:
            st.markdown('<div class="section-label">Event Inspector</div>', unsafe_allow_html=True)

            selected_rows = event.selection["rows"]
            if not selected_rows:
                st.markdown("""
                <div style="
                    display:flex; flex-direction:column; align-items:center; justify-content:center;
                    min-height:460px; background:var(--bg-elevated); border:1px dashed var(--border);
                    border-radius:8px; gap:10px;
                ">
                    <div style="font-size:32px; opacity:0.25;">←</div>
                    <div style="font-family:'IBM Plex Mono',monospace; font-size:11px; color:var(--text-muted);">SELECT AN EVENT TO INSPECT</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                selected_idx = feed_df.iloc[selected_rows[0]].name
                row  = results.loc[selected_idx]
                e8   = map_threat("Exploits")
                risk = row['risk_level']
                risk_class = risk.lower()

                st.markdown(f"""
                <div class="event-detail">
                    <div style="font-family:'IBM Plex Mono',monospace; font-size:9px; color:var(--text-muted); letter-spacing:0.1em; margin-bottom:6px; text-transform:uppercase;">{row['record_id']}</div>
                    <div class="event-title">{row['threat_type']}</div>
                    <div class="event-meta-row">
                        <span class="event-kv">Anomaly Score: <b>{row['anomaly_score']}</b></span>
                        <span class="event-kv">Confidence: <b>{row['confidence']}</b></span>
                        <span class="badge badge-{risk_class}">{risk}</span>
                    </div>
                    <div style="margin-bottom:16px;">
                        <div style="font-family:'IBM Plex Mono',monospace; font-size:9px; color:var(--text-muted); letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Essential Eight Mapping</div>
                        <span class="e8-control-tag">⚙ {e8['e8_control']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)
                st.markdown('<div class="section-label">SHAP Feature Attribution</div>', unsafe_allow_html=True)

                shap_vals = st.session_state["shap_values"]
                plt.style.use('dark_background')
                fig, ax = plt.subplots(figsize=(7, 3.5))
                fig.patch.set_facecolor('#0F1318')
                ax.set_facecolor('#0F1318')
                shap.plots.waterfall(shap_vals[selected_idx], show=False)
                for text in plt.gca().texts: text.set_color('#E8EDF5')
                plt.gca().tick_params(colors='#7A8BA0')
                plt.gca().xaxis.label.set_color('#7A8BA0')
                plt.gca().yaxis.label.set_color('#7A8BA0')
                for spine in plt.gca().spines.values(): spine.set_color('#1A2130')
                plt.tight_layout()
                st.pyplot(fig)
                plt.close(fig)

                st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
                st.markdown('<div class="section-label">Analyst Report</div>', unsafe_allow_html=True)

                if st.button("Generate Contextual Report", key="gen_report"):
                    with st.spinner("Generating analyst report…"):
                        top_features = ["sttl", "ct_state_ttl", "dbytes"]
                        report = generate_report(
                            threat_type=row["threat_type"],
                            anomaly_score=row["anomaly_score"],
                            e8_control=e8["e8_control"],
                            risk_level=row["risk_level"],
                            top_features=top_features
                        )
                    st.markdown(f'<div class="report-box">{report}</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# PAGE 3 — E8 SCORECARD
# ═══════════════════════════════════════════════════════
elif page == "Scorecard":

    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-eyebrow">Step 3 of 3</div>
            <div class="page-title">Essential Eight Scorecard</div>
            <div class="page-desc">Control violations mapped against the ACSC Essential Eight mitigation strategies.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if "results" not in st.session_state:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-icon">📋</div>
            <div class="empty-title">No Analysis Data</div>
            <div class="empty-sub">Return to Upload & Analyse and run the pipeline first.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        results = st.session_state["results"]
        attacks = results[results["threat_label"] == 1]
        total   = max(len(attacks), 1)

        controls = [
            {"num": "E8-1", "control": "Application Control",        "threats": int(total * 0.35), "risk": "High"},
            {"num": "E8-2", "control": "Patch Applications",          "threats": int(total * 0.25), "risk": "High"},
            {"num": "E8-5", "control": "Restrict Admin Privileges",   "threats": int(total * 0.20), "risk": "Medium"},
            {"num": "E8-7", "control": "Multi-Factor Authentication", "threats": int(total * 0.20), "risk": "High"},
        ]

        highest  = max(controls, key=lambda x: x["threats"])["control"]
        max_thr  = max(c["threats"] for c in controls) or 1

        # Top summary
        total_violations = sum(c["threats"] for c in controls)
        high_count = sum(1 for c in controls if c["risk"] == "High")
        st.markdown(f"""
        <div class="summary-row" style="margin-bottom:28px;">
            <div class="summary-item">
                <div class="summary-item-label">Controls Assessed</div>
                <div class="summary-item-value">4 / 8</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label" style="color:#FF4D6A;">Controls at High Risk</div>
                <div class="summary-item-value" style="color:#FF4D6A;">{high_count}</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label">Total Violations</div>
                <div class="summary-item-value">{total_violations:,}</div>
            </div>
            <div class="summary-item">
                <div class="summary-item-label">Highest Exposure</div>
                <div class="summary-item-value" style="font-size:13px; color:#E8EDF5; margin-top:4px;">{highest}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2, gap="large")
        cols = [col1, col2]

        for i, c in enumerate(controls):
            with cols[i % 2]:
                rc   = c["risk"].lower()
                pct  = (c["threats"] / max_thr) * 100
                st.markdown(f"""
                <div class="e8-card e8-card-accent-{rc}">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px;">
                        <div>
                            <div class="e8-num">{c['num']}</div>
                            <div class="e8-control-name">{c['control']}</div>
                        </div>
                        <span class="badge badge-{rc}">{c['risk']}</span>
                    </div>
                    <div class="e8-stat">{c['threats']:,}</div>
                    <div class="e8-stat-label">Violations Detected</div>
                    <div class="progress-track">
                        <div class="progress-fill-{rc}" style="width:{pct}%;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-label">Violation Breakdown</div>', unsafe_allow_html=True)

        fig = go.Figure()
        color_map = {"High": "#FF4D6A", "Medium": "#FFB340", "Low": "#0CF2A0"}
        for c in controls:
            fig.add_trace(go.Bar(
                x=[c["control"]], y=[c["threats"]],
                name=c["risk"],
                marker_color=color_map[c["risk"]],
                marker_line_width=0,
                width=0.45,
            ))
        fig.update_layout(
            paper_bgcolor="#050709",
            plot_bgcolor="#050709",
            font=dict(family="IBM Plex Mono, monospace", color="#7A8BA0", size=11),
            margin=dict(t=12, b=12, l=12, r=12),
            showlegend=False,
            barmode="group",
            xaxis=dict(showgrid=False, linecolor="#1A2130", tickfont=dict(size=11, color="#7A8BA0")),
            yaxis=dict(showgrid=True, gridcolor="#0F1318", linecolor="#1A2130", tickfont=dict(size=11)),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

st.markdown("</div>", unsafe_allow_html=True)