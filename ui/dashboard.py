# ui/dashboard.py
"""
DKSec UI — catalog-agnostic Streamlit dashboard.

Run with:
    python -m streamlit run ui/dashboard.py
    # or from project root:
    streamlit run ui/dashboard.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow imports from project root when launched directly via streamlit
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

st.set_page_config(
    page_title="DKSec",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

# --- Sidebar ---
with st.sidebar:
    st.markdown(
        '<div style="font-size:1.25rem;font-weight:700;color:#e6edf3;padding:4px 0 12px">🛡️ DKSec</div>',
        unsafe_allow_html=True,
    )

    store = RuleStore(_CATALOGS_DIR)
    result_store = ResultStore(_OUTPUT_DIR)

    catalogs = store.list_catalogs()
    if catalogs:
        st.caption(f"📂 Catalogs: **{', '.join(catalogs)}**")
    else:
        st.caption("📁 No catalogs loaded  \n`dksec ingest` to start")

    runs = result_store.list_alert_runs()
    if runs:
        st.caption(f"⚔️ Attack runs: **{len(runs)}**")

    st.divider()

# --- Page navigation ---
pg = st.navigation(
    {
        "Analysis": [
            st.Page("ui/pages/comparison.py", title="Comparison",  icon="📊", default=True),
            st.Page("ui/pages/home.py",        title="Overview",    icon="🏠"),
            st.Page("ui/pages/scoring.py",     title="Scoring",     icon="🏆"),
        ],
        "Catalogs": [
            st.Page("ui/pages/catalogs.py",    title="Browse Rules", icon="📋"),
        ],
        "Operations": [
            st.Page("ui/pages/attack_chain.py",   title="Attack Chain",   icon="⚔️"),
            st.Page("ui/pages/deploy_preview.py", title="Deploy Preview", icon="🚀"),
        ],
    }
)
pg.run()
