#!/usr/bin/env python3
"""
DKSEC Rule Dashboard - entry point.

Run with:  python -m streamlit run dashboard.py
"""

import time

import streamlit as st

from utils import (
    ALERTS_CACHE_FILE,
    RULES_CACHE_FILE,
    apply_theme,
    load_config,
    load_kibana_rules,
    refresh_kibana_rules,
)

st.set_page_config(
    page_title="DKSEC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

cfg        = load_config()
kibana_url = cfg["kibana"]["url"].rstrip("/")
es_user    = cfg["elasticsearch"]["user"]
es_pass    = cfg["elasticsearch"]["password"]

# Global sidebar
with st.sidebar:
    st.markdown(
        '<div style="font-size:1.25rem;font-weight:700;color:#e6edf3;padding:4px 0 18px">DKSEC</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    if RULES_CACHE_FILE.exists():
        age_min = int((time.time() - RULES_CACHE_FILE.stat().st_mtime) / 60)
        st.caption(f"Kibana cache: {age_min} min old")
    else:
        st.caption("Kibana cache: not loaded")

    if st.button("Refresh Kibana rules"):
        if RULES_CACHE_FILE.exists():
            RULES_CACHE_FILE.unlink()
        load_kibana_rules.clear()
        with st.spinner("Fetching rules from Kibana..."):
            try:
                rules = refresh_kibana_rules(kibana_url, es_user, es_pass)
                st.success(f"Fetched {len(rules)} rules")
            except RuntimeError as exc:
                st.error(str(exc))
        st.rerun()

    if ALERTS_CACHE_FILE.exists():
        alert_age = int((time.time() - ALERTS_CACHE_FILE.stat().st_mtime) / 60)
        st.caption(f"Alert cache: {alert_age} min old")

    st.divider()

# Navigation
pg = st.navigation(
    {
        "Overview": [
            st.Page("pages/home.py", title="Dashboard", icon="🏠", default=True),
        ],
        "Detection": [
            st.Page("pages/comparison.py", title="Coverage Analysis", icon="⚖️"),
            st.Page("pages/scoring.py",    title="Rule Scoring",      icon="🏆"),
        ],
        "Rules": [
            st.Page("pages/sigma_rules.py", title="Sigma Rules",  icon="📋"),
            st.Page("pages/kibana_rules.py", title="Kibana Rules", icon="🔍"),
        ],
        "Testing": [
            st.Page("pages/sliver_harness.py", title="Sliver Harness", icon="🎯"),
        ],
    }
)
pg.run()
