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
    load_complete_elastic_rules,
    load_complete_sigma_rules,
    load_config,
)

st.set_page_config(
    page_title="DKSEC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

# Global sidebar
with st.sidebar:
    st.markdown(
        '<div style="font-size:1.25rem;font-weight:700;color:#e6edf3;padding:4px 0 12px">DKSEC</div>',
        unsafe_allow_html=True,
    )

    # Always-visible rule counts (offline)
    sigma_rules   = load_complete_sigma_rules()
    elastic_rules = load_complete_elastic_rules()
    n_elastic = len([r for r in elastic_rules if "SIGMA" not in (r.get("tags") or [])])
    st.caption(f"🔵 {len(sigma_rules)} Sigma · 🟡 {n_elastic} Elastic rules")

    st.divider()

    # Kibana integration — only shown when URL is configured
    cfg        = load_config()
    kibana_url = cfg["kibana"]["url"].rstrip("/")
    es_user    = cfg["elasticsearch"]["user"]
    es_pass    = cfg["elasticsearch"]["password"]

    if kibana_url:
        if RULES_CACHE_FILE.exists():
            age_min = int((time.time() - RULES_CACHE_FILE.stat().st_mtime) / 60)
            st.caption(f"Kibana cache: {age_min} min old")
        else:
            st.caption("Kibana cache: not loaded")

        if ALERTS_CACHE_FILE.exists():
            alert_age = int((time.time() - ALERTS_CACHE_FILE.stat().st_mtime) / 60)
            st.caption(f"Alert cache: {alert_age} min old")

        if st.button("Refresh Kibana rules"):
            from utils import load_kibana_rules, refresh_kibana_rules
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
    else:
        st.caption("📁 Offline mode — local files")
        st.caption("Add `config.yaml` to enable live Kibana sync.")

    st.divider()

# Navigation — Coverage Analysis is the primary decision tool
pg = st.navigation(
    {
        "Analysis": [
            st.Page("pages/comparison.py", title="Coverage Analysis", icon="📊", default=True),
            st.Page("pages/home.py",        title="Overview",          icon="🏠"),
            st.Page("pages/scoring.py",     title="Rule Scoring",      icon="🏆"),
        ],
        "Rules": [
            st.Page("pages/sigma_rules.py",  title="Sigma Rules",   icon="📋"),
            st.Page("pages/kibana_rules.py", title="Elastic Rules",  icon="🔍"),
        ],
        "Testing": [
            st.Page("pages/sliver_harness.py", title="Sliver Harness", icon="🎯"),
        ],
    }
)
pg.run()
