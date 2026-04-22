"""Kibana Rules — browse and filter all detection rules in Kibana."""

import pandas as pd
import streamlit as st

from utils import RULES_CACHE_FILE, load_config, load_kibana_rules

cfg        = load_config()
es_user    = cfg["elasticsearch"]["user"]
es_pass    = cfg["elasticsearch"]["password"]
kibana_url = cfg["kibana"]["url"].rstrip("/")

kibana_rules = load_kibana_rules(kibana_url, es_user, es_pass)
live_kibana  = RULES_CACHE_FILE.exists()

st.title("Kibana Detection Rules" if live_kibana else "Elastic Detection Rules (Local)")
if not live_kibana:
    st.caption(
        "No live Kibana connection — showing local AST files from `rule_ast/elastic/`. "
        "Connect to Kibana and refresh to see actual deployed rules."
    )

if not kibana_rules:
    st.warning("No detection rules found.")
    st.stop()

c1, c2 = st.columns(2)
c1.metric("Total rules", len(kibana_rules))
c2.metric("Enabled", sum(1 for r in kibana_rules if r.get("enabled")))

# ── Table ──────────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Rules</div>', unsafe_allow_html=True)

pool = kibana_rules

rows = [
    {
        "Name":       r.get("name", ""),
        "Type":       r.get("type", ""),
        "Severity":   r.get("severity", ""),
        "Risk Score": r.get("risk_score", 0),
        "Enabled":    "✅" if r.get("enabled") else "❌",
        "Tags":       ", ".join(r.get("tags") or [])[:80] or "—",
        "Rule ID":    r.get("rule_id", r.get("id", "")),
    }
    for r in pool
]

df = pd.DataFrame(rows)

col_a, col_b = st.columns(2)
sev_opts   = sorted(df["Severity"].dropna().unique().tolist())
sev_filter = col_a.multiselect("Severity", sev_opts)
type_opts   = sorted(df["Type"].dropna().unique().tolist())
type_filter = col_b.multiselect("Type", type_opts)

if sev_filter:
    df = df[df["Severity"].isin(sev_filter)]
if type_filter:
    df = df[df["Type"].isin(type_filter)]

st.dataframe(df, width="stretch", height=500)

# ── Charts ─────────────────────────────────────────────────────────────────
if not df.empty:
    st.markdown(
        '<div class="section-header">Distribution</div>', unsafe_allow_html=True
    )
    col_left, col_right = st.columns(2)
    with col_left:
        st.caption("Severity")
        sev_dist = (
            df["Severity"]
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Count")
            .set_index("Severity")
        )
        st.bar_chart(sev_dist, color="#58a6ff")
    with col_right:
        st.caption("Rule type")
        type_dist = (
            df["Type"]
            .value_counts()
            .rename_axis("Type")
            .reset_index(name="Count")
            .set_index("Type")
        )
        st.bar_chart(type_dist, color="#d29922")
