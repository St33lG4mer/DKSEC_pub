"""Rule Scoring — ranks Sigma rules by a composite quality score."""

import pandas as pd
import streamlit as st

from utils import (
    classify_rule,
    fetch_alerts_24h,
    get_critical_gaps,
    load_config,
    load_failures,
    load_rule_decisions,
    load_sigma_rules,
    metric_card_html,
    score_rules,
)

cfg        = load_config()
es_host    = cfg["elasticsearch"]["host"].rstrip("/")
es_user    = cfg["elasticsearch"]["user"]
es_pass    = cfg["elasticsearch"]["password"]

sigma_rules = load_sigma_rules()
failures    = load_failures()
decisions   = load_rule_decisions()

# Build overlap/add sets from pre-computed decisions (name-based)
_skip_names = {r["name"].lower() for r in decisions.get("skip", [])}
_add_names  = {r["name"].lower() for r in decisions.get("add",  [])}


def _decision_match(rule: dict) -> str:
    """Return 'skip', 'add', or '' based on decision list name matching."""
    title = rule.get("title", "").lower()
    stem  = rule.get("rule_id", "").lower().replace("_", " ")
    for candidate in (title, stem):
        if candidate in _skip_names:
            return "skip"
        if candidate in _add_names:
            return "add"
    return ""


# Build sigma_in_kibana from ADD decision list (rules that should be pushed)
sigma_in_kibana: set[str] = set()
for r in sigma_rules:
    if _decision_match(r) == "add":
        sigma_in_kibana.add(r["rule_id"])

# Build overlapping set from SKIP decision list
overlapping_sigma_ids: set[str] = set()
for r in sigma_rules:
    if _decision_match(r) == "skip":
        overlapping_sigma_ids.add(r["rule_id"])

st.title("Rule Scoring")
st.caption(
    "**Score** = risk score "
    "+ 10 if EQL valid "
    "+ 5 × MITRE techniques "
    "+ 10 if marked ADD in decisions "
    "+ up to 20 for 24 h alert activity "
    "− 15 if marked SKIP (Elastic already covers). "
    "Normalized to 0–100 via min-max scaling."
)

# ── Get alert counts ────────────────────────────────────────────────────────
alerts      = fetch_alerts_24h(es_host, es_user, es_pass)
alert_counts = {r["rule"]: r["count"] for r in alerts.get("sigma", {}).get("top_rules", [])}

# ── Score ───────────────────────────────────────────────────────────────────
df = score_rules(sigma_rules, failures, sigma_in_kibana, overlapping_sigma_ids, alert_counts)

if df.empty:
    st.info("No rules to score.")
    st.stop()

# ── Decision column ──────────────────────────────────────────────────────────
decision_map = {}
for r in sigma_rules:
    d = _decision_match(r)
    label = {"add": "➕ Add", "skip": "⏭️ Skip"}.get(d, "—")
    decision_map[r["title"]] = label

df["Decision"] = df["Name"].map(decision_map).fillna("—")

# ── Classification badges ────────────────────────────────────────────────────
st.markdown('<div class="section-header">Rule Classifications</div>', unsafe_allow_html=True)

cb1, cb2, cb3, cb4 = st.columns(4)
if es_host and not alerts.get("error"):
    n_dead     = int((df["Classification"] == "dead").sum())
    n_noisy    = int((df["Classification"] == "noisy").sum())
    n_valuable = int((df["Classification"] == "valuable").sum())
    n_active   = int((df["Classification"] == "active").sum())
    cb1.markdown(metric_card_html("Dead Rules",    str(n_dead),     "No alerts fired in 24 h",          "#8b949e"), unsafe_allow_html=True)
    cb2.markdown(metric_card_html("Noisy Rules",   str(n_noisy),    "≥50 fires, low/medium severity",    "#d29922"), unsafe_allow_html=True)
    cb3.markdown(metric_card_html("Valuable Rules", str(n_valuable), "Fires on high/critical severity",  "#3fb950"), unsafe_allow_html=True)
    cb4.markdown(metric_card_html("Active Rules",  str(n_active),   "Firing, not noisy or valuable",     "#58a6ff"), unsafe_allow_html=True)
else:
    n_crit = int((df["Severity"] == "critical").sum())
    n_high = int((df["Severity"] == "high").sum())
    n_med  = int((df["Severity"] == "medium").sum())
    n_low  = int((df["Severity"] == "low").sum())
    cb1.markdown(metric_card_html("Critical", str(n_crit), "rules", "#f85149"), unsafe_allow_html=True)
    cb2.markdown(metric_card_html("High",     str(n_high), "rules", "#d29922"), unsafe_allow_html=True)
    cb3.markdown(metric_card_html("Medium",   str(n_med),  "rules", "#58a6ff"), unsafe_allow_html=True)
    cb4.markdown(metric_card_html("Low",      str(n_low),  "rules", "#3fb950"), unsafe_allow_html=True)

st.write("")

# ── Filters ─────────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Ranked Rules</div>', unsafe_allow_html=True)

col_a, col_b, col_c, col_d = st.columns(4)
top_n        = col_a.slider("Show top N", 10, min(500, len(df)), min(50, len(df)), 10)
unique_only  = col_b.checkbox("Unique rules only (no overlap)")
sev_filter   = col_c.multiselect("Severity", ["critical", "high", "medium", "low"])
dec_filter   = col_d.selectbox("Decision", ["All", "➕ Add", "⏭️ Skip", "—"])

view = df[df["Unique (no overlap)"] == "✅"] if unique_only else df
if sev_filter:
    view = view[view["Severity"].isin(sev_filter)]
if dec_filter != "All":
    view = view[view["Decision"] == dec_filter]

cols = ["Name", "Score", "Risk Score", "Severity", "EQL Valid",
        "Decision", "MITRE Techniques", "24h Alerts"]
st.dataframe(view[cols].head(top_n), use_container_width=True, height=500)

# ── Charts ────────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Distribution</div>', unsafe_allow_html=True)
col_left, col_right = st.columns(2)

with col_left:
    st.caption("Score distribution")
    st.bar_chart(df["Score"].value_counts().sort_index().rename("Rules"), color="#3fb950")

with col_right:
    st.caption("Top 20 rules by score")
    st.bar_chart(df.head(20).set_index("Name")["Score"], color="#58a6ff")
