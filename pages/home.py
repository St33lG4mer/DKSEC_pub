"""Overview — offline-ready summary of the full rule inventory."""

import pandas as pd
import streamlit as st

from utils import (
    SEV_COLORS,
    compute_coverage_report,
    load_complete_elastic_rules,
    load_complete_sigma_rules,
    load_failures,
    metric_card_html,
)

SEV_ORDER = ["critical", "high", "medium", "low"]

st.title("Overview")
st.caption("📁 Offline mode — all metrics are derived from local rule files.")

sigma_rules   = load_complete_sigma_rules()
elastic_rules = load_complete_elastic_rules()
failures      = load_failures()

elastic_native = [r for r in elastic_rules if "SIGMA" not in (r.get("tags") or [])]

with st.spinner("Computing coverage…"):
    report = compute_coverage_report(sigma_rules, elastic_rules)

sigma_unique = report["sigma_unique"]
overlaps     = report["overlaps"]

# ── Metric cards ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Rule Inventory</div>', unsafe_allow_html=True)

overlap_pct = round(len(overlaps) / len(sigma_rules) * 100) if sigma_rules else 0
add_color   = "#f85149" if len(sigma_unique) > 20 else ("#d29922" if len(sigma_unique) > 5 else "#3fb950")

st.markdown(
    '<div class="metric-row">'
    + metric_card_html("Sigma Rules",        f"{len(sigma_rules):,}",   "deploy-ready Sigma rules", "#58a6ff")
    + metric_card_html("Elastic Rules",      f"{len(elastic_native):,}", "native Elastic rules",     "#d29922")
    + metric_card_html("Overlap Pairs",      str(len(overlaps)),         f"{overlap_pct}% of Sigma rules matched", "#3fb950")
    + metric_card_html("Sigma to Add",       str(len(sigma_unique)),     "rules not in Elastic SIEM",  add_color)
    + '</div>',
    unsafe_allow_html=True,
)

if sigma_unique:
    n_crit = sum(1 for r in sigma_unique if r["severity"] == "critical")
    n_high = sum(1 for r in sigma_unique if r["severity"] == "high")
    st.info(
        f"📋 **{len(sigma_unique)} Sigma rule(s) should be added to Elastic SIEM** — "
        f"{n_crit} critical, {n_high} high severity.  \n"
        "→ Go to **Coverage Analysis** for the full list and MITRE breakdown."
    )

st.divider()

# ── Severity distribution ────────────────────────────────────────────────────
st.markdown('<div class="section-header">Severity Distribution</div>', unsafe_allow_html=True)

col_sig, col_ela = st.columns(2)

def _sev_df(rules: list[dict]) -> pd.DataFrame:
    rows = [(s, sum(1 for r in rules if r.get("severity") == s)) for s in SEV_ORDER]
    return pd.DataFrame(rows, columns=["Severity", "Count"]).set_index("Severity")

with col_sig:
    st.caption("🔵 Sigma rules by severity")
    st.bar_chart(_sev_df(sigma_rules), color="#58a6ff")

with col_ela:
    st.caption("🟡 Elastic rules by severity")
    st.bar_chart(_sev_df(elastic_native), color="#d29922")

st.divider()

# ── Top Sigma rules to add ───────────────────────────────────────────────────
st.markdown('<div class="section-header">Top 10 Sigma Rules to Add (by Risk Score)</div>', unsafe_allow_html=True)

if sigma_unique:
    top10 = sigma_unique[:10]
    rows = []
    for r in top10:
        sev = r["severity"]
        color = SEV_COLORS.get(sev, "#8b949e")
        rows.append({
            "Rule Name":        r["title"],
            "Severity":         r["severity"].capitalize(),
            "Risk Score":       r["risk_score"],
            "MITRE Techniques": ", ".join(r.get("techniques", [])) or "—",
            "Event Categories": ", ".join(r.get("event_categories", [])) or "—",
        })
    st.dataframe(pd.DataFrame(rows), width='stretch', height=360, hide_index=True)
else:
    st.success("✅ All Sigma rules are covered by Elastic rules at the default threshold.")

st.divider()

# ── Rule health ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Rule Health</div>', unsafe_allow_html=True)

n_failures   = len(failures) if isinstance(failures, dict) else 0
n_valid      = len(sigma_rules) - n_failures

h1, h2, h3, h4 = st.columns(4)
h1.metric("Total Sigma rules",    len(sigma_rules))
h2.metric("EQL valid",            n_valid, delta=f"{round(n_valid / len(sigma_rules) * 100)}%" if sigma_rules else "—")
h3.metric("EQL failures",         n_failures)
h4.metric("Total Elastic rules",  len(elastic_native))

