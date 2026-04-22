"""
Rule Comparison — Sigma vs Elastic by query logic.

Pairs rules by Jaccard similarity on ECS fields and event categories.
Sigma-only coverage areas are shown separately and excluded from pairing.
Alert fire counts are shown alongside each overlapping pair.
"""

import pandas as pd
import streamlit as st

from utils import (
    ALERTS_CACHE_FILE,
    enrich_overlaps_with_alerts,
    fetch_alerts_24h,
    find_query_overlaps,
    load_complete_elastic_rules,
    load_complete_sigma_rules,
    load_config,
)

cfg     = load_config()
es_host = cfg["elasticsearch"]["host"].rstrip("/")
es_user = cfg["elasticsearch"]["user"]
es_pass = cfg["elasticsearch"]["password"]

st.title("Rule Comparison")
st.caption(
    "Rules are compared by **query logic** — shared ECS fields, event categories, "
    "and MITRE techniques.  \n"
    "Areas covered exclusively by one side appear in the coverage map and are **not** "
    "counted as overlap."
)

sigma_rules   = load_complete_sigma_rules()
elastic_rules = load_complete_elastic_rules()

# ── Sidebar controls ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("**Comparison settings**")
    query_threshold = st.slider(
        "Query similarity threshold",
        min_value=0.05,
        max_value=0.80,
        value=0.15,
        step=0.05,
        help="Minimum Jaccard similarity on query tokens to count as overlap",
    )
    if st.button("🔃 Refresh alert data", help="Clear alert cache"):
        if ALERTS_CACHE_FILE.exists():
            ALERTS_CACHE_FILE.unlink()
        st.rerun()

# ── Compute overlaps ────────────────────────────────────────────────────────
with st.spinner("Analysing rule logic…"):
    overlaps, coverage = find_query_overlaps(sigma_rules, elastic_rules, query_threshold)

# Enrich with live alert counts (graceful if ES unavailable)
alerts = fetch_alerts_24h(es_host, es_user, es_pass)
if not alerts["error"]:
    overlaps = enrich_overlaps_with_alerts(overlaps, alerts)

# ── Coverage map ─────────────────────────────────────────────────────────────
st.markdown(
    '<div class="section-header">Detection Coverage Map</div>',
    unsafe_allow_html=True,
)
st.caption(
    "Only **shared** event categories are compared below. "
    "Sigma-only areas represent unique value; Elastic-only areas are potential gaps."
)

col_sigma, col_both, col_elastic = st.columns(3)


def _pills(cats: list[str], css_class: str) -> str:
    if not cats:
        return '<span style="color:#8b949e;font-size:0.82rem">none detected</span>'
    return " ".join(
        f'<span class="coverage-pill {css_class}">{c}</span>' for c in cats
    )


with col_sigma:
    st.markdown("**🔵 Sigma-only coverage**")
    st.caption("Unique to Sigma — excluded from comparison")
    st.markdown(_pills(coverage["sigma_only"], "pill-sigma"), unsafe_allow_html=True)

with col_both:
    st.markdown("**🟢 Shared coverage**")
    st.caption("Compared below")
    st.markdown(_pills(coverage["shared"], "pill-both"), unsafe_allow_html=True)

with col_elastic:
    st.markdown("**🟡 Elastic-only coverage**")
    st.caption("Potential Sigma coverage gaps")
    st.markdown(_pills(coverage["elastic_only"], "pill-elastic"), unsafe_allow_html=True)

st.write("")

# ── Summary metrics ──────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
m1.metric("Overlapping rule pairs", len(overlaps))
m2.metric("Sigma-only categories", len(coverage["sigma_only"]))
m3.metric("Shared categories", len(coverage["shared"]))
m4.metric("Elastic-only (gaps)", len(coverage["elastic_only"]))

if not overlaps:
    st.info(
        "No overlapping rules found at this threshold. "
        "Try lowering the similarity slider in the sidebar."
    )
    st.stop()

# ── Overlap table ─────────────────────────────────────────────────────────────
st.markdown(
    '<div class="section-header">Overlapping Rules</div>', unsafe_allow_html=True
)

df = pd.DataFrame(overlaps)

col_a, col_b, col_c = st.columns(3)
min_sim   = col_a.slider("Min similarity to show", 0.0, 1.0, 0.0, 0.05)
cat_opts  = sorted({o["shared_cats"] for o in overlaps if o["shared_cats"] != "—"})
cat_filt  = col_b.selectbox("Filter by event category", ["All"] + cat_opts)
best_filt = col_c.selectbox("Filter by suggested best", ["All", "SIGMA", "Elastic"])

view = df[df["jaccard"] >= min_sim]
if cat_filt != "All":
    view = view[view["shared_cats"] == cat_filt]
if best_filt != "All":
    view = view[view["suggested_best"] == best_filt]

st.dataframe(
    view[
        [
            "sigma_name", "elastic_name", "jaccard", "shared_fields",
            "shared_cats", "shared_mitre", "sigma_severity", "elastic_sev",
            "sigma_fires", "elastic_fires", "suggested_best",
        ]
    ].rename(
        columns={
            "sigma_name":    "Sigma Rule",
            "elastic_name":  "Elastic Rule",
            "jaccard":       "Similarity",
            "shared_fields": "Shared Fields",
            "shared_cats":   "Event Categories",
            "shared_mitre":  "Shared MITRE",
            "sigma_severity":"Sigma Sev.",
            "elastic_sev":   "Elastic Sev.",
            "sigma_fires":   "Sigma Fires (24h)",
            "elastic_fires": "Elastic Fires (24h)",
            "suggested_best":"Best Rule",
        }
    ),
    use_container_width=True,
    height=500,
)

# ── Analysis charts ───────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Analysis</div>', unsafe_allow_html=True)
col_left, col_right = st.columns(2)

with col_left:
    st.caption("Suggested best rule in overlapping pairs")
    winner = (
        df["suggested_best"]
        .value_counts()
        .rename_axis("Winner")
        .reset_index(name="Count")
        .set_index("Winner")
    )
    st.bar_chart(winner, color="#3fb950")

with col_right:
    st.caption("Overlaps by shared event category")
    cat_counts = (
        df["shared_cats"]
        .value_counts()
        .head(10)
        .rename_axis("Category")
        .reset_index(name="Count")
        .set_index("Category")
    )
    st.bar_chart(cat_counts, color="#58a6ff")

# ── Alert activity in overlapping pairs ──────────────────────────────────────
if not alerts["error"] and any(
    o["sigma_fires"] + o["elastic_fires"] > 0 for o in overlaps
):
    st.markdown(
        '<div class="section-header">Alert Activity in Overlapping Rules</div>',
        unsafe_allow_html=True,
    )
    active = [o for o in overlaps if o["sigma_fires"] + o["elastic_fires"] > 0]
    df_active = pd.DataFrame(active)[
        ["sigma_name", "elastic_name", "sigma_fires", "elastic_fires", "jaccard"]
    ].rename(
        columns={
            "sigma_name":    "Sigma Rule",
            "elastic_name":  "Elastic Rule",
            "sigma_fires":   "Sigma Fires",
            "elastic_fires": "Elastic Fires",
            "jaccard":       "Similarity",
        }
    )
    st.dataframe(
        df_active.sort_values("Sigma Fires", ascending=False),
        use_container_width=True,
        height=300,
    )
