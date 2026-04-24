"""
Coverage Analysis — the primary decision tool.

Compares Sigma vs Elastic rules by query logic (offline).
Priority output: "Here are the Sigma rules that should be added to Elastic SIEM."
"""

import pandas as pd
import streamlit as st

from utils import (
    compute_coverage_report,
    load_complete_elastic_rules,
    load_complete_sigma_rules,
)

SEV_ORDER  = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "#f85149", "high": "#d29922", "medium": "#58a6ff", "low": "#8b949e"}

st.title("Coverage Analysis")
st.caption(
    "📁 **Offline mode** — analysing local rule inventory.  \n"
    "Rules are compared by shared ECS fields, event categories, and MITRE techniques."
)

sigma_rules   = load_complete_sigma_rules()
elastic_rules = load_complete_elastic_rules()

# ── Sidebar controls ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("**Analysis settings**")
    query_threshold = st.slider(
        "Query similarity threshold",
        min_value=0.05,
        max_value=0.80,
        value=0.15,
        step=0.05,
        help="Minimum Jaccard similarity on query tokens to count as overlap.",
    )
    sev_filter = st.multiselect(
        "Severity filter (Sigma to add)",
        SEV_ORDER,
        default=["critical", "high"],
        help="Show only these severities in the 'Sigma rules to add' table.",
    )

# ── Compute coverage report ──────────────────────────────────────────────────
with st.spinner("Analysing rule coverage…"):
    report = compute_coverage_report(sigma_rules, elastic_rules, query_threshold)

overlaps     = report["overlaps"]
coverage     = report["coverage"]
sigma_unique = report["sigma_unique"]
elastic_uniq = report["elastic_unique"]
shared_tech  = report["shared_techniques"]
sigma_tech   = report["sigma_only_techniques"]
elastic_tech = report["elastic_only_techniques"]

# ── SECTION 1: Summary metrics ───────────────────────────────────────────────
st.markdown('<div class="section-header">Coverage Summary</div>', unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Overlapping rule pairs",    len(overlaps),     help="Rules matched across both rule sets")
m2.metric("Sigma rules to add",        len(sigma_unique), help="Sigma rules with no Elastic equivalent — recommended to deploy")
m3.metric("Elastic-only gaps",         len(elastic_uniq), help="Elastic rules with no Sigma coverage")
m4.metric("Shared MITRE techniques",   len(shared_tech),  help="Techniques covered by both rule sets")

overlap_pct = round(len({o["sigma_id"] for o in overlaps}) / len(sigma_rules) * 100) if sigma_rules else 0
st.progress(min(1.0, overlap_pct / 100), text=f"{overlap_pct}% of Sigma rules have an Elastic equivalent")

st.divider()

# ── SECTION 2: Sigma rules to add (PRIORITY) ────────────────────────────────
st.markdown(
    '<div class="section-header">🔵 Sigma Rules to Add to Elastic SIEM</div>',
    unsafe_allow_html=True,
)
st.caption(
    f"Found **{len(sigma_unique)}** Sigma rule(s) with no equivalent Elastic rule — "
    "these are your highest-value additions."
)

if sigma_unique:
    sev_set = set(sev_filter) if sev_filter else set(SEV_ORDER)
    filtered = [r for r in sigma_unique if r["severity"] in sev_set] if sev_filter else sigma_unique

    if not filtered:
        st.info(f"No rules match the selected severities ({', '.join(sev_filter)}). Adjust the filter in the sidebar.")
    else:
        rows = []
        for r in filtered:
            rows.append({
                "Rule Name":        r["title"],
                "Severity":         r["severity"].capitalize(),
                "Risk Score":       r["risk_score"],
                "MITRE Techniques": ", ".join(r.get("techniques", [])) or "—",
                "Category":         r.get("category", "any"),
                "Rule ID":          r["rule_id"],
            })
        df_add = pd.DataFrame(rows)
        st.dataframe(df_add, width='stretch', height=420, hide_index=True)
        st.caption(f"Showing {len(rows)} of {len(sigma_unique)} total Sigma-unique rules. Use the severity filter to narrow results.")
else:
    st.success("✅ All Sigma rules already have an Elastic equivalent at this threshold.")

st.divider()

# ── SECTION 3: Elastic-only gaps ────────────────────────────────────────────
st.markdown(
    '<div class="section-header">🟡 Elastic-Only Rules (Gaps Without Sigma Coverage)</div>',
    unsafe_allow_html=True,
)
st.caption(
    f"**{len(elastic_uniq)}** Elastic rule(s) have no Sigma equivalent. "
    "These represent detection logic that only lives in Elastic."
)

if elastic_uniq:
    with st.expander(f"View {len(elastic_uniq)} Elastic-only rules", expanded=False):
        rows_e = []
        for r in elastic_uniq:
            rows_e.append({
                "Rule Name":  r.get("name", r.get("title", "—")),
                "Severity":   r.get("severity", "—").capitalize(),
                "Risk Score": r.get("risk_score", 0),
                "Tags":       ", ".join(r.get("tags") or [])[:80] or "—",
                "Rule ID":    r.get("rule_id", r.get("id", "—")),
            })
        st.dataframe(pd.DataFrame(rows_e), width='stretch', height=320, hide_index=True)
else:
    st.success("✅ Every Elastic rule has a Sigma equivalent.")

st.divider()

# ── SECTION 4: Overlapping rule pairs ────────────────────────────────────────
with st.expander(f"🟢 View {len(overlaps)} overlapping rule pair(s)", expanded=False):
    if overlaps:
        df_ol = pd.DataFrame(overlaps)
        st.dataframe(
            df_ol[[
                "sigma_name", "elastic_name", "jaccard", "shared_fields",
                "shared_cats", "shared_mitre", "sigma_severity", "elastic_sev",
            ]].rename(columns={
                "sigma_name":    "Sigma Rule",
                "elastic_name":  "Elastic Rule",
                "jaccard":       "Similarity",
                "shared_fields": "Shared Fields",
                "shared_cats":   "Event Categories",
                "shared_mitre":  "Shared MITRE",
                "sigma_severity":"Sigma Sev.",
                "elastic_sev":   "Elastic Sev.",
            }),
            width='stretch',
            height=420,
            hide_index=True,
        )
    else:
        st.info("No overlapping pairs found at the current threshold.")

st.divider()

# ── SECTION 5: MITRE technique breakdown ─────────────────────────────────────
st.markdown('<div class="section-header">MITRE ATT&CK Coverage Breakdown</div>', unsafe_allow_html=True)


def _tech_pills(techs: list[str], css_class: str) -> str:
    if not techs:
        return '<span style="color:#8b949e;font-size:0.82rem">none</span>'
    return " ".join(
        f'<span class="coverage-pill {css_class}">{t.upper()}</span>' for t in techs[:30]
    )


col_s, col_b, col_e = st.columns(3)
with col_s:
    st.markdown(f"**🔵 Sigma-only techniques** ({len(sigma_tech)})")
    st.caption("Covered only by Sigma — unique detection value")
    st.markdown(_tech_pills(sigma_tech, "pill-sigma"), unsafe_allow_html=True)
with col_b:
    st.markdown(f"**🟢 Shared techniques** ({len(shared_tech)})")
    st.caption("Covered by both rule sets")
    st.markdown(_tech_pills(list(shared_tech), "pill-both"), unsafe_allow_html=True)
with col_e:
    st.markdown(f"**🟡 Elastic-only techniques** ({len(elastic_tech)})")
    st.caption("Covered only by Elastic — consider adding Sigma coverage")
    st.markdown(_tech_pills(elastic_tech, "pill-elastic"), unsafe_allow_html=True)

st.divider()

# ── SECTION 6: Event category coverage map ───────────────────────────────────
st.markdown('<div class="section-header">Event Category Coverage Map</div>', unsafe_allow_html=True)
col_a, col_b2, col_c = st.columns(3)

with col_a:
    st.markdown("**🔵 Sigma-only**")
    st.markdown(_tech_pills(coverage.get("sigma_only", []), "pill-sigma"), unsafe_allow_html=True)
with col_b2:
    st.markdown("**🟢 Shared**")
    st.markdown(_tech_pills(coverage.get("shared", []), "pill-both"), unsafe_allow_html=True)
with col_c:
    st.markdown("**🟡 Elastic-only**")
    st.markdown(_tech_pills(coverage.get("elastic_only", []), "pill-elastic"), unsafe_allow_html=True)

