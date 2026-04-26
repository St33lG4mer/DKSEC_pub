# ui/pages/comparison.py
"""Comparison page — catalog picker + overlap/unique analysis."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from pipeline.compare import compare_rules
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("📊 Comparison")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning(
        "Need at least 2 catalogs loaded.  \n"
        "Run `dksec ingest` for each catalog first."
    )
    st.stop()

with st.sidebar:
    st.markdown("**Comparison settings**")
    catalog_a = st.selectbox("Catalog A (source)", catalogs, index=0, key="cmp_a")
    remaining = [c for c in catalogs if c != catalog_a]
    catalog_b = st.selectbox("Catalog B (target)", remaining if remaining else catalogs,
                              key="cmp_b")
    threshold = st.slider("Jaccard threshold", 0.05, 0.80, 0.15, 0.05)
    run_id = None
    runs = result_store.list_alert_runs()
    if runs:
        use_alerts = st.checkbox("Include alert data", value=True)
        if use_alerts:
            run_id = st.selectbox("Attack run", runs, index=len(runs) - 1)

if catalog_a == catalog_b:
    st.error("Select two different catalogs.")
    st.stop()

rules_a = store.load_all(catalog_a)
rules_b = store.load_all(catalog_b)

if not rules_a or not rules_b:
    st.warning("One or both catalogs are empty. Run `dksec ingest` and `dksec translate` first.")
    st.stop()

alerts = result_store.load_alerts(run_id) if run_id else None

with st.spinner("Analysing coverage…"):
    result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)

# Persist results
overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
result_store.save_unique(catalog_a, catalog_b, unique_a_dicts)
result_store.save_unique(catalog_b, catalog_a, [r.to_dict() for r in result.unique_b])

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric(f"{catalog_a.title()} rules", len(rules_a))
c2.metric(f"{catalog_b.title()} rules", len(rules_b))
c3.metric("Overlaps", len(result.overlaps))
c4.metric(f"Unique {catalog_a} (ADD)", len(result.unique_a))

st.caption(f"Confidence: **{result.confidence}**")
st.divider()

# Unique rules table
st.markdown(f"### {catalog_a.title()} Rules to Add ({len(result.unique_a)})")
if result.unique_a:
    sev_filter = st.multiselect(
        "Filter by severity", ["critical", "high", "medium", "low"],
        default=["critical", "high"],
    )
    rows = [
        {
            "ID": r.id[:10] + "…",
            "Name": r.name,
            "Severity": r.severity,
            "MITRE": ", ".join(r.mitre_techniques[:3]),
            "Categories": ", ".join(r.event_categories[:2]),
        }
        for r in result.unique_a
    ]
    df = pd.DataFrame(rows)
    if sev_filter:
        df = df[df["Severity"].isin(sev_filter)]
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.success(f"All {catalog_a} rules are already covered by {catalog_b}.")

st.divider()

# Overlaps expander
with st.expander(f"Overlap pairs ({len(result.overlaps)})"):
    if result.overlaps:
        overlap_rows = [
            {
                f"{catalog_a} rule": p.rule_a.name,
                f"{catalog_b} rule": p.rule_b.name,
                "Jaccard": round(p.jaccard_score, 3),
                "Alert confirmed": "✅" if p.alert_confirmed else "—",
            }
            for p in result.overlaps
        ]
        st.dataframe(pd.DataFrame(overlap_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No overlaps found at the current threshold.")
