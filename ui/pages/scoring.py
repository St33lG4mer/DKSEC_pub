# ui/pages/scoring.py
"""Scoring page — rule scoring and prioritization."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.scoring import classify_rule, normalize_scores, score_rule
from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("🏆 Scoring")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if not catalogs:
    st.info("No catalogs loaded yet.")
    st.stop()

with st.sidebar:
    catalog = st.selectbox("Catalog to score", catalogs)
    sev_filter = st.multiselect(
        "Severity filter",
        ["critical", "high", "medium", "low"],
        default=["critical", "high"],
    )

rules = store.load_all(catalog)
if not rules:
    st.info(f"No rules found in catalog '{catalog}'.")
    st.stop()

# Collect overlap IDs from all comparison pairs involving this catalog
overlap_ids: set[str] = set()
for other in catalogs:
    if other == catalog:
        continue
    for pair in result_store.load_overlaps(catalog, other):
        overlap_ids.add(pair.get("rule_a_id", ""))

# Score rules
raw_scores = [score_rule(r, r.id in overlap_ids, 0) for r in rules]
norm_scores = normalize_scores(raw_scores)

rows = [
    {
        "Name": r.name,
        "Severity": r.severity,
        "Score": round(ns, 1),
        "Class": classify_rule(0, r.severity),
        "MITRE": ", ".join(r.mitre_techniques[:2]),
        "Overlap": "⚠️ overlap" if r.id in overlap_ids else "✅ unique",
    }
    for r, ns in zip(rules, norm_scores)
]
df = pd.DataFrame(rows)
if sev_filter:
    df = df[df["Severity"].isin(sev_filter)]
df = df.sort_values("Score", ascending=False)

st.caption(f"Scoring **{len(df)}** rules from **{catalog}**")
st.dataframe(df, use_container_width=True, hide_index=True)
