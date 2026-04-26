# ui/pages/catalogs.py
"""Browse Rules page — explore rules from any loaded catalog."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.rule_store import RuleStore

_ROOT = Path(__file__).parent.parent.parent
_CATALOGS_DIR = _ROOT / "catalogs"

apply_theme()
st.title("📋 Browse Rules")

store = RuleStore(_CATALOGS_DIR)
catalogs = store.list_catalogs()

if not catalogs:
    st.info("No catalogs loaded yet. Run `dksec ingest` to load rules.")
    st.stop()

with st.sidebar:
    catalog = st.selectbox("Catalog", catalogs)
    sev_filter = st.multiselect(
        "Severity", ["critical", "high", "medium", "low"], default=[]
    )
    search = st.text_input("Search rule name", placeholder="e.g. mimikatz")

rules = store.load_all(catalog)
if sev_filter:
    rules = [r for r in rules if r.severity in sev_filter]
if search:
    rules = [r for r in rules if search.lower() in r.name.lower()]

st.caption(f"Showing **{len(rules)}** rules from **{catalog}**")

if not rules:
    st.info("No rules match the current filters.")
    st.stop()

rows = [
    {
        "ID": r.id[:10] + "…",
        "Name": r.name,
        "Severity": r.severity,
        "Language": r.language,
        "MITRE": ", ".join(r.mitre_techniques[:3]),
        "Translated": "✅" if r.translated_query else "—",
    }
    for r in rules
]
st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

# Rule detail viewer
st.divider()
st.markdown("### Rule Detail")
selected_name = st.selectbox("Select rule to inspect", [r.name for r in rules])
if selected_name:
    selected = next((r for r in rules if r.name == selected_name), None)
    if selected:
        with st.expander("Rule details", expanded=True):
            st.json(selected.to_dict())
