# ui/pages/home.py
"""Overview page — headline metrics for all loaded catalogs."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_ROOT = Path(__file__).parent.parent.parent
_CATALOGS_DIR = _ROOT / "catalogs"
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("🏠 Overview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)


@st.cache_data(show_spinner=False)
def _count_catalog_rules(catalogs_dir: str, catalog: str) -> int:
    ast_dir = Path(catalogs_dir) / catalog / "ast"
    if not ast_dir.exists():
        return 0
    return sum(1 for _ in ast_dir.glob("*.json"))

catalogs = store.list_catalogs()
if not catalogs:
    st.info(
        "No catalogs loaded yet.  \n"
        "Run `dksec ingest --catalog sigma --source folder --path ./rules` to get started."
    )
    st.stop()

st.caption(f"Loaded catalogs: **{', '.join(catalogs)}**")

# Per-catalog metrics
cols = st.columns(max(len(catalogs), 1))
for i, cat in enumerate(catalogs):
    rule_count = _count_catalog_rules(str(_CATALOGS_DIR), cat)
    with cols[i]:
        st.metric(f"📂 {cat.title()}", f"{rule_count:,}", "rules loaded")

st.divider()

# Comparison summary (if at least 2 catalogs)
if len(catalogs) >= 2:
    st.markdown("### Comparison Results")
    _SIEM_CATALOGS = {"elastic", "sentinel", "splunk", "qradar", "chronicle"}
    # Source = non-SIEM; target = SIEM
    non_siem = [c for c in catalogs if c not in _SIEM_CATALOGS]
    siem = [c for c in catalogs if c in _SIEM_CATALOGS]
    catalog_a = non_siem[0] if non_siem else catalogs[0]
    catalog_b = siem[0] if siem else catalogs[1]
    decisions = result_store.load_decisions(catalog_a, catalog_b)

    if decisions:
        add_count = sum(1 for v in decisions.values() if v == "ADD")
        overlaps = result_store.load_overlaps(catalog_a, catalog_b)
        st.success(
            f"🎯 **{add_count} rules from '{catalog_a}' should be added** to '{catalog_b}'"
        )
        col1, col2 = st.columns(2)
        col1.metric("Overlaps", len(overlaps))
        col2.metric("Unique (to add)", add_count)
    else:
        st.info(
            "No comparison results yet.  \n"
            "Run `dksec compare --a sigma --b elastic` or `dksec run-all` to generate them."
        )

st.divider()

# Attack runs
runs = result_store.list_alert_runs()
if runs:
    st.markdown(f"### Attack Runs ({len(runs)})")
    st.caption(f"Latest run ID: `{runs[-1]}`")
else:
    st.caption("No attack runs yet. Run `dksec attack --framework sliver`.")
