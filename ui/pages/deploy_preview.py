# ui/pages/deploy_preview.py
"""Deploy Preview — review unique rules and launch deploy via CLI."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_ROOT = Path(__file__).parent.parent.parent
_CATALOGS_DIR = _ROOT / "catalogs"
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("🚀 Deploy Preview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning("Need at least 2 catalogs to preview deployments.")
    st.stop()

with st.sidebar:
    catalog_a = st.selectbox("Source catalog", catalogs, index=0)
    remaining = [c for c in catalogs if c != catalog_a]
    catalog_b = st.selectbox("Target SIEM catalog", remaining if remaining else catalogs)

decisions = result_store.load_decisions(catalog_a, catalog_b)
unique_dicts = result_store.load_unique(catalog_a, catalog_b)

st.caption(
    f"Rules from **{catalog_a}** not covered by **{catalog_b}** — "
    "candidates to add to the SIEM."
)

if not unique_dicts:
    st.info(
        "No comparison results yet.  \n"
        "Run `dksec compare --a sigma --b elastic` first to identify unique rules."
    )
    st.stop()

add_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "ADD"]
st.metric(f"Rules to add ({catalog_a} → {catalog_b})", len(unique_dicts))
if decisions:
    st.caption(f"Decisions available: {len(add_rules)} marked ADD")

# Table
rows = [
    {
        "ID": r.get("id", "?")[:10] + "…",
        "Name": r.get("name", "?"),
        "Severity": r.get("severity", "?"),
        "MITRE": ", ".join((r.get("mitre_techniques") or [])[:3]),
    }
    for r in unique_dicts
]
st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.divider()
st.markdown("### Deploy to SIEM")
col1, col2 = st.columns(2)
dry_run = col1.checkbox("Dry run (preview only)", value=True)
target = col2.text_input("Target", value=catalog_b)

if st.button("🚀 Deploy unique rules", type="primary"):
    cmd = [
        sys.executable, "cli.py", "deploy",
        "--mode", "permanent",
        "--catalog", catalog_a,
        "--target", target,
    ]
    if dry_run:
        cmd.append("--dry-run")

    with st.spinner("Running deploy…"):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent.parent),
        )

    if proc.returncode == 0:
        st.success(proc.stdout or "Deploy completed.")
    else:
        st.error(proc.stderr or proc.stdout or "Deploy failed.")
