# ui/pages/deploy_preview.py
"""Deploy Preview — review ADD-decision rules and launch deploy via CLI."""
from __future__ import annotations

import subprocess
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
st.title("🚀 Deploy Preview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning("Need at least 2 catalogs to preview deployments.")
    st.stop()

with st.sidebar:
    _SIEM_CATALOGS = {"elastic", "sentinel", "splunk", "qradar", "chronicle"}
    non_siem = [c for c in catalogs if c not in _SIEM_CATALOGS]
    src_idx = catalogs.index(non_siem[0]) if non_siem else 0
    catalog_a = st.selectbox("Source ruleset", catalogs, index=src_idx,
                              help="External ruleset (e.g. Sigma)")
    remaining = [c for c in catalogs if c != catalog_a]
    catalog_b = st.selectbox("Target SIEM catalog", remaining if remaining else catalogs,
                              help="Your SIEM (e.g. Elastic)")

decisions = result_store.load_decisions(catalog_a, catalog_b)
unique_dicts = result_store.load_unique(catalog_a, catalog_b)

st.caption(
    f"Rules from **{catalog_a}** not covered by **{catalog_b}** — "
    "candidates to add to the SIEM."
)

if not unique_dicts:
    st.info(
        "No comparison results yet.  \n"
        f"Run `dksec compare --a {catalog_a} --b {catalog_b}` first."
    )
    st.stop()

# Split rules by decision status
add_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "ADD"]
skip_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "SKIP"]
review_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "REVIEW"]
undecided = [r for r in unique_dicts if r.get("id") not in decisions]

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total unique", len(unique_dicts))
c2.metric("ADD (deploy)", len(add_rules))
c3.metric("SKIP", len(skip_rules))
c4.metric("Undecided", len(undecided))

if not add_rules:
    st.warning(
        f"No rules are marked ADD yet. Use the **Comparison** page to triage rules, "
        "or run `dksec decide` to auto-generate decisions."
    )
else:
    st.divider()
    st.markdown(f"### Rules queued for deploy ({len(add_rules)})")
    st.caption("These are the **only** rules that will be sent to the SIEM.")

    for r in add_rules:
        with st.expander(f"[{r.get('severity','?').upper()}] {r.get('name','?')}"):
            st.markdown(f"**ID:** `{r.get('id','?')}`")
            st.markdown(f"**Description:** {r.get('description') or '_No description_'}")
            tq = r.get("translated_query") or r.get("raw_query") or "_No query_"
            st.code(tq, language="sql")
            mitre = ", ".join((r.get("mitre_techniques") or [])[:5])
            if mitre:
                st.caption(f"MITRE: {mitre}")

st.divider()
st.markdown("### Deploy to SIEM")

if not add_rules:
    st.info("Triage rules on the Comparison page first, then return here to deploy.")
    st.stop()

col1, col2 = st.columns(2)
dry_run = col1.checkbox("Dry run (preview only)", value=True)
target = col2.text_input("Target SIEM name", value=catalog_b)

st.warning(
    f"This will deploy **{len(add_rules)} rules** from `{catalog_a}` to `{target}`.  \n"
    f"{'(DRY RUN — no changes will be made)' if dry_run else '**LIVE DEPLOY — rules will be created in the SIEM.**'}"
)

if st.button("🚀 Deploy ADD rules", type="primary"):
    cmd = [
        sys.executable,
        str(_ROOT / "cli.py"),
        "deploy",
        "--mode", "permanent",
        "--catalog", catalog_a,
        "--target", target,
        "--compare-catalog", catalog_b,
    ]
    if dry_run:
        cmd.append("--dry-run")

    with st.spinner("Running deploy…"):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(_ROOT),
        )

    if proc.returncode == 0:
        st.success(proc.stdout or "Deploy completed.")
    else:
        st.error(proc.stderr or proc.stdout or "Deploy failed.")
