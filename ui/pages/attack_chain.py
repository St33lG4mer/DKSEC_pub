# ui/pages/attack_chain.py
"""Attack Chain page — view attack run history and alert data."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore

_ROOT = Path(__file__).parent.parent.parent
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("⚔️ Attack Chain")

result_store = ResultStore(_OUTPUT_DIR)
runs = result_store.list_alert_runs()

if not runs:
    st.info(
        "No attack runs yet.  \n"
        "Run `dksec attack --framework sliver` or `dksec run-all` "
        "to execute MITRE ATT&CK scenarios."
    )
    st.stop()

st.caption(f"**{len(runs)} run(s)** found in output/alerts/")

selected_run = st.selectbox("Select run", runs, index=len(runs) - 1)
alerts = result_store.load_alerts(selected_run)

c1, c2 = st.columns(2)
c1.metric("Total alerts", len(alerts))
unique_rules = len({a.get("rule_id") for a in alerts if a.get("rule_id")})
c2.metric("Unique rules fired", unique_rules)

if not alerts:
    st.info("No alerts in this run.")
    st.stop()

st.divider()
st.markdown("### Alert Breakdown")

rows = [
    {"Rule ID": a.get("rule_id", "?"), "Scenario": a.get("scenario_id", "?")}
    for a in alerts
]
df = pd.DataFrame(rows)
rule_counts = (
    df.groupby("Rule ID")
    .size()
    .reset_index(name="Alert Count")
    .sort_values("Alert Count", ascending=False)
)
st.dataframe(rule_counts, use_container_width=True, hide_index=True)

with st.expander("By scenario"):
    scenario_counts = (
        df.groupby("Scenario")
        .size()
        .reset_index(name="Alerts")
        .sort_values("Alerts", ascending=False)
    )
    st.dataframe(scenario_counts, use_container_width=True, hide_index=True)
